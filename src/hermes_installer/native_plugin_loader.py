"""Load selected native adapters only from the root-mounted HI08 closure.

The only filesystem location this module accepts is the deterministic target
derived from the peer-bound no-argument package binder.  The mount itself must
already exist in the service namespace; this module cannot create or select a
mount.  Package and resolver metadata remain presentation only, and every
effect is re-authorized by the root broker.
"""
from __future__ import annotations

import hashlib
import contextlib
import functools
import importlib.util
import inspect
import json
import math
import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
import re
import site
import socket
import stat
import struct
import sys
import threading
from dataclasses import dataclass
from types import MappingProxyType, ModuleType
from typing import Any

from .native_plugin_bindings import (
    NativePluginBindingUnavailable,
    RootSelectedPluginEffects,
    SelectedPluginEffect,
    bind_selected_plugin_effects,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z", re.ASCII)
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z", re.ASCII)
_MCP_SERVER = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z", re.ASCII)
_MAX_ENTRYPOINT_BYTES = 32 * 1024 * 1024
_MAX_CLOSURE_FILES = 200_000
_MAX_CLOSURE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_PLUGIN_RESULT_BYTES = 2 * 1024 * 1024
_MAX_PLUGIN_RESULT_NODES = 50_000
_MAX_PLUGIN_RESULT_DEPTH = 64
_MAX_BACKEND_RESULT_NODES = 65_536
_MAX_BACKEND_RESULT_DEPTH = 32
_MAX_BACKEND_RESULT_BYTES = 2 * 1024 * 1024
_BOUNDED_BACKEND_RESULT_SCHEMA_ID = "installer-native-bounded-backend-result-v1"
_BOUNDED_BACKEND_RESULT_SCHEMA_SHA256 = "8ef1ffe2ca1c26f2bb82fd9178b4cd223bbee4b3b7c1a8d784f850e289026cb4"
_BOUNDED_BACKEND_RESULT_SCHEMA_SIZE = 235
_BOUNDED_BACKEND_REGISTRATIONS = frozenset({
    ("financial-execution-gateway:tool:financial_execute_one_order",
     "financial_execute_one_order"),
    ("agent-live-wallet:tool:agent_live_wallet_action", "agent_live_wallet_action"),
    ("agent-sandbox-wallet:tool:agent_sandbox_wallet_action", "agent_sandbox_wallet_action"),
})
_UNSAFE_PLUGIN_RESULT = (
    '{"error":"Native plugin result could not be represented safely.",'
    '"error_type":"native_plugin_result_contract"}'
)
_LISTEN_FD_BASE = 3
_LOADER_PROGRESS_FD_NAME = "hermes-loader-progress"
_LOADER_PROGRESS_MAX_BYTES = 65_536
_LOADER_PROGRESS_PHASES = (
    "entrypoint-imported", "actions-registered", "ready",
)
_LOADER_NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_MAX_LOADER_PROCESS_ROLES = 256
_MAX_LOADER_REGISTRATIONS = 256
_NATIVE_MCP_ADAPTER_ID = "hermes-installer.native-mcp-dispatch.v1"
_NATIVE_CANDIDATE_INDEX_PATH = "catalog/native-candidates.json"
_MAX_NATIVE_CANDIDATE_INDEX_BYTES = 2 * 1024 * 1024
_MAX_NATIVE_CANDIDATES = 1024
_NATIVE_MCP_HANDLER_LOCK = threading.RLock()
_NATIVE_MCP_SELECTED_HANDLERS: dict[tuple[str, str], Any] = {}
_NATIVE_MCP_PRE_DISCOVERY = threading.local()


class NativePluginLoadUnavailable(PermissionError):
    """Selected package mount, manifest, or adapter source is unavailable."""


@dataclass(frozen=True, slots=True)
class _LoadedProcessRoleOrigin:
    """Observed origin of one imported, root-selected process-role module."""

    role_id: str
    module_name: str
    closure_member_path: str
    module_file_sha256: str
    module_file_device: int
    module_file_inode: int
    module_file_size_bytes: int

    def to_wire(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "module_name": self.module_name,
            "closure_member_path": self.closure_member_path,
            "module_file_sha256": self.module_file_sha256,
            "module_file_device": self.module_file_device,
            "module_file_inode": self.module_file_inode,
            "module_file_size_bytes": self.module_file_size_bytes,
        }


def _process_role_field(role: object, name: str) -> Any:
    if isinstance(role, Mapping):
        return role.get(name)
    return getattr(role, name, None)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class SelectedNativeCandidate:
    """One root-compiled Hermes tool candidate, presentation only."""

    native_tool_name: str
    adapter_id: str
    action_id: str
    argument_schema: MappingProxyType
    result_schema: MappingProxyType
    native_schema_sha256: str
    observer_enrollment_ids: tuple[str, ...]
    native_server_name: str
    description: str
    registration_id: str = ""
    toolset: str = ""
    family: str = ""
    handler_kind: str = ""
    result_schema_id: str | None = None
    selector_fields: tuple[str, ...] = ()
    action_bindings: tuple[MappingProxyType, ...] = ()

    @property
    def is_native_mcp(self) -> bool:
        return self.adapter_id == _NATIVE_MCP_ADAPTER_ID


class _NativeLoaderProgressWriter:
    """Root-challenged sender for systemd's named native-loader activation FD."""

    __slots__ = ("_channel", "_selection", "_nonce", "_sequence", "_registrations",
                 "_roles", "_closed")

    def __init__(self, channel: socket.socket, selection: object, nonce: str) -> None:
        self._channel = channel
        self._selection = selection
        self._nonce = nonce
        self._sequence = 0
        self._registrations: tuple[str, ...] = ()
        self._roles: tuple[dict[str, Any], ...] = ()
        self._closed = False

    @classmethod
    def from_systemd_activation(cls, selection: object) -> "_NativeLoaderProgressWriter":
        """Take only systemd's root-configured named FD; never accept a path or nonce input."""
        names = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
        values = {name: os.environ.pop(name, None) for name in names}
        if all(value is None for value in values.values()):
            raise NativePluginLoadUnavailable("root native loader activation channel is unavailable")
        count = values["LISTEN_FDS"]
        closeable_count = 0
        if (isinstance(count, str) and len(count) <= 3
                and re.fullmatch(r"[0-9]{1,3}", count, re.ASCII)):
            closeable_count = min(int(count), 64)
        if (not isinstance(values["LISTEN_PID"], str)
                or not 1 <= len(values["LISTEN_PID"]) <= 20
                or not values["LISTEN_PID"].isascii()
                or not values["LISTEN_PID"].isdecimal()
                or int(values["LISTEN_PID"]) != os.getpid()
                or closeable_count < 1 or closeable_count > 64
                or closeable_count != int(count)):
            cls._close_activation_range(closeable_count)
            raise NativePluginLoadUnavailable("root native loader activation descriptor is malformed")
        raw_names = values["LISTEN_FDNAMES"]
        fd_names = raw_names.split(":") if isinstance(raw_names, str) else []
        if (len(fd_names) != closeable_count or any(not name for name in fd_names)
                or fd_names.count(_LOADER_PROGRESS_FD_NAME) != 1):
            cls._close_activation_range(closeable_count)
            raise NativePluginLoadUnavailable("named root native loader descriptor is unavailable")
        selected_fd = _LISTEN_FD_BASE + fd_names.index(_LOADER_PROGRESS_FD_NAME)
        for offset in range(closeable_count):
            descriptor = _LISTEN_FD_BASE + offset
            if descriptor != selected_fd:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        try:
            channel = socket.socket(fileno=selected_fd)
            if (channel.family != socket.AF_UNIX
                    or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
                raise OSError("activation descriptor is not an AF_UNIX stream")
            channel.getpeername()  # Require systemd to have connected the named OpenFile endpoint.
            channel.settimeout(10.0)
            nonce = cls._read_challenge(channel)
            if not _LOADER_NONCE.fullmatch(nonce):
                raise OSError("root native loader challenge is malformed")
            return cls(channel, selection, nonce)
        except (OSError, ValueError):
            try:
                channel.close()
            except (OSError, UnboundLocalError):
                try:
                    os.close(selected_fd)
                except OSError:
                    pass
            raise NativePluginLoadUnavailable("root native loader channel challenge failed") from None

    @staticmethod
    def _close_activation_range(count: int) -> None:
        for descriptor in range(_LISTEN_FD_BASE, _LISTEN_FD_BASE + count):
            try:
                os.close(descriptor)
            except OSError:
                pass

    @staticmethod
    def _read_challenge(channel: socket.socket) -> str:
        data = bytearray()
        while len(data) < 43:
            chunk = channel.recv(43 - len(data))
            if not chunk:
                raise OSError("root native loader challenge ended early")
            data.extend(chunk)
        try:
            return data.decode("ascii")
        except UnicodeError:
            raise OSError("root native loader challenge is not ASCII") from None

    def emit(self, *, sequence: int, phase: str,
             registered_registration_ids: tuple[str, ...] | list[str],
             loaded_process_roles: tuple[_LoadedProcessRoleOrigin, ...] | list[_LoadedProcessRoleOrigin]) -> None:
        if self._closed or sequence != self._sequence or sequence >= len(_LOADER_PROGRESS_PHASES):
            raise NativePluginLoadUnavailable("native loader progress sequence is unavailable")
        if phase != _LOADER_PROGRESS_PHASES[sequence]:
            self.close()
            raise NativePluginLoadUnavailable("native loader progress phase is invalid")
        expected_roles = self._expected_roles()
        wire_roles = self._validate_role_origins(loaded_process_roles, expected_roles)
        if sequence == 0:
            if registered_registration_ids != () and registered_registration_ids != []:
                self.close()
                raise NativePluginLoadUnavailable("native loader import event has unexpected registrations")
            registrations: tuple[str, ...] = ()
            self._roles = wire_roles
        else:
            registrations = tuple(registered_registration_ids)
            if (not registrations or len(registrations) > _MAX_LOADER_REGISTRATIONS
                    or tuple(sorted(set(registrations))) != registrations
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in registrations)
                    or registrations != self._expected_registration_ids()
                    or (sequence == 2 and registrations != self._registrations)
                    or wire_roles != self._roles):
                self.close()
                raise NativePluginLoadUnavailable("native loader registrations or role origins changed")
            if sequence == 1:
                self._registrations = registrations

        binding = getattr(self._selection, "_binding", None)
        required = {
            "package_id": getattr(self._selection, "package_id", None),
            "generation": self._profile_generation(),
            "package_generation": getattr(self._selection, "generation", None),
            "entrypoint_sha256": getattr(binding, "entrypoint_sha256", None),
            "resolver_sha256": getattr(binding, "resolver_digest", None),
        }
        if (any(not isinstance(value, str) or not value for value in required.values())
                or any(not _SHA256.fullmatch(required[field]) for field in (
                    "entrypoint_sha256", "resolver_sha256"))):
            self.close()
            raise NativePluginLoadUnavailable("native loader selection is incomplete")
        record = {
            "schema": 2, "launch_nonce": self._nonce,
            "sequence": sequence, "phase": phase, **required,
            "registered_registration_ids": list(registrations),
            "loaded_process_roles": wire_roles,
        }
        try:
            payload = json.dumps(record, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False).encode("utf-8")
            if not payload or len(payload) > _LOADER_PROGRESS_MAX_BYTES:
                raise ValueError("progress frame exceeds its bound")
            self._channel.sendall(struct.pack("!I", len(payload)) + payload)
        except (OSError, TypeError, ValueError, UnicodeError):
            self.close()
            raise NativePluginLoadUnavailable("root native loader progress could not be recorded") from None
        self._sequence += 1
        if sequence == 2:
            self.close()

    def _profile_generation(self) -> str:
        roles = getattr(self._selection, "process_roles", ())
        generations = {_process_role_field(role, "profile_generation") for role in roles}
        if (len(generations) != 1 or not all(isinstance(value, str) and _ID.fullmatch(value)
                                             for value in generations)):
            self.close()
            raise NativePluginLoadUnavailable("native process-role profile generation is ambiguous")
        return next(iter(generations))

    def _expected_roles(self) -> tuple[tuple[str, str, str, str], ...]:
        selected = getattr(self._selection, "process_roles", None)
        if (not isinstance(selected, tuple) or not 1 <= len(selected) <= _MAX_LOADER_PROCESS_ROLES):
            self.close()
            raise NativePluginLoadUnavailable("root selected no exact native process-role modules")
        rows: list[tuple[str, str, str, str]] = []
        for role in selected:
            role_id = _process_role_field(role, "role_id")
            module_name = _process_role_field(role, "module_name")
            member_path = _process_role_field(role, "closure_member_path")
            digest = _process_role_field(role, "role_sha256")
            try:
                normalized_path = _relative_path(member_path)
            except NativePluginLoadUnavailable:
                self.close()
                raise NativePluginLoadUnavailable("root selected an invalid native process-role module") from None
            if (not isinstance(role_id, str) or not _ID.fullmatch(role_id)
                    or not isinstance(module_name, str) or not _MODULE.fullmatch(module_name)
                    or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                    or normalized_path != member_path):
                self.close()
                raise NativePluginLoadUnavailable("root selected an invalid native process-role module")
            rows.append((role_id, module_name, normalized_path, digest))
        if tuple(sorted(rows)) != tuple(rows) or len({row[0] for row in rows}) != len(rows):
            self.close()
            raise NativePluginLoadUnavailable("root selected ambiguous native process-role modules")
        return tuple(rows)

    def _expected_registration_ids(self) -> tuple[str, ...]:
        rows: list[str] = []
        for role in getattr(self._selection, "process_roles", ()):
            values = _process_role_field(role, "registration_ids")
            if (not isinstance(values, (tuple, list)) or len(values) > _MAX_LOADER_REGISTRATIONS
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in values)
                    or tuple(sorted(set(values))) != tuple(values)):
                self.close()
                raise NativePluginLoadUnavailable("root selected invalid process-role registrations")
            rows.extend(values)
        expected = tuple(sorted(set(rows)))
        if (not expected or len(rows) != len(expected)
                or len(expected) > _MAX_LOADER_REGISTRATIONS):
            self.close()
            raise NativePluginLoadUnavailable("root selected ambiguous process-role registrations")
        return expected

    def _validate_role_origins(
        self, origins: tuple[_LoadedProcessRoleOrigin, ...] | list[_LoadedProcessRoleOrigin],
        expected: tuple[tuple[str, str, str, str], ...],
    ) -> tuple[dict[str, Any], ...]:
        if not isinstance(origins, (tuple, list)) or len(origins) != len(expected):
            self.close()
            raise NativePluginLoadUnavailable("loaded process-role module set is incomplete")
        rows: list[dict[str, Any]] = []
        for origin, selected in zip(origins, expected, strict=True):
            if not isinstance(origin, _LoadedProcessRoleOrigin):
                self.close()
                raise NativePluginLoadUnavailable("loaded process-role origin is not loader-observed")
            role_id, module_name, member_path, digest = selected
            if (origin.role_id != role_id or origin.module_name != module_name
                    or origin.closure_member_path != member_path or origin.module_file_sha256 != digest
                    or type(origin.module_file_device) is not int or origin.module_file_device < 0
                    or type(origin.module_file_inode) is not int or origin.module_file_inode <= 0
                    or type(origin.module_file_size_bytes) is not int
                    or origin.module_file_size_bytes <= 0):
                self.close()
                raise NativePluginLoadUnavailable("loaded process-role origin differs from root selection")
            rows.append(origin.to_wire())
        return tuple(rows)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._channel.close()
        except OSError:
            pass


def _validate_plugin_result_tree(value: Any) -> None:
    """Bound and validate JSON results before adapting them to Hermes' tool contract."""
    nodes = 0
    encoded_size = 0
    active: set[int] = set()

    def account(amount: int) -> None:
        nonlocal encoded_size
        encoded_size += amount
        if encoded_size > _MAX_PLUGIN_RESULT_BYTES:
            raise ValueError("result exceeds its serialized size bound")

    def quoted_string_size(text: str) -> int:
        if len(text) > _MAX_PLUGIN_RESULT_BYTES:
            raise ValueError("result string exceeds its bound")
        size = 2  # JSON quotes
        for char in text:
            codepoint = ord(char)
            if char in {'"', "\\"}:
                size += 2
            elif codepoint < 0x20:
                size += 6  # conservative JSON unicode escape bound
            else:
                size += len(char.encode("utf-8"))
            if size > _MAX_PLUGIN_RESULT_BYTES:
                raise ValueError("result string exceeds its serialized size bound")
        return size

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_PLUGIN_RESULT_NODES or depth > _MAX_PLUGIN_RESULT_DEPTH:
            raise ValueError("result structure exceeds its bound")
        if item is None:
            account(4)
            return
        if type(item) is bool:
            account(4 if item else 5)
            return
        if type(item) is str:
            account(quoted_string_size(item))
            return
        if type(item) is int:
            if item.bit_length() > _MAX_PLUGIN_RESULT_BYTES * 4:
                raise ValueError("result integer exceeds its bound")
            account(len(str(item)))
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("result float is not finite")
            account(len(json.dumps(item, allow_nan=False)))
            return
        if type(item) not in {dict, list}:
            raise ValueError("result contains an unsupported value")

        identity = id(item)
        if identity in active:
            raise ValueError("result contains a cycle")
        active.add(identity)
        try:
            if type(item) is dict:
                account(2)  # braces
                for index, (key, child) in enumerate(item.items()):
                    if index:
                        account(1)
                    if type(key) is not str:
                        raise ValueError("result object key is not text")
                    account(quoted_string_size(key) + 1)  # key and colon
                    visit(child, depth + 1)
            else:
                account(2)  # brackets
                for index, child in enumerate(item):
                    if index:
                        account(1)
                    visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(value, 0)


def _plugin_tool_result(value: Any) -> Any:
    """Map reviewed structured adapter output to Hermes' bounded string contract."""
    if isinstance(value, str):
        return value
    if type(value) not in {dict, list, int, float, bool, type(None)}:
        return _UNSAFE_PLUGIN_RESULT
    if type(value) is dict and value.get("_multimodal") is True and isinstance(value.get("content"), list):
        try:
            _validate_plugin_result_tree(value)
            encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(encoded) > _MAX_PLUGIN_RESULT_BYTES:
                return _UNSAFE_PLUGIN_RESULT
        except (TypeError, ValueError, UnicodeError, RecursionError):
            return _UNSAFE_PLUGIN_RESULT
        # Hermes recognizes this exact envelope and passes its typed content
        # through to multimodal handling; do not flatten it to ordinary text.
        return value
    try:
        _validate_plugin_result_tree(value)
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > _MAX_PLUGIN_RESULT_BYTES:
            return _UNSAFE_PLUGIN_RESULT
        return encoded.decode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        # Do not include handler values or serializer exceptions in the tool
        # result; they may contain credentials or private effect output.
        return _UNSAFE_PLUGIN_RESULT


def _validate_backend_result_tree(value: Any) -> None:
    """Validate one raw backend object without trusting its fields.

    This intentionally accepts only already-decoded JSON objects or arrays.
    It never parses a backend string as JSON, so duplicate-key source text and
    scalar coercions cannot be hidden by this boundary.
    """
    if type(value) not in {dict, list}:
        raise ValueError("backend result must be a JSON object or array")
    pending: list[tuple[Any, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    nodes = 0
    estimated_serialized_bytes = 0

    def add_size(size: int) -> None:
        nonlocal estimated_serialized_bytes
        estimated_serialized_bytes += size
        if estimated_serialized_bytes > _MAX_BACKEND_RESULT_BYTES:
            raise ValueError("backend result exceeds its serialized byte bound")

    def validate_string(text: str) -> None:
        raw = text.encode("utf-8", errors="strict")
        if len(raw) > _MAX_BACKEND_RESULT_BYTES:
            raise ValueError("backend result string exceeds its byte bound")
        # Account for JSON quoting and escaping before the final whole-value
        # serialization, so a large tree cannot allocate an oversized buffer.
        add_size(len(json.dumps(text, ensure_ascii=False, separators=(",", ":"))
                    .encode("utf-8")))

    while pending:
        item, depth, exiting = pending.pop()
        if exiting:
            active.remove(id(item))
            continue
        nodes += 1
        if nodes > _MAX_BACKEND_RESULT_NODES or depth > _MAX_BACKEND_RESULT_DEPTH:
            raise ValueError("backend result exceeds its structural bound")
        kind = type(item)
        if item is None or kind in {bool, int}:
            if kind is int and item.bit_length() > _MAX_BACKEND_RESULT_BYTES * 4:
                raise ValueError("backend result integer exceeds its byte bound")
            add_size(5 if item is None else 6 if kind is bool else max(1, item.bit_length() // 3))
            continue
        if kind is float:
            if not math.isfinite(item):
                raise ValueError("backend result contains a nonfinite number")
            add_size(32)
            continue
        if kind is str:
            validate_string(item)
            continue
        if kind in {dict, list}:
            if len(item) + nodes > _MAX_BACKEND_RESULT_NODES:
                raise ValueError("backend result exceeds its node bound")
            identity = id(item)
            if identity in active:
                raise ValueError("backend result contains a cycle")
            active.add(identity)
            pending.append((item, depth, True))
            add_size(2 + max(0, len(item) - 1)
                     + (len(item) if kind is dict else 0))
            children = list(item.items()) if kind is dict else [(None, child) for child in item]
            for key, child in reversed(children):
                if kind is dict:
                    if type(key) is not str:
                        raise ValueError("backend result object key is not text")
                    validate_string(key)
                pending.append((child, depth + 1, False))
            continue
        raise ValueError("backend result contains a non-JSON value")


def _bounded_backend_tool_result(value: Any, candidate: SelectedNativeCandidate) -> Any:
    """Serialize one selected backend result under the exact v113 envelope."""
    expected_schema = {
        "additionalProperties": False,
        "properties": {
            "result": {"oneOf": [{"type": "object"}, {"type": "array"}]},
            "result_trust": {"const": "untrusted-backend-data"},
            "schema": {"const": 1},
        },
        "required": ["schema", "result_trust", "result"],
        "type": "object",
    }
    if ((candidate.registration_id, candidate.native_tool_name) not in _BOUNDED_BACKEND_REGISTRATIONS
            or candidate.result_schema_id != _BOUNDED_BACKEND_RESULT_SCHEMA_ID
            or _canonical(_thaw_frozen_json(candidate.result_schema)) != _canonical(expected_schema)):
        return _UNSAFE_PLUGIN_RESULT
    try:
        _validate_backend_result_tree(value)
        wrapped = {"schema": 1, "result_trust": "untrusted-backend-data", "result": value}
        encoded = json.dumps(wrapped, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > _MAX_BACKEND_RESULT_BYTES:
            return _UNSAFE_PLUGIN_RESULT
        return encoded.decode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return _UNSAFE_PLUGIN_RESULT


class _NativePluginContextResultAdapter:
    """Preserve PluginContext APIs while enforcing Hermes' supported tool result types."""

    __slots__ = ("__context", "__registered_tool_names", "__package", "__adapter_id")

    def __init__(self, context: object, package: SelectedNativePackage, adapter_id: str) -> None:
        object.__setattr__(self, "_NativePluginContextResultAdapter__context", context)
        object.__setattr__(self, "_NativePluginContextResultAdapter__registered_tool_names", [])
        object.__setattr__(self, "_NativePluginContextResultAdapter__package", package)
        object.__setattr__(self, "_NativePluginContextResultAdapter__adapter_id", adapter_id)

    @property
    def registered_tool_names(self) -> tuple[str, ...]:
        return tuple(object.__getattribute__(self, "_NativePluginContextResultAdapter__registered_tool_names"))

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(object.__getattribute__(self, "_NativePluginContextResultAdapter__context"), name)

    def register_tool(self, name: str, toolset: str, schema: dict, handler: Any,
                      check_fn: Any = None, requires_env: Any = None, is_async: bool = False,
                      description: str = "", emoji: str = "", override: bool = False) -> Any:
        if not callable(handler):
            raise NativePluginLoadUnavailable("selected native tool handler is unavailable")
        package = object.__getattribute__(self, "_NativePluginContextResultAdapter__package")
        adapter_id = object.__getattribute__(self, "_NativePluginContextResultAdapter__adapter_id")
        candidate = package.candidate(name)
        if (candidate is None or candidate.is_native_mcp or candidate.adapter_id != adapter_id
                or candidate.native_server_name != "hermes-installer"
                or toolset != candidate.toolset or description != candidate.description
                or not isinstance(schema, dict)
                or _canonical(schema) != _canonical(_thaw_frozen_json(candidate.argument_schema))):
            raise NativePluginLoadUnavailable("native PluginContext tool differs from the selected candidate index")
        is_bounded_backend = (candidate.registration_id, candidate.native_tool_name) in _BOUNDED_BACKEND_REGISTRATIONS
        if is_async:
            @functools.wraps(handler)
            async def bounded_handler(*args: Any, **kwargs: Any) -> Any:
                result = await handler(*args, **kwargs)
                return (_bounded_backend_tool_result(result, candidate) if is_bounded_backend
                        else _plugin_tool_result(result))
        else:
            @functools.wraps(handler)
            def bounded_handler(*args: Any, **kwargs: Any) -> Any:
                result = handler(*args, **kwargs)
                if inspect.isawaitable(result):
                    close = getattr(result, "close", None)
                    if callable(close):
                        close()
                    return _UNSAFE_PLUGIN_RESULT
                return (_bounded_backend_tool_result(result, candidate) if is_bounded_backend
                        else _plugin_tool_result(result))

        context = object.__getattribute__(self, "_NativePluginContextResultAdapter__context")
        registration = context.register_tool(
            name=name, toolset=toolset, schema=schema, handler=bounded_handler,
            check_fn=check_fn, requires_env=requires_env, is_async=is_async,
            description=description, emoji=emoji, override=override,
        )
        if registration is not None:
            object.__getattribute__(self, "_NativePluginContextResultAdapter__registered_tool_names").append(name)
            package._mark_candidate_registered(candidate.adapter_id, candidate.registration_id)
        return registration


def _thaw_frozen_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_frozen_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_frozen_json(item) for item in value]
    return value


def selected_mount_target(package_id: str, profile_id: str, generation: str,
                          compiled_closure_sha256: str) -> Path:
    """Return the sole mount location permitted by the protected assembly contract."""
    values = (package_id, profile_id, generation)
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in values):
        raise NativePluginLoadUnavailable("root package identity is malformed")
    if not isinstance(compiled_closure_sha256, str) or not _SHA256.fullmatch(compiled_closure_sha256):
        raise NativePluginLoadUnavailable("root closure pin is malformed")
    preimage = b"\0".join(value.encode("utf-8") for value in (
        package_id, profile_id, generation, compiled_closure_sha256,
    ))
    mount_id = hashlib.sha256(preimage).hexdigest()
    return Path("/run/hermes-installer/native") / mount_id


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _json_document(raw: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise NativePluginLoadUnavailable(f"{label} is missing or exceeds its bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs_no_duplicates,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise NativePluginLoadUnavailable(f"{label} is not strict UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise NativePluginLoadUnavailable(f"{label} must be a JSON object")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise NativePluginLoadUnavailable("native package manifest is not canonical JSON data") from None


def _validate_compiled_schema(value: Any, *, depth: int = 0) -> None:
    """Accept only the finite JSON Schema subset understood by native dispatch."""
    if depth > 16 or not isinstance(value, dict):
        raise NativePluginLoadUnavailable("native candidate schema is malformed or too deeply nested")
    allowed = {
        "type", "properties", "required", "additionalProperties", "items", "enum",
        "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
    }
    if set(value) - allowed or "type" not in value:
        raise NativePluginLoadUnavailable("native candidate schema uses an unsupported field")
    kind = value["type"]
    if kind not in {"object", "array", "string", "integer", "number", "boolean", "null"}:
        raise NativePluginLoadUnavailable("native candidate schema uses an unsupported type")
    if kind == "object":
        properties, required = value.get("properties", {}), value.get("required", [])
        if (not isinstance(properties, dict) or len(properties) > 128
                or not isinstance(required, list) or len(required) > 128
                or any(not isinstance(name, str) or not 1 <= len(name) <= 128 for name in required)
                or len(set(required)) != len(required)
                or set(required) - set(properties)
                or type(value.get("additionalProperties", False)) is not bool):
            raise NativePluginLoadUnavailable("native candidate object schema is malformed")
        for name, child in properties.items():
            if not isinstance(name, str) or not 1 <= len(name) <= 128:
                raise NativePluginLoadUnavailable("native candidate property name is malformed")
            _validate_compiled_schema(child, depth=depth + 1)
    if kind == "array" and "items" in value:
        _validate_compiled_schema(value["items"], depth=depth + 1)
    if kind == "array" and "items" not in value:
        raise NativePluginLoadUnavailable("native candidate array schema has no item schema")
    if "enum" in value:
        enum = value["enum"]
        if (not isinstance(enum, list) or not enum or len(enum) > 256
                or len({_canonical(item) for item in enum}) != len(enum)):
            raise NativePluginLoadUnavailable("native candidate enum exceeds its bound")
    for key in ("minimum", "maximum"):
        if key in value and (kind not in {"integer", "number"}
                or isinstance(value[key], bool) or type(value[key]) not in {int, float}
                or not math.isfinite(value[key])):
            raise NativePluginLoadUnavailable("native candidate numeric bound is malformed")
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        expected_type = "string" if "Length" in key else "array"
        if key in value and (kind != expected_type or type(value[key]) is not int
                             or not 0 <= value[key] <= 1_000_000):
            raise NativePluginLoadUnavailable("native candidate size bound is malformed")
    for low, high in (("minimum", "maximum"), ("minLength", "maxLength"), ("minItems", "maxItems")):
        if low in value and high in value and value[low] > value[high]:
            raise NativePluginLoadUnavailable("native candidate schema range is inverted")


def _parse_native_candidate_index(raw: bytes, *, selected: RootSelectedPluginEffects,
                                  manifest: MappingProxyType) -> tuple[SelectedNativeCandidate, ...]:
    doc = _json_document(raw, maximum=_MAX_NATIVE_CANDIDATE_INDEX_BYTES,
                         label="root-selected native candidate index")
    expected_doc_fields = {
        "schema", "package_id", "profile_id", "generation", "resolver_sha256",
        "candidates", "registration_projection_sha256", "registrations",
    }
    if set(doc) != expected_doc_fields or _canonical(doc) != raw:
        raise NativePluginLoadUnavailable("root-selected native candidate index is not canonical or strict")
    if (type(doc["schema"]) is not int or doc["schema"] != 1
            or doc["package_id"] != selected.package_id
            or doc["profile_id"] != selected.profile_id
            or doc["generation"] != selected.generation
            or doc["resolver_sha256"] != selected.resolver_digest):
        raise NativePluginLoadUnavailable("native candidate index differs from the selected package")
    rows, registrations = doc["candidates"], doc["registrations"]
    if (not isinstance(rows, list) or not 1 <= len(rows) <= _MAX_NATIVE_CANDIDATES
            or not isinstance(registrations, list) or len(registrations) != len(rows)
            or not 1 <= len(registrations) <= _MAX_NATIVE_CANDIDATES):
        raise NativePluginLoadUnavailable("native registration projection exceeds its row bound")
    projection_digest = doc["registration_projection_sha256"]
    if (not isinstance(projection_digest, str) or not _SHA256.fullmatch(projection_digest)
            or hashlib.sha256(_canonical(registrations)).hexdigest() != projection_digest):
        raise NativePluginLoadUnavailable("native registration projection digest differs")

    registration_fields = {
        "registration_id", "native_tool_name", "native_server_name", "toolset", "family",
        "adapter_id", "argument_schema_id", "result_schema_id", "native_schema_sha256",
        "registration_source_artifact_id", "registration_source_sha256",
        "registration_source_receipt_handle", "handler_kind", "handler_id",
        "selector_fields", "action_bindings", "observer_enrollment_ids", "generation",
    }
    binding_fields = {"selector_values", "action_binding_id", "argument_projection", "workflow_id"}
    expected_row_fields = {
        "native_tool_name", "adapter_id", "action_id", "argument_schema", "result_schema",
        "native_schema_sha256", "observer_enrollment_ids", "native_server_name", "description",
        "registration_id", "toolset", "family", "handler_kind",
    }
    registrations_by_id: dict[str, Mapping[str, Any]] = {}
    names: set[str] = set()
    manifest_adapters = {row["adapter_id"]: set(row["action_ids"]) for row in manifest["adapters"]}
    closure_files = {row["relative_path"]: row for row in manifest["closure_files"]}
    for registration in registrations:
        if not isinstance(registration, dict) or set(registration) != registration_fields:
            raise NativePluginLoadUnavailable("native registration row has unknown or missing fields")
        reg_id, name, adapter_id = (registration["registration_id"], registration["native_tool_name"],
                                    registration["adapter_id"])
        if (not isinstance(reg_id, str) or not _ID.fullmatch(reg_id)
                or not isinstance(name, str) or not _ID.fullmatch(name) or name in names
                or not isinstance(adapter_id, str) or not _ID.fullmatch(adapter_id)
                or reg_id != f"{adapter_id}:tool:{name}" or reg_id in registrations_by_id):
            raise NativePluginLoadUnavailable("native registration identity is malformed or duplicated")
        for key in ("native_server_name", "toolset", "family", "handler_id",
                    "argument_schema_id", "result_schema_id", "registration_source_artifact_id",
                    "registration_source_receipt_handle"):
            if not isinstance(registration[key], str) or not _ID.fullmatch(registration[key]):
                raise NativePluginLoadUnavailable("native registration metadata or schema identity is malformed")
        for key in ("native_schema_sha256", "registration_source_sha256"):
            if not isinstance(registration[key], str) or not _SHA256.fullmatch(registration[key]):
                raise NativePluginLoadUnavailable("native registration source digest is malformed")
        if registration["generation"] != selected.generation:
            raise NativePluginLoadUnavailable("native registration generation differs from the selected package")
        if (reg_id, name) in _BOUNDED_BACKEND_REGISTRATIONS:
            schema_member = closure_files.get(
                f"catalog/schemas/{_BOUNDED_BACKEND_RESULT_SCHEMA_ID}.json")
            if (registration["result_schema_id"] != _BOUNDED_BACKEND_RESULT_SCHEMA_ID
                    or schema_member is None
                    or schema_member["sha256"] != _BOUNDED_BACKEND_RESULT_SCHEMA_SHA256
                    or schema_member["size_bytes"] != _BOUNDED_BACKEND_RESULT_SCHEMA_SIZE):
                raise NativePluginLoadUnavailable("backend result schema is not the exact pinned v113 artifact")
        if registration["registration_source_sha256"] not in {
                row["sha256"] for row in manifest["closure_files"]}:
            raise NativePluginLoadUnavailable("native registration source is not pinned by the selected closure")
        kind = registration["handler_kind"]
        if kind not in {"effect-action", "finite-selector", "finite-workflow",
                        "public-registry-read", "owner-overlay", "mcp-dispatch"}:
            raise NativePluginLoadUnavailable("native registration handler kind is unsupported")
        if ((kind == "mcp-dispatch") != (adapter_id == _NATIVE_MCP_ADAPTER_ID)
                or (adapter_id == _NATIVE_MCP_ADAPTER_ID and registration["native_server_name"] == "hermes-installer")
                or (adapter_id != _NATIVE_MCP_ADAPTER_ID and registration["native_server_name"] != "hermes-installer")):
            raise NativePluginLoadUnavailable("native registration owner differs from its handler family")
        selector_fields = registration["selector_fields"]
        bindings = registration["action_bindings"]
        if (not isinstance(selector_fields, list) or len(selector_fields) > 128
                or len(set(selector_fields)) != len(selector_fields)
                or any(not isinstance(field, str) or not _ID.fullmatch(field) for field in selector_fields)
                or not isinstance(bindings, list) or not 1 <= len(bindings) <= 128):
            raise NativePluginLoadUnavailable("native registration selector projection is malformed")
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != binding_fields:
                raise NativePluginLoadUnavailable("native registration action binding is malformed")
            action_binding_id = binding["action_binding_id"]
            if action_binding_id is not None:
                if (not isinstance(action_binding_id, str) or not action_binding_id.startswith(f"{adapter_id}:action:")):
                    raise NativePluginLoadUnavailable("native registration action binding identity is malformed")
                child_action = action_binding_id.split(":action:", 1)[1]
                if (not _ID.fullmatch(child_action) or child_action not in manifest_adapters.get(adapter_id, set())
                        or selected.resolve(adapter_id, child_action) is None):
                    raise NativePluginLoadUnavailable("native registration child action is not selected")
            selector_values = binding["selector_values"]
            projection = binding["argument_projection"]
            workflow_id = binding["workflow_id"]
            if (not isinstance(selector_values, dict) or set(selector_values) != set(selector_fields)
                    or any(not isinstance(key, str) or not isinstance(value, str)
                           for key, value in selector_values.items())
                    or not isinstance(projection, list) or len(projection) > 128
                    or (workflow_id is not None and
                        (not isinstance(workflow_id, str) or not _ID.fullmatch(workflow_id)))):
                raise NativePluginLoadUnavailable("native registration binding fields are malformed")
            for item in projection:
                if (not isinstance(item, dict) or set(item) != {"name", "source_field"}
                        or not isinstance(item["name"], str) or not _ID.fullmatch(item["name"])
                        or not isinstance(item["source_field"], str) or not _ID.fullmatch(item["source_field"])):
                    raise NativePluginLoadUnavailable("native registration argument projection is malformed")
        names.add(name)
        registrations_by_id[reg_id] = registration

    result: list[SelectedNativeCandidate] = []
    candidate_registration_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != expected_row_fields:
            raise NativePluginLoadUnavailable("native candidate row has unknown or missing fields")
        name, adapter_id, action_id = row["native_tool_name"], row["adapter_id"], row["action_id"]
        reg_id = row["registration_id"]
        registration = registrations_by_id.get(reg_id) if isinstance(reg_id, str) else None
        if (registration is None or reg_id in candidate_registration_ids
                or not isinstance(name, str) or not _ID.fullmatch(name)
                or not isinstance(adapter_id, str) or not _ID.fullmatch(adapter_id)
                or not isinstance(action_id, str) or not _ID.fullmatch(action_id)):
            raise NativePluginLoadUnavailable("native candidate identity is malformed or duplicated")
        common_fields = ("native_tool_name", "native_server_name", "toolset", "family", "adapter_id",
                         "native_schema_sha256", "observer_enrollment_ids", "handler_kind")
        if any(_canonical(row[field]) != _canonical(registration[field]) for field in common_fields):
            raise NativePluginLoadUnavailable("native candidate differs from its registration projection")
        argument_schema, result_schema = row["argument_schema"], row["result_schema"]
        if not isinstance(argument_schema, dict) or not isinstance(result_schema, dict):
            raise NativePluginLoadUnavailable("native candidate schemas must be JSON objects")
        if argument_schema.get("type") != "object":
            raise NativePluginLoadUnavailable("native candidate arguments must use an object schema")
        _validate_compiled_schema(argument_schema)
        _validate_compiled_schema(result_schema)
        schema_digest = row["native_schema_sha256"]
        if (not isinstance(schema_digest, str) or not _SHA256.fullmatch(schema_digest)
                or hashlib.sha256(_canonical(argument_schema)).hexdigest() != schema_digest):
            raise NativePluginLoadUnavailable("native candidate argument schema digest differs")
        if schema_digest != registration["native_schema_sha256"]:
            raise NativePluginLoadUnavailable("native candidate schema differs from its selected registration")
        handler_kind = registration["handler_kind"]
        action_bindings = registration["action_bindings"]
        if handler_kind == "effect-action":
            binding_id = action_bindings[0]["action_binding_id"] if len(action_bindings) == 1 else None
            expected_action = (binding_id.split(":action:", 1)[1]
                               if isinstance(binding_id, str) else None)
        elif handler_kind == "mcp-dispatch":
            expected_action = registration["handler_id"]
        else:
            expected_action = reg_id
        if action_id != expected_action:
            raise NativePluginLoadUnavailable("native candidate action differs from the registration projection")
        observers = row["observer_enrollment_ids"]
        if (not isinstance(observers, list) or not 1 <= len(observers) <= 64
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in observers)
                or len(set(observers)) != len(observers)):
            raise NativePluginLoadUnavailable("native candidate observer enrollment list is malformed")
        server = row["native_server_name"]
        description = row["description"]
        if (not isinstance(server, str) or not _MCP_SERVER.fullmatch(server)
                or not isinstance(description, str) or not description or len(description) > 4096
                or any(ord(char) < 0x20 for char in description)):
            raise NativePluginLoadUnavailable("native candidate display metadata is malformed")
        if adapter_id == _NATIVE_MCP_ADAPTER_ID and server == "hermes-installer":
            raise NativePluginLoadUnavailable("native MCP candidate has the installer action owner")
        if adapter_id != _NATIVE_MCP_ADAPTER_ID and server != "hermes-installer":
            raise NativePluginLoadUnavailable("compiled installer action has an unapproved toolset owner")
        result_schema_id = registration["result_schema_id"]
        if ((reg_id, name) in _BOUNDED_BACKEND_REGISTRATIONS
                and (result_schema_id != _BOUNDED_BACKEND_RESULT_SCHEMA_ID
                     or _canonical(result_schema) != _canonical({
                         "additionalProperties": False,
                         "properties": {
                             "result": {"oneOf": [{"type": "object"}, {"type": "array"}]},
                             "result_trust": {"const": "untrusted-backend-data"},
                             "schema": {"const": 1},
                         },
                         "required": ["schema", "result_trust", "result"],
                         "type": "object",
                     }))):
            raise NativePluginLoadUnavailable("backend result schema is not the exact v113 bounded envelope")
        candidate_registration_ids.add(reg_id)
        result.append(SelectedNativeCandidate(
            name, adapter_id, action_id, _freeze_json(argument_schema), _freeze_json(result_schema),
            schema_digest, tuple(observers), server, description, reg_id, row["toolset"], row["family"],
            handler_kind, result_schema_id, tuple(registration["selector_fields"]),
            tuple(_freeze_json(item) for item in action_bindings),
        ))
    if candidate_registration_ids != set(registrations_by_id):
        raise NativePluginLoadUnavailable("native candidate set does not cover the exact registration projection")
    return tuple(result)


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NativePluginLoadUnavailable("native manifest contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise NativePluginLoadUnavailable("native manifest path escapes its closure")
    if path.as_posix() != value:
        raise NativePluginLoadUnavailable("native manifest path is not normalized")
    return value


def _read_native_candidate_index_from_verified_mount(root: Path, manifest: MappingProxyType,
                                                      selected: RootSelectedPluginEffects
                                                      ) -> tuple[SelectedNativeCandidate, ...]:
    pin = manifest["candidate_index"]
    member = root / "closure" / _NATIVE_CANDIDATE_INDEX_PATH
    raw = _read_regular_nofollow(member, maximum=_MAX_NATIVE_CANDIDATE_INDEX_BYTES)
    if len(raw) != pin["size_bytes"] or hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        raise NativePluginLoadUnavailable("mounted native candidate index differs from its manifest pin")
    candidates = _parse_native_candidate_index(raw, selected=selected, manifest=manifest)
    registrations = {candidate.registration_id for candidate in candidates}
    action_bindings = {
        binding["action_binding_id"]
        for candidate in candidates for binding in candidate.action_bindings
        if isinstance(binding, Mapping) and isinstance(binding.get("action_binding_id"), str)
    }
    workflows = {
        binding["workflow_id"]
        for candidate in candidates for binding in candidate.action_bindings
        if isinstance(binding, Mapping) and isinstance(binding.get("workflow_id"), str)
    }
    observers = {observer for candidate in candidates for observer in candidate.observer_enrollment_ids}
    for role in selected.process_role_records:
        if (not set(role["registration_ids"]).issubset(registrations)
                or not set(role["action_binding_ids"]).issubset(action_bindings)
                or not set(role["workflow_ids"]).issubset(workflows)
                or not set(role["observer_enrollment_ids"]).issubset(observers)):
            raise NativePluginLoadUnavailable("native process role references an unselected registration or observer")
    return candidates


def read_native_candidate_index(binding: RootSelectedPluginEffects) -> tuple[SelectedNativeCandidate, ...]:
    """Read only the sealed candidate member selected by a verified root binding.

    The manifest and closure are revalidated at this API boundary. It accepts
    no path, package selector, profile selector, or caller-supplied document.
    """
    if not isinstance(binding, RootSelectedPluginEffects):
        raise NativePluginLoadUnavailable("native candidate index requires a root-selected binding")
    binding._require_live()
    target = selected_mount_target(binding.package_id, binding.profile_id, binding.generation,
                                   binding.compiled_closure_sha256)
    try:
        _require_private_readonly_mount(target, Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
        root = target.resolve(strict=True)
        if root != target or root.is_symlink() or not root.is_dir():
            raise NativePluginLoadUnavailable("root-selected native mount target is unavailable")
        raw_manifest = _read_regular_nofollow(root / "manifest.json", maximum=_MAX_ENTRYPOINT_BYTES)
        manifest = _manifest(raw_manifest, selected=binding)
        _verify_closure(root, manifest)
        return _read_native_candidate_index_from_verified_mount(root, manifest, binding)
    except NativePluginLoadUnavailable:
        raise
    except OSError:
        raise NativePluginLoadUnavailable("root native candidate index mount is unavailable") from None


def _read_regular_nofollow(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise NativePluginLoadUnavailable("root native package file is unavailable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > maximum:
            raise NativePluginLoadUnavailable("root native package file is not an immutable regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != info.st_size or len(raw) > maximum:
            raise NativePluginLoadUnavailable("root native package file changed during read")
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise NativePluginLoadUnavailable("root native package file changed during read")
        return raw
    finally:
        os.close(fd)


def _decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _require_private_readonly_mount(target: Path, mountinfo: str) -> None:
    expected = str(target)
    matches: list[tuple[set[str], list[str]]] = []
    for line in mountinfo.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            mountpoint = _decode_mount_field(fields[4])
            options = set(fields[5].split(",")) | set(fields[separator + 3].split(","))
            propagation = fields[6:separator]
        except (ValueError, IndexError):
            continue
        if mountpoint == expected:
            matches.append((options, propagation))
    if len(matches) != 1:
        raise NativePluginLoadUnavailable("root native package mount is absent or ambiguous")
    options, propagation = matches[0]
    if not {"ro", "nosuid", "nodev", "noexec"}.issubset(options):
        raise NativePluginLoadUnavailable("root native package mount lacks required restrictive flags")
    if any(item.startswith(("shared:", "master:", "propagate_from:")) for item in propagation):
        raise NativePluginLoadUnavailable("root native package mount has shared propagation")


def _require_protected_import_environment() -> None:
    """Reject interpreter startup modes that add caller-controlled import roots."""
    if ("PYTHONPATH" in os.environ or "PYTHONHOME" in os.environ
            or getattr(sys.flags, "no_user_site", 0) != 1
            or getattr(site, "ENABLE_USER_SITE", True) not in {False, None}):
        raise NativePluginLoadUnavailable("Hermes runtime import environment is not protected")


def _manifest(raw: bytes, *, selected: RootSelectedPluginEffects) -> dict[str, Any]:
    value = _json_document(raw, maximum=_MAX_ENTRYPOINT_BYTES, label="native entrypoint manifest")
    if set(value) != {"schema", "package_id", "profile_id", "generation", "closure_files",
                      "adapters", "dependencies", "candidate_index",
                      "process_role_records", "process_role_records_sha256"}:
        raise NativePluginLoadUnavailable("native entrypoint manifest has unknown or missing fields")
    if (type(value["schema"]) is not int or value["schema"] != 1
            or value["package_id"] != selected.package_id
            or value["profile_id"] != selected.profile_id
            or value["generation"] != selected.generation
            or hashlib.sha256(raw).hexdigest() != selected.entrypoint_sha256):
        raise NativePluginLoadUnavailable("native entrypoint manifest does not match the selected package")
    files = value["closure_files"]
    if not isinstance(files, list) or not 1 <= len(files) <= _MAX_CLOSURE_FILES:
        raise NativePluginLoadUnavailable("native closure file manifest exceeds its bound")
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    previous = ""
    for row in files:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode"}:
            raise NativePluginLoadUnavailable("native closure file row has unknown or missing fields")
        name = _relative_path(row["relative_path"])
        if (name in names or name.casefold() in folded or name <= previous
                or not isinstance(row["sha256"], str) or not _SHA256.fullmatch(row["sha256"])
                or type(row["size_bytes"]) is not int or row["size_bytes"] <= 0
                or type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777
                or row["mode"] & 0o022):
            raise NativePluginLoadUnavailable("native closure file row is malformed or noncanonical")
        previous = name
        names.add(name)
        folded.add(name.casefold())
        total += row["size_bytes"]
        if total > _MAX_CLOSURE_BYTES:
            raise NativePluginLoadUnavailable("native closure exceeds its total size bound")
        normalized.append(dict(row))
    if hashlib.sha256(_canonical(normalized)).hexdigest() != selected.compiled_closure_sha256:
        raise NativePluginLoadUnavailable("native compiled closure digest does not match root binding")
    roles = value["process_role_records"]
    if not isinstance(roles, list) or not 1 <= len(roles) <= _MAX_LOADER_PROCESS_ROLES:
        raise NativePluginLoadUnavailable("native process-role selection is missing or exceeds its bound")
    role_fields = {
        "role_id", "package_id", "native_package_generation", "profile_id", "profile_generation",
        "role_artifact_id", "role_sha256", "role_source_receipt_handle", "module_name",
        "closure_member_path", "role_source_revision", "role_source_tree_sha256",
        "observer_enrollment_ids", "registration_ids", "action_binding_ids", "workflow_ids",
    }
    normalized_roles: list[dict[str, Any]] = []
    seen_role_ids: set[str] = set()
    seen_role_modules: set[str] = set()
    role_profile_generations: set[str] = set()
    previous_role_id = ""
    closure_by_path = {row["relative_path"]: row for row in normalized}
    role_list_fields = ("observer_enrollment_ids", "registration_ids", "action_binding_ids", "workflow_ids")
    for row in roles:
        if not isinstance(row, dict) or set(row) != role_fields:
            raise NativePluginLoadUnavailable("native process-role row has unknown or missing fields")
        role_id = row["role_id"]
        module_name = row["module_name"]
        member_path = _relative_path(row["closure_member_path"])
        role_sha = row["role_sha256"]
        if (not isinstance(role_id, str) or not _ID.fullmatch(role_id) or role_id <= previous_role_id
                or role_id in seen_role_ids
                or row["package_id"] != selected.package_id
                or row["native_package_generation"] != selected.generation
                or row["profile_id"] != selected.profile_id
                or not isinstance(row["profile_generation"], str) or not _ID.fullmatch(row["profile_generation"])
                or not isinstance(row["role_artifact_id"], str) or not _ID.fullmatch(row["role_artifact_id"])
                or not isinstance(role_sha, str) or not _SHA256.fullmatch(role_sha)
                or not isinstance(row["role_source_receipt_handle"], str)
                or not _ID.fullmatch(row["role_source_receipt_handle"])
                or not isinstance(module_name, str) or not _MODULE.fullmatch(module_name)
                or module_name in seen_role_modules
                or not isinstance(row["role_source_revision"], str)
                or not 1 <= len(row["role_source_revision"]) <= 256
                or any(ord(char) < 0x20 for char in row["role_source_revision"])
                or not isinstance(row["role_source_tree_sha256"], str)
                or not _SHA256.fullmatch(row["role_source_tree_sha256"])):
            raise NativePluginLoadUnavailable("native process-role identity or package join is invalid")
        closure_member = closure_by_path.get(member_path)
        if closure_member is None or closure_member["sha256"] != role_sha:
            raise NativePluginLoadUnavailable("native process-role module differs from its closure pin")
        for key in role_list_fields:
            values = row[key]
            if (not isinstance(values, list) or len(values) > 512
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in values)
                    or values != sorted(set(values))):
                raise NativePluginLoadUnavailable("native process-role foreign-key list is malformed")
        if not row["observer_enrollment_ids"]:
            raise NativePluginLoadUnavailable("native process role has no selected observer")
        previous_role_id = role_id
        seen_role_ids.add(role_id)
        seen_role_modules.add(module_name)
        role_profile_generations.add(row["profile_generation"])
        normalized_roles.append(dict(row))
    if len(role_profile_generations) != 1:
        raise NativePluginLoadUnavailable("native process roles disagree on process generation")
    role_digest = value["process_role_records_sha256"]
    if (not isinstance(role_digest, str) or not _SHA256.fullmatch(role_digest)
            or hashlib.sha256(_canonical(normalized_roles)).hexdigest() != role_digest
            or role_digest != selected.process_role_records_sha256):
        raise NativePluginLoadUnavailable("native process-role digest differs from its root resolver cross-pin")
    try:
        selected._accept_verified_process_role_records(
            tuple(MappingProxyType(row) for row in normalized_roles), role_digest,
        )
    except NativePluginBindingUnavailable:
        raise NativePluginLoadUnavailable("native process-role selection is unavailable") from None
    candidate_ref = value["candidate_index"]
    if not isinstance(candidate_ref, dict) or set(candidate_ref) != {
            "artifact_id", "relative_path", "sha256", "size_bytes"}:
        raise NativePluginLoadUnavailable("native candidate-index manifest pin is missing or malformed")
    candidate_relative = _relative_path(candidate_ref["relative_path"])
    candidate_file = next((row for row in normalized if row["relative_path"] == candidate_relative), None)
    expected_candidate_artifact = f"native-candidate-index:{selected.package_id}:{selected.generation}"
    if (candidate_ref["artifact_id"] != expected_candidate_artifact
            or candidate_relative != _NATIVE_CANDIDATE_INDEX_PATH
            or not isinstance(candidate_ref["sha256"], str) or not _SHA256.fullmatch(candidate_ref["sha256"])
            or type(candidate_ref["size_bytes"]) is not int
            or not 1 <= candidate_ref["size_bytes"] <= _MAX_NATIVE_CANDIDATE_INDEX_BYTES
            or candidate_file is None
            or candidate_file["sha256"] != candidate_ref["sha256"]
            or candidate_file["size_bytes"] != candidate_ref["size_bytes"]):
        raise NativePluginLoadUnavailable("native candidate-index pin is outside the selected closure")

    adapters = value["adapters"]
    dependencies = value["dependencies"]
    if (not isinstance(adapters, list) or not adapters or len(adapters) > 692
            or not isinstance(dependencies, list) or len(dependencies) > 256):
        raise NativePluginLoadUnavailable("native adapter or dependency list is malformed")
    adapter_ids: set[str] = set()
    module_names: set[str] = set()
    module_paths: set[str] = set()
    for row in adapters:
        fields = {"adapter_id", "relative_module_path", "module_name", "entrypoint_symbol",
                  "artifact_sha256", "allowed_internal_modules", "allowed_dependency_artifact_ids", "action_ids"}
        if not isinstance(row, dict) or set(row) != fields:
            raise NativePluginLoadUnavailable("native adapter row has unknown or missing fields")
        adapter_id, module_name = row["adapter_id"], row["module_name"]
        relative = _relative_path(row["relative_module_path"])
        if (not isinstance(adapter_id, str) or not _ID.fullmatch(adapter_id) or adapter_id in adapter_ids
                or not isinstance(module_name, str) or not _MODULE.fullmatch(module_name) or module_name in module_names
                or relative in module_paths
                or not isinstance(row["entrypoint_symbol"], str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", row["entrypoint_symbol"])
                or not isinstance(row["artifact_sha256"], str) or not _SHA256.fullmatch(row["artifact_sha256"])
                or relative not in names or row["artifact_sha256"] != next(
                    file["sha256"] for file in normalized if file["relative_path"] == relative
                )):
            raise NativePluginLoadUnavailable("native adapter does not map to its pinned closure module")
        for key in ("allowed_internal_modules", "allowed_dependency_artifact_ids", "action_ids"):
            seq = row[key]
            if not isinstance(seq, list) or any(not isinstance(item, str) for item in seq) or len(set(seq)) != len(seq):
                raise NativePluginLoadUnavailable("native adapter allowlist is malformed")
        if any(not _MODULE.fullmatch(item) for item in row["allowed_internal_modules"]):
            raise NativePluginLoadUnavailable("native adapter internal module allowlist is malformed")
        if any(not _ID.fullmatch(item) for item in row["allowed_dependency_artifact_ids"]):
            raise NativePluginLoadUnavailable("native adapter dependency allowlist is malformed")
        if any(not _ID.fullmatch(item) for item in row["action_ids"]):
            raise NativePluginLoadUnavailable("native adapter action list is malformed")
        adapter_ids.add(adapter_id)
        module_names.add(module_name)
        module_paths.add(relative)
    dependency_ids: set[str] = set()
    for row in dependencies:
        if not isinstance(row, dict) or set(row) != {"artifact_id", "sha256", "module_names"}:
            raise NativePluginLoadUnavailable("native dependency row has unknown or missing fields")
        artifact_id = row["artifact_id"]
        if (not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id) or artifact_id in dependency_ids
                or not isinstance(row["sha256"], str) or not _SHA256.fullmatch(row["sha256"])
                or not isinstance(row["module_names"], list)
                or any(not isinstance(name, str) or not _MODULE.fullmatch(name) for name in row["module_names"])
                or len(set(row["module_names"])) != len(row["module_names"])):
            raise NativePluginLoadUnavailable("native dependency row is malformed")
        dependency_ids.add(artifact_id)
    for adapter in adapters:
        if not set(adapter["allowed_dependency_artifact_ids"]).issubset(dependency_ids):
            raise NativePluginLoadUnavailable("native adapter names an unselected dependency artifact")
    dependency_module_names = [name for dependency in dependencies for name in dependency["module_names"]]
    if (len(dependency_module_names) != len(set(dependency_module_names))
            or set(dependency_module_names) & module_names):
        raise NativePluginLoadUnavailable("native dependency module names collide with selected adapters")
    selected_rows = selected.adapter_rows
    by_adapter: dict[str, set[str]] = {}
    for effect in selected_rows:
        by_adapter.setdefault(effect.adapter_id, set()).add(effect.action_id)
    resolver_manifest_by_adapter: dict[str, str] = {}
    resolver_adapter_by_adapter: dict[str, str] = {}
    for effect in selected_rows:
        previous_manifest = resolver_manifest_by_adapter.setdefault(effect.adapter_id, effect.manifest_sha256)
        previous_adapter = resolver_adapter_by_adapter.setdefault(effect.adapter_id, effect.adapter_sha256)
        if previous_manifest != effect.manifest_sha256 or previous_adapter != effect.adapter_sha256:
            raise NativePluginLoadUnavailable("native resolver splits one adapter across source digests")
    selected_plugin_adapters = set(by_adapter) - {_NATIVE_MCP_ADAPTER_ID}
    if (set(by_adapter) & {_NATIVE_MCP_ADAPTER_ID} and _NATIVE_MCP_ADAPTER_ID in adapter_ids):
        raise NativePluginLoadUnavailable("native MCP dispatch is a protected core adapter, not a package module")
    if selected_plugin_adapters != adapter_ids:
        raise NativePluginLoadUnavailable("root resolver and pinned package adapter sets differ")
    for adapter in adapters:
        if adapter["adapter_id"] not in by_adapter or set(adapter["action_ids"]) != by_adapter[adapter["adapter_id"]]:
            raise NativePluginLoadUnavailable("native package adapters do not match the root selected resolver")
        if resolver_adapter_by_adapter[adapter["adapter_id"]] != adapter["artifact_sha256"]:
            raise NativePluginLoadUnavailable("native resolver adapter digest differs from the pinned module")
    return value


def _verify_closure(root: Path, manifest: dict[str, Any]) -> MappingProxyType:
    closure = root / "closure"
    try:
        if closure.is_symlink() or not closure.is_dir():
            raise NativePluginLoadUnavailable("root native closure directory is unavailable")
        closure_root = closure.resolve(strict=True)
        if closure_root.parent != root:
            raise NativePluginLoadUnavailable("root native closure escaped its mount")
        actual: dict[str, Path] = {}
        for current, dirnames, filenames in os.walk(closure_root, followlinks=False):
            current_path = Path(current)
            for name in list(dirnames):
                candidate = current_path / name
                info = candidate.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 2:
                    raise NativePluginLoadUnavailable("native closure contains a symlink or special directory")
            for name in filenames:
                candidate = current_path / name
                info = candidate.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise NativePluginLoadUnavailable("native closure contains a symlink, hard link, or special file")
                relative = candidate.relative_to(closure_root).as_posix()
                _relative_path(relative)
                actual[relative] = candidate
        expected_rows = manifest["closure_files"]
        expected = {row["relative_path"]: row for row in expected_rows}
        if actual.keys() != expected.keys():
            raise NativePluginLoadUnavailable("mounted closure file set differs from its pinned manifest")
        for relative, candidate in actual.items():
            row = expected[relative]
            info = candidate.stat(follow_symlinks=False)
            if info.st_size != row["size_bytes"] or stat.S_IMODE(info.st_mode) != row["mode"]:
                raise NativePluginLoadUnavailable("mounted closure file metadata differs from its pinned manifest")
            digest = hashlib.sha256(_read_regular_nofollow(candidate, maximum=row["size_bytes"])).hexdigest()
            if digest != row["sha256"]:
                raise NativePluginLoadUnavailable("mounted closure file digest differs from its pinned manifest")
        return MappingProxyType(actual)
    except NativePluginLoadUnavailable:
        raise
    except OSError:
        raise NativePluginLoadUnavailable("root native closure could not be inspected") from None


def _read_module_origin(source: Path, *, expected_sha256: str) -> tuple[int, int, int, str]:
    """Read an imported role member without following links and retain its inode identity."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError:
        raise NativePluginLoadUnavailable("selected process-role source is unavailable") from None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > _MAX_ENTRYPOINT_BYTES):
            raise NativePluginLoadUnavailable("selected process-role source is not a bounded regular file")
        digest = hashlib.sha256()
        read_size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            read_size += len(chunk)
            if read_size > before.st_size:
                raise NativePluginLoadUnavailable("selected process-role source changed during observation")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or read_size != before.st_size or digest.hexdigest() != expected_sha256):
            raise NativePluginLoadUnavailable("selected process-role source differs from its protected pin")
        return before.st_dev, before.st_ino, before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _load_selected_process_roles(
    root: Path, closure_modules: MappingProxyType, selection: object,
    imported_modules: list[str],
) -> tuple[_LoadedProcessRoleOrigin, ...]:
    """Import only root-selected role modules and capture their actual closure origins."""
    roles = getattr(selection, "process_roles", None)
    if (not isinstance(roles, tuple) or not 1 <= len(roles) <= _MAX_LOADER_PROCESS_ROLES):
        raise NativePluginLoadUnavailable("root selected no exact native process-role modules")
    closure_root = root / "closure"
    observed: list[_LoadedProcessRoleOrigin] = []
    seen_ids: set[str] = set()
    seen_modules: set[str] = set()
    seen_members: set[str] = set()
    for role in roles:
        role_id = _process_role_field(role, "role_id")
        module_name = _process_role_field(role, "module_name")
        member_path = _process_role_field(role, "closure_member_path")
        expected_digest = _process_role_field(role, "role_sha256")
        try:
            member_path = _relative_path(member_path)
        except NativePluginLoadUnavailable:
            raise NativePluginLoadUnavailable("root selected an invalid native process-role module") from None
        if (not isinstance(role_id, str) or not _ID.fullmatch(role_id)
                or not isinstance(module_name, str) or not _MODULE.fullmatch(module_name)
                or not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest)
                or role_id in seen_ids or module_name in seen_modules or member_path in seen_members):
            raise NativePluginLoadUnavailable("root selected an ambiguous native process-role module")
        seen_ids.add(role_id)
        seen_modules.add(module_name)
        seen_members.add(member_path)
        source = closure_modules.get(member_path)
        if not isinstance(source, Path):
            raise NativePluginLoadUnavailable("selected process-role member is absent from the verified closure")
        source = closure_root / member_path
        resolved_source = source.resolve(strict=True)
        if (resolved_source != source or source.is_symlink()
                or module_name in sys.modules):
            raise NativePluginLoadUnavailable("selected process-role module was preloaded outside this binding")
        package_paths = [str(source.parent)] if source.name == "__init__.py" else None
        spec = importlib.util.spec_from_file_location(
            module_name, source, submodule_search_locations=package_paths,
        )
        if (spec is None or spec.loader is None or spec.origin is None
                or Path(spec.origin).resolve(strict=True) != resolved_source):
            raise NativePluginLoadUnavailable("selected process-role module cannot load from its pinned member")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        imported_modules.append(module_name)
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise NativePluginLoadUnavailable("selected process-role module import failed") from None
        module_file = getattr(module, "__file__", None)
        module_spec = getattr(module, "__spec__", None)
        spec_origin = getattr(module_spec, "origin", None)
        if (sys.modules.get(module_name) is not module or not isinstance(module_file, str)
                or Path(module_file).resolve(strict=True) != resolved_source
                or not isinstance(spec_origin, str)
                or Path(spec_origin).resolve(strict=True) != resolved_source):
            raise NativePluginLoadUnavailable("selected process-role module origin changed during import")
        actual_device, actual_inode, actual_size, actual_digest = _read_module_origin(
            source, expected_sha256=expected_digest,
        )
        observed.append(_LoadedProcessRoleOrigin(
            role_id, module_name, member_path, actual_digest, actual_device, actual_inode, actual_size,
        ))
    if tuple((row.role_id, row.module_name, row.closure_member_path) for row in observed) != tuple(
            sorted((row.role_id, row.module_name, row.closure_member_path) for row in observed)):
        raise NativePluginLoadUnavailable("selected process-role modules are not canonically ordered")
    return tuple(observed)


class SelectedNativeAdapter:
    """One verified selected module and its fixed entrypoint symbol."""

    __slots__ = ("adapter_id", "module", "entrypoint_symbol", "action_ids",
                 "resource_manifest_sha256", "_entrypoint")

    def __init__(self, adapter_id: str, module: ModuleType, entrypoint_symbol: str,
                 action_ids: tuple[str, ...], resource_manifest_sha256: str,
                 entrypoint: Any) -> None:
        self.adapter_id = adapter_id
        self.module = module
        self.entrypoint_symbol = entrypoint_symbol
        self.action_ids = action_ids
        self.resource_manifest_sha256 = resource_manifest_sha256
        self._entrypoint = entrypoint

    def register(self, hermes_plugin_context: object, runtime_context: object) -> None:
        """Invoke only the pinned two-argument installer adapter entrypoint."""
        if not callable(self._entrypoint):
            raise NativePluginLoadUnavailable("selected native adapter entrypoint is unavailable")
        try:
            signature = inspect.signature(self._entrypoint)
            signature.bind(hermes_plugin_context, runtime_context)
        except (TypeError, ValueError):
            raise NativePluginLoadUnavailable("native adapter entrypoint must accept PluginContext and trusted runtime context") from None
        self._entrypoint(hermes_plugin_context, runtime_context)


class SelectedNativePackage:
    """Verified read-only mount plus the exact currently selected adapter modules."""

    __slots__ = ("_selection", "mount_target", "entrypoint_sha256", "_adapters", "_progress_writer",
                 "candidate_rows", "_authority", "_registered_candidate_registrations", "_loader_ready",
                 "_loaded_process_role_origins")

    def __init__(self, selection: RootSelectedPluginEffects, mount_target: Path,
                 entrypoint_sha256: str, adapters: MappingProxyType,
                 progress_writer: _NativeLoaderProgressWriter | None = None,
                 candidate_rows: tuple[SelectedNativeCandidate, ...] = (), authority: object | None = None,
                 loaded_process_role_origins: tuple[_LoadedProcessRoleOrigin, ...] = ()) -> None:
        self._selection = selection
        self.mount_target = mount_target
        self.entrypoint_sha256 = entrypoint_sha256
        self._adapters = adapters
        self._progress_writer = progress_writer
        self.candidate_rows = candidate_rows
        self._authority = authority
        self._registered_candidate_registrations: set[tuple[str, str]] = set()
        self._loaded_process_role_origins = loaded_process_role_origins
        self._loader_ready = False

    @property
    def package_id(self) -> str:
        return self._selection.package_id

    @property
    def profile_id(self) -> str:
        return self._selection.profile_id

    @property
    def generation(self) -> str:
        return self._selection.generation

    @property
    def compiled_closure_sha256(self) -> str:
        return self._selection.compiled_closure_sha256

    def resolve_adapter(self, adapter_id: str) -> SelectedNativeAdapter | None:
        self._selection._require_live()
        return self._adapters.get(adapter_id) if isinstance(adapter_id, str) else None

    def resolve(self, adapter_id: str, action_id: str) -> SelectedPluginEffect | None:
        """Presentation-only row for the selected adapter/action."""
        return self._selection.resolve(adapter_id, action_id)

    def manifest_digest_for_adapter(self, adapter_id: str) -> str | None:
        """Return the selected source resource-manifest digest for one adapter."""
        self._selection._require_live()
        rows = [row for row in self._selection.adapter_rows if row.adapter_id == adapter_id]
        if not rows:
            return None
        digests = {row.manifest_sha256 for row in rows}
        if len(digests) != 1:
            raise NativePluginLoadUnavailable("selected adapter has inconsistent source manifest digests")
        return next(iter(digests))

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        self._selection._require_live()
        return tuple(self._adapters)

    @property
    def registered_registration_ids(self) -> tuple[str, ...]:
        self._selection._require_live()
        return tuple(sorted(registration_id for _adapter_id, registration_id
                            in self._registered_candidate_registrations))

    def _mark_candidate_registered(self, adapter_id: str, registration_id: str) -> None:
        self._selection._require_live()
        if not isinstance(registration_id, str) or not _ID.fullmatch(registration_id):
            raise NativePluginLoadUnavailable("selected tool registration identity is malformed")
        self._registered_candidate_registrations.add((adapter_id, registration_id))

    def candidate(self, name: str) -> SelectedNativeCandidate | None:
        self._selection._require_live()
        return next((row for row in self.candidate_rows if row.native_tool_name == name), None)


def predeclare_selected_native_package(plugin_manager: object, package: SelectedNativePackage,
                                       runtime_context_factory: Any) -> tuple[str, ...]:
    """Install only selected package wrappers into Hermes' predeclared-module map.

    This targets the pinned Hermes 7085 ``PluginManager._predeclared_modules``
    seam. The official manager still owns discovery, ``PluginContext`` creation,
    registration ledgers, deadlines, and unload. Runtime context is created at
    each registration from the trusted installer bootstrap, never manifest data.
    """
    predeclared = getattr(plugin_manager, "_predeclared_modules", None)
    if not isinstance(predeclared, dict) or not callable(runtime_context_factory):
        raise NativePluginLoadUnavailable("pinned Hermes plugin loader or trusted runtime factory is unavailable")
    prepared: dict[str, ModuleType] = {}
    for adapter_id in package.adapter_ids:
        if adapter_id in predeclared:
            raise NativePluginLoadUnavailable("selected native plugin key is already predeclared")
        adapter = package.resolve_adapter(adapter_id)
        if adapter is None:
            raise NativePluginLoadUnavailable("selected native adapter expired during loader preparation")
        module = ModuleType(f"hermes_installer_selected_{adapter_id.replace('-', '_')}")

        def register(ctx: object, *, _adapter=adapter, _adapter_id=adapter_id) -> None:
            runtime_context = runtime_context_factory(_adapter_id)
            try:
                from hermes_installer.registry.resources_runtime import NativePluginRuntimeContext
                valid_context = isinstance(runtime_context, NativePluginRuntimeContext)
            except Exception:
                valid_context = False
            identity = getattr(runtime_context, "identity", None)
            if (not valid_context or getattr(identity, "kind", None) != "plugins"
                    or getattr(identity, "resource_id", None) != _adapter_id
            or getattr(identity, "content_digest", None) != _adapter.resource_manifest_sha256
                    or not callable(getattr(runtime_context, "invocation_contexts", None))
                    or not callable(getattr(getattr(runtime_context, "plugin_effects", None), "invoke", None))):
                raise NativePluginLoadUnavailable("trusted selected native plugin context is unavailable")
            # Hermes' real PluginContext is extensible in the pinned runtime.
            # The only exposed convenience is the same typed fixed-effect
            # facade held by NativePluginRuntimeContext.
            try:
                setattr(ctx, "plugin_effects", runtime_context.plugin_effects)
            except Exception:
                raise NativePluginLoadUnavailable("pinned Hermes PluginContext cannot accept the trusted facade") from None
            result_context = _NativePluginContextResultAdapter(ctx, package, _adapter_id)
            _adapter.register(result_context, runtime_context)
            progress_writer = getattr(package, "_progress_writer", None)
            expected_adapter_tools = {
                row.native_tool_name for row in package.candidate_rows
                if row.adapter_id == _adapter_id and not row.is_native_mcp
            }
            if set(result_context.registered_tool_names) != expected_adapter_tools:
                raise NativePluginLoadUnavailable("selected adapter registered no Hermes tools")
            registered = getattr(plugin_manager, "_hermes_installer_native_registered_adapters", None)
            if not isinstance(registered, set):
                registered = set()
                setattr(plugin_manager, "_hermes_installer_native_registered_adapters", registered)
            registered.add(_adapter_id)

        module.register = register
        prepared[adapter_id] = module
    # Publish atomically after every adapter and key has been validated.
    if any(key in predeclared for key in prepared):
        raise NativePluginLoadUnavailable("selected native plugin key collided during loader preparation")
    predeclared.update(prepared)
    setattr(plugin_manager, "_hermes_installer_native_plugin_keys", frozenset(prepared))
    setattr(plugin_manager, "_hermes_installer_native_plugin_package", package)
    return tuple(prepared)


def filter_unselected_native_mcp_candidates(server_name: str, candidates: list[Any]) -> list[Any]:
    """Protect root-selected names from later ambient config/cache discovery.

    The patched pinned `_register_candidates` calls this before registration.
    Once a name belongs to the sealed native index, only the exact handler
    object created by this module for the exact protected server can pass.
    """
    if not isinstance(server_name, str) or not isinstance(candidates, list):
        return []
    kept: list[Any] = []
    with _NATIVE_MCP_HANDLER_LOCK:
        for candidate in candidates:
            name = getattr(candidate, "registry_name", None)
            selected = _NATIVE_MCP_SELECTED_HANDLERS.get((server_name, name))
            # The installer-owned Hermes runtime has no direct MCP config/cache
            # authority. Only the exact candidate closure that this process
            # installed through the protected index may enter ToolRegistry.
            if selected is None or getattr(candidate, "handler", None) is not selected:
                continue
            kept.append(candidate)
    return kept


def install_native_candidate_index(package: SelectedNativePackage, authority: object) -> tuple[str, ...]:
    """Install sealed native candidates through Hermes' actual ToolRegistry seam."""
    if not isinstance(package, SelectedNativePackage) or package._authority is not authority:
        raise NativePluginLoadUnavailable("root-selected native package authority is unavailable")
    package._selection._require_live()
    mcp_rows = tuple(row for row in package.candidate_rows if row.is_native_mcp)
    if not mcp_rows:
        return ()
    dispatch = getattr(authority, "dispatch_native_mcp", None)
    if not callable(dispatch):
        raise NativePluginLoadUnavailable("root native MCP dispatch is unavailable")
    try:
        from types import SimpleNamespace
        from tools import mcp_tool_registration as registration_module
        from tools.mcp_tool_common import _core
        from tools.registry import registry
    except Exception:
        raise NativePluginLoadUnavailable("pinned Hermes MCP ToolRegistry is unavailable") from None
    candidate_factory = getattr(registration_module, "_Candidate", None)
    register_candidates = getattr(registration_module, "_register_candidates", None)
    if not callable(candidate_factory) or not callable(register_candidates):
        raise NativePluginLoadUnavailable("pinned Hermes MCP registration seam is unavailable")
    groups: dict[str, list[Any]] = {}
    selected_handlers: dict[tuple[str, str], Any] = {}
    for row in mcp_rows:
        schema = {
            "name": row.native_tool_name,
            "description": row.description,
            "parameters": _thaw_frozen_json(row.argument_schema),
        }
        registration = SimpleNamespace(
            id=row.action_id,
            native_tool_name=row.native_tool_name,
            native_schema_sha256=row.native_schema_sha256,
            native_schema=schema,
            native_package_id=package.package_id,
            native_package_generation=package.generation,
            profile_id=package.profile_id,
            native_server_name=row.native_server_name,
        )

        def handler(arguments: Mapping[str, Any], *, _registration=registration) -> str:
            from hermes_installer.native_invocations import dispatch_native_mcp_tool_call
            return dispatch_native_mcp_tool_call(authority, _registration, arguments)

        candidate = candidate_factory(
            row.native_tool_name, "root-selected compiled MCP candidate", schema, handler,
        )
        groups.setdefault(row.native_server_name, []).append(candidate)
        selected_handlers[(row.native_server_name, row.native_tool_name)] = handler

    installed_names: list[str] = []
    with _NATIVE_MCP_HANDLER_LOCK:
        for key in selected_handlers:
            previous = _NATIVE_MCP_SELECTED_HANDLERS.get(key)
            if previous is not None and previous is not selected_handlers[key]:
                raise NativePluginLoadUnavailable("native MCP selected candidate changed within this process")
        scope = _core._mcp_registry_scope()
        # The pinned registrar allows same-toolset replacement. Prevent that
        # behavior from replacing any existing owner, even with the same label.
        with registry._lock:
            for (server_name, name) in selected_handlers:
                existing = registry.get_entry(name, scope=scope)
                if existing is not None:
                    raise NativePluginLoadUnavailable("native MCP candidate collides with an existing tool")
            _NATIVE_MCP_SELECTED_HANDLERS.update(selected_handlers)
            try:
                for server_name, candidates in groups.items():
                    landed = register_candidates(
                        server_name, candidates,
                        check_fn=lambda _authority=authority: callable(
                            getattr(_authority, "dispatch_native_mcp", None)),
                        scope=lambda _scope=scope: _scope,
                        lazy=False,
                    )
                    if set(landed) != {candidate.registry_name for candidate in candidates}:
                        raise NativePluginLoadUnavailable("Hermes rejected a selected native MCP candidate")
                    installed_names.extend(landed)
                for row in mcp_rows:
                    entry = registry.get_entry(row.native_tool_name, scope=scope)
                    expected_toolset = f"mcp-{row.native_server_name}"
                    handler = selected_handlers[(row.native_server_name, row.native_tool_name)]
                    if (entry is None or entry.toolset != expected_toolset or entry.handler is not handler):
                        raise NativePluginLoadUnavailable("Hermes changed a selected native MCP registration")
                    package._mark_candidate_registered(row.adapter_id, row.registration_id)
            except Exception:
                for (server_name, name), handler in selected_handlers.items():
                    entry = registry.get_entry(name, scope=scope)
                    if (entry is not None and entry.handler is handler
                            and entry.toolset == f"mcp-{server_name}"):
                        with contextlib.suppress(Exception):
                            registry.deregister(name, scope=scope)
                # Keep the name guard after a failed protected install: normal
                # config/cache discovery must not become a fallback authority.
                raise
    return tuple(installed_names)


def prepare_native_mcp_candidate_discovery() -> tuple[str, ...]:
    """Install protected candidates and return names; never read worker MCP config/cache."""
    if getattr(_NATIVE_MCP_PRE_DISCOVERY, "active", False):
        return ()
    _NATIVE_MCP_PRE_DISCOVERY.active = True
    try:
        try:
            from hermes_cli.plugins import discover_plugins, get_plugin_manager
            manager = get_plugin_manager()
            package = getattr(manager, "_hermes_installer_native_plugin_package", None)
            if not isinstance(package, SelectedNativePackage):
                discover_plugins()
                manager = get_plugin_manager()
                package = getattr(manager, "_hermes_installer_native_plugin_package", None)
            if not isinstance(package, SelectedNativePackage):
                return ()
            if not package.candidate_rows:
                raise NativePluginLoadUnavailable("sealed native candidate index is unavailable")
            authority = package._authority
            if authority is None:
                raise NativePluginLoadUnavailable("root native MCP authority is unavailable")
            if any(row.is_native_mcp and (row.native_server_name, row.native_tool_name)
                   not in _NATIVE_MCP_SELECTED_HANDLERS for row in package.candidate_rows):
                install_native_candidate_index(package, authority)
            return tuple(row.native_tool_name for row in package.candidate_rows if row.is_native_mcp)
        except NativePluginLoadUnavailable:
            return ()
        except Exception:
            # Optional native candidates stay absent. The patched discovery
            # hook returns this empty result directly, so Hermes cannot fall
            # back to worker-owned mcp_servers, schema cache, or endpoint data.
            return ()
    finally:
        _NATIVE_MCP_PRE_DISCOVERY.active = False


def finish_selected_native_plugin_discovery(plugin_manager: object) -> bool:
    """Record READY only after the official PluginManager completes registration."""
    package = getattr(plugin_manager, "_hermes_installer_native_plugin_package", None)
    if not isinstance(package, SelectedNativePackage):
        return False
    writer = package._progress_writer
    if writer is None:
        return False
    try:
        registered = getattr(plugin_manager, "_hermes_installer_native_registered_adapters", None)
        if not isinstance(registered, set) or registered != set(package.adapter_ids):
            raise NativePluginLoadUnavailable("selected adapter registration sweep was incomplete")
        if package._authority is None or not package.candidate_rows:
            raise NativePluginLoadUnavailable("root-selected native candidate index is unavailable")
        install_native_candidate_index(package, package._authority)
        expected_registrations = {(row.adapter_id, row.registration_id)
                                  for row in package.candidate_rows}
        if package._registered_candidate_registrations != expected_registrations:
            raise NativePluginLoadUnavailable("selected candidate registration sweep was incomplete")
        plugins = getattr(plugin_manager, "_plugins", None)
        if not isinstance(plugins, dict):
            raise NativePluginLoadUnavailable("pinned Hermes plugin state is unavailable")
        for adapter_id in package.adapter_ids:
            plugin = plugins.get(adapter_id)
            if (plugin is None or getattr(plugin, "enabled", False) is not True
                    or getattr(plugin, "error", None) is not None
                    or getattr(plugin, "deferred", False) is True
                    or not getattr(plugin, "tools_registered", ())):
                raise NativePluginLoadUnavailable("selected Hermes plugin did not finish registration")
        writer.emit(sequence=1, phase="actions-registered",
                    registered_registration_ids=package.registered_registration_ids,
                    loaded_process_roles=package._loaded_process_role_origins)
        writer.emit(sequence=2, phase="ready",
                    registered_registration_ids=package.registered_registration_ids,
                    loaded_process_roles=package._loaded_process_role_origins)
        package._loader_ready = True
        return True
    except NativePluginLoadUnavailable:
        writer.close()
        raise


def ensure_selected_native_plugins_ready() -> SelectedNativePackage:
    """Force the official pinned discovery sweep and require its completed loader state."""
    try:
        from hermes_cli.plugins import discover_plugins, get_plugin_manager
        discover_plugins()
        manager = get_plugin_manager()
        package = getattr(manager, "_hermes_installer_native_plugin_package", None)
        if (not isinstance(package, SelectedNativePackage) or package._loader_ready is not True
                or not package.candidate_rows):
            raise NativePluginLoadUnavailable("selected native package discovery is not ready")
        package._selection._require_live()
        return package
    except NativePluginLoadUnavailable:
        raise
    except Exception:
        raise NativePluginLoadUnavailable("selected native package discovery is unavailable") from None


def _selected_runtime_context_factory(authority: object, package: SelectedNativePackage):
    """Build one typed component context from current root-selected bindings.

    Imports are delayed until Hermes actually loads a selected adapter. This
    keeps ordinary plugin discovery independent of the optional component
    cohort, while a selected plugin cannot fall back to source files or a
    caller-supplied context when any trusted part is absent.
    """
    def create(adapter_id: str):
        try:
            from hermes_installer.components.plugin_effects import bind_plugin_effects_to_runtime_context
            from hermes_installer.registry.resources_runtime import (
                NativePluginRuntimeContext, ResourceIdentity, ReviewedPluginAdapterRegistry,
            )
        except Exception:
            raise NativePluginLoadUnavailable("trusted native component context is unavailable") from None
        if any(not callable(getattr(authority, method, None)) for method in (
                "begin_native_invocation", "get_invocation_contexts", "context")):
            raise NativePluginLoadUnavailable("root native invocation context APIs are unavailable")
        digest = package.manifest_digest_for_adapter(adapter_id)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise NativePluginLoadUnavailable("root selected no source manifest for this adapter")
        identity = ResourceIdentity(
            resource_id=adapter_id, kind="plugins", version=package.generation,
            source_path="root-selected-native-package", source_revision=package.compiled_closure_sha256,
            content_digest=digest,
        )
        try:
            capabilities = tuple(sorted({
                effect.capability for action in _selected_actions(package, adapter_id)
                if (effect := package.resolve(adapter_id, action)) is not None
            }))
            runtime_context = NativePluginRuntimeContext(
                identity=identity, declared_capabilities=capabilities, authority=authority,
                invocation_contexts=None,
                selected_adapters=ReviewedPluginAdapterRegistry(), plugin_effects=None,
            )
            return bind_plugin_effects_to_runtime_context(
                authority=authority, selected_package=package,
                current_binding=_current_native_invocation_binding,
                runtime_context=runtime_context,
            )
        except Exception:
            raise NativePluginLoadUnavailable("root invocation or selected effect context is unavailable") from None
    return create


def _selected_actions(package: SelectedNativePackage, adapter_id: str) -> tuple[str, ...]:
    adapter = package.resolve_adapter(adapter_id)
    return tuple(adapter.action_ids) if adapter is not None else ()


def _current_native_invocation_binding() -> Any | None:
    try:
        from hermes_installer.native_invocations import current_native_invocation_binding
        return current_native_invocation_binding()
    except Exception:
        return None


def install_selected_native_plugins(plugin_manager: object, manifests: list[Any]) -> list[Any]:
    """Bind the root-selected closure into the real pinned PluginManager sweep.

    Only adapter IDs in the no-argument root-selected resolver become synthetic
    bundled manifests. Any disk/entrypoint plugin claiming one of those keys is
    removed from this sweep, and the loader consumes its predeclared verified
    module. This function is called by the reviewed exact-source overlay before
    Hermes resolves winners and runs its normal registration lifecycle.
    """
    if not isinstance(manifests, list):
        raise NativePluginLoadUnavailable("pinned Hermes discovery manifest list is unavailable")
    try:
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process()
        package = bind_current_native_plugin_package(authority)
    except Exception:
        # Native binding is optional for the rest of Hermes discovery, but no
        # unselected plugin module is allowed in the installer-managed runtime.
        return []
    return _install_root_selected_package(
        plugin_manager, manifests, package,
        _selected_runtime_context_factory(authority, package),
    )


def _install_root_selected_package(plugin_manager: object, manifests: list[Any],
                                   package: SelectedNativePackage,
                                   runtime_context_factory: Any) -> list[Any]:
    """Install a verified selected package into the real Hermes discovery pass."""
    try:
        predeclared_ids = predeclare_selected_native_package(
            plugin_manager, package, runtime_context_factory,
        )
        if set(predeclared_ids) != set(package.adapter_ids):
            raise NativePluginLoadUnavailable("selected native adapter set changed during discovery")
        from hermes_cli.plugins_manifest import PluginManifest
        # The selected root closure is the entire plugin authority for this
        # managed process. User, project, and entrypoint plugins cannot add
        # handlers outside that selection, even under a distinct plugin key.
        synthetic = [
            PluginManifest(
                name=adapter_id, key=adapter_id, source="bundled", kind="backend",
                path=str(package.mount_target / "closure"),
            )
            for adapter_id in predeclared_ids
        ]
        return synthetic
    except NativePluginLoadUnavailable:
        # A partial registration map would let normal file discovery win over
        # a selected package. Remove every module installed by this call and
        # leave the untrusted manifest list without selected adapter keys.
        predeclared = getattr(plugin_manager, "_predeclared_modules", None)
        if isinstance(predeclared, dict):
            for adapter_id in package.adapter_ids:
                module = predeclared.get(adapter_id)
                if isinstance(module, ModuleType) and module.__name__.startswith("hermes_installer_selected_"):
                    predeclared.pop(adapter_id, None)
        with contextlib.suppress(Exception):
            delattr(plugin_manager, "_hermes_installer_native_plugin_keys")
        return []


def bind_current_native_plugin_package(authority: object) -> SelectedNativePackage:
    """Bind, verify and import only the root-selected closure for this process.

    This does not create an invocation context or grant. The caller must obtain
    the runtime context from the enrolled root context adapter before calling a
    selected adapter's ``register`` method.
    """
    selection = bind_selected_plugin_effects(authority)
    target = selected_mount_target(selection.package_id, selection.profile_id,
                                   selection.generation, selection.compiled_closure_sha256)
    progress_writer: _NativeLoaderProgressWriter | None = None
    imported_modules: list[str] = []
    try:
        _require_private_readonly_mount(target, Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
        root = target.resolve(strict=True)
        if root != target or root.is_symlink() or not root.is_dir():
            raise NativePluginLoadUnavailable("root-selected native mount target is not a fixed directory")
        raw_manifest = _read_regular_nofollow(root / "manifest.json", maximum=_MAX_ENTRYPOINT_BYTES)
        manifest = _manifest(raw_manifest, selected=selection)
        resolver_bytes = _read_regular_nofollow(root / "resolver" / "resolver", maximum=2 * 1024 * 1024)
        if hashlib.sha256(resolver_bytes).hexdigest() != selection.resolver_digest:
            raise NativePluginLoadUnavailable("mounted native resolver digest differs from root binding")
        mounted_resolver = _json_document(resolver_bytes, maximum=2 * 1024 * 1024,
                                          label="mounted native resolver")
        if _canonical(mounted_resolver) != resolver_bytes:
            raise NativePluginLoadUnavailable("mounted native resolver is not canonical JSON")
        _require_protected_import_environment()
        modules = _verify_closure(root, manifest)
        candidate_rows = _read_native_candidate_index_from_verified_mount(root, manifest, selection)
        # The named activation descriptor is provisioned by root custody via
        # systemd OpenFile. Resolve it before importing selected code so the
        # package remains unavailable if loaded-code proof cannot be reported.
        progress_writer = _NativeLoaderProgressWriter.from_systemd_activation(selection)
        process_role_origins = _load_selected_process_roles(
            root, modules, selection, imported_modules,
        )
        loaded: dict[str, SelectedNativeAdapter] = {}
        for row in manifest["adapters"]:
            adapter_id = row["adapter_id"]
            module_name = row["module_name"]
            source = modules[row["relative_module_path"]]
            if module_name in sys.modules:
                previous = sys.modules[module_name]
                previous_file = getattr(previous, "__file__", None)
                if not isinstance(previous_file, str) or Path(previous_file).resolve(strict=True) != source.resolve(strict=True):
                    raise NativePluginLoadUnavailable("native adapter module name is already owned by another source")
                module = previous
            else:
                package_paths = [str(source.parent)] if source.name == "__init__.py" else None
                spec = importlib.util.spec_from_file_location(module_name, source,
                                                              submodule_search_locations=package_paths)
                if spec is None or spec.loader is None:
                    raise NativePluginLoadUnavailable("native adapter module cannot be loaded from its pinned path")
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                imported_modules.append(module_name)
                try:
                    spec.loader.exec_module(module)
                except Exception:
                    sys.modules.pop(module_name, None)
                    raise NativePluginLoadUnavailable("pinned native adapter import failed") from None
            entrypoint = getattr(module, row["entrypoint_symbol"], None)
            if not callable(entrypoint):
                raise NativePluginLoadUnavailable("pinned native adapter entrypoint is not callable")
            loaded[adapter_id] = SelectedNativeAdapter(
                adapter_id, module, row["entrypoint_symbol"], tuple(row["action_ids"]),
                selection.manifest_digest_for_adapter(adapter_id) or "", entrypoint,
            )
        progress_writer.emit(
            sequence=0, phase="entrypoint-imported", registered_registration_ids=(),
            loaded_process_roles=process_role_origins,
        )
        return SelectedNativePackage(selection, target, selection.entrypoint_sha256,
                                     MappingProxyType(loaded), progress_writer,
                                     candidate_rows=candidate_rows, authority=authority,
                                     loaded_process_role_origins=process_role_origins)
    except NativePluginBindingUnavailable as exc:
        if progress_writer is not None:
            progress_writer.close()
        for module_name in imported_modules:
            sys.modules.pop(module_name, None)
        raise NativePluginLoadUnavailable("root native package binding is unavailable") from None
    except NativePluginLoadUnavailable:
        if progress_writer is not None:
            progress_writer.close()
        for module_name in imported_modules:
            sys.modules.pop(module_name, None)
        raise
    except OSError:
        if progress_writer is not None:
            progress_writer.close()
        for module_name in imported_modules:
            sys.modules.pop(module_name, None)
        raise NativePluginLoadUnavailable("root native package mount is unavailable") from None
    except BaseException:
        if progress_writer is not None:
            progress_writer.close()
        for module_name in imported_modules:
            sys.modules.pop(module_name, None)
        raise
