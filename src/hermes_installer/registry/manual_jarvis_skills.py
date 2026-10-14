"""Separate, ownership-journaled offline import of bundled Hermes Resources.

This importer makes all 396 bundled native skill cards visible to Hermes and
retains all 208 effective profile identities under a private registry namespace.
Only the primary Jarvis home stays user-selectable. It does not activate plugins,
copy credentials, or claim delegated profile/tool effects.
"""
from __future__ import annotations

import hashlib
import argparse
import contextvars
import fcntl
import io
import json
import os
import pwd
import re
import shutil
import stat
import struct
import sys
import tempfile
import threading
import types
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from importlib.resources import files as package_files


PINNED_REVISION = "113f42d33be9e0c8f0f47f5ca998e687323dec83"
PINNED_TREE = "c0c994b5e0b96b90cfd2fc564ea8632dff124308"
PINNED_VERSION = "2.3.1"
PRIMARY_PROFILE = "hermes"
PRIMARY_SKILLS = (
    "conversation-gateway",
    "hermes-response-contract",
    "speech-input-routing",
    "spoken-response-delivery",
)
PLUGIN_PENDING = {
    "resource_id": "voice-pipeline",
    "state": "not-imported",
    "reason": (
        "The vendored Resources bundle contains only a voice-pipeline declaration, not an "
        "executable Hermes plugin adapter. No separately authorized local Wyoming/Piper "
        "endpoints are enrolled, so voice effects remain unavailable."
    ),
}
_ARTIFACT_LIMIT = 16 * 1024 * 1024
_MEMBER_LIMIT = 256 * 1024
_PACKAGE_MEMBER_LIMIT = 2 * 1024 * 1024
_BUNDLE_SKILL_COUNT = 396
_BUNDLE_PROFILE_COUNT = 208
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = f"installer-resources-{PINNED_REVISION[:12]}"
_OWNER_FILE = ".hermes-installer-resource-ownership.json"
PINNED_HERMES_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
LEGACY_MATERIALIZED_ARTIFACT_SHA256 = "f73463c641ac3744007ee8395b663802d5c916f59256fa8184ad2b4f5594b274"
_HELPER_ARCHIVE_PATH = "manual_stage_jarvis_skills.py"
_ROOT_RUNUSER = Path("/usr/sbin/runuser")
_IMPORTER_MODULE = "hermes_installer.registry.manual_jarvis_skills"
_JARVIS_HOME = Path("/home/admin/.hermes")
_HELPER_BACKUP_NAME = re.compile(r"^\.jarvis-resources-skills-helper-transition-[0-9a-f]{32}$")

# R0201/#35: only the fixed Root adapter-update operation may reuse the exact
# immutable base ZIP.  Core supplies its held-lock/seal predicate and a fresh
# input witness; this module never persists the entry or caches parsed output.
_ROOT_UPDATE_ARTIFACT_CACHE_SEAL = object()
_ROOT_UPDATE_ARTIFACT_CACHE = contextvars.ContextVar(
    "manual_jarvis_root_update_artifact_cache", default=None)

_BASE_ARTIFACT_INPUTS = (
    "hermes_installer/__init__.py",
    "hermes_installer/state.py",
    "hermes_installer/network.py",
    "hermes_installer/components/__init__.py",
    "hermes_installer/components/catalog.py",
    "hermes_installer/components/skill_refs.py",
    "hermes_installer/components/native_plugins.py",
    "hermes_installer/components/public_registries.py",
    "hermes_installer/registry/__init__.py",
    "hermes_installer/registry/types.py",
    "hermes_installer/registry/resolver.py",
    "hermes_installer/registry/source.py",
    "hermes_installer/registry/native.py",
    "hermes_installer/registry/resources_runtime.py",
    "hermes_installer/registry/manual_jarvis_skills.py",
    "hermes_installer/registry/jarvis_master_semantics.py",
    "hermes_installer/registry/bundle_data/hermes-agent-resources.pin.json",
    "hermes_installer/registry/bundle_data/hermes-agent-resources-2.3.1.tar.gz",
    "hermes_installer/registry/bundle_data/jarvis-master-semantics.json",
)
_BASE_ARTIFACT_SOURCE_LIMIT = 8 * 1024 * 1024
_BASE_ARTIFACT_CODE_LIMIT = 2 * 1024 * 1024
_BASE_ARTIFACT_CLOSURE_LIMIT = 32 * 1024 * 1024
_BASE_ARTIFACT_RUNTIME_ENTRYPOINTS = {
    "/opt/hermes-jarvis-mvp-20261011/gateway-venv/bin/python": (
        "/usr/bin/python3.13", (3, 13, 5), 0, 0, 0o755, 6_673_736,
        "bd241b38381974ae27d7d5098a6d0e6dda0a744b5e9fdd6fe3a1ae632588961e",
        "/opt/hermes-jarvis-mvp-20261011/gateway-venv", "/usr"),
    "/var/tmp/hermes-jarvis-core-checks-20261011/gateway-test-venv/bin/python": (
        "/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14",
        (3, 14, 7), 1000, 1000, 0o755, 108_914_888,
        "566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001",
        "/var/tmp/hermes-jarvis-core-checks-20261011/gateway-test-venv",
        "/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64"),
}
_BASE_ARTIFACT_YAML_ORIGINS = {
    "/opt/hermes-jarvis-mvp-20261011/gateway-venv/bin/python": (
        "/opt/hermes-jarvis-mvp-20261011/gateway-venv/lib/python3.13/site-packages/yaml/__init__.py",
        0, 0, 0o644, "b19dfcc333d6a75dfd73073901164507252f271b41d3b5f7d85510033a0547a7"),
    "/var/tmp/hermes-jarvis-core-checks-20261011/gateway-test-venv/bin/python": (
        "/var/tmp/hermes-jarvis-core-checks-20261011/gateway-test-venv/lib/python3.14/site-packages/yaml/__init__.py",
        1000, 1000, 0o644, "b19dfcc333d6a75dfd73073901164507252f271b41d3b5f7d85510033a0547a7"),
}
_PLUGIN_CONTRACT_FIELDS = (
    "adapter_id", "resource_id", "component_adapter_id", "handler_available", "status", "blocker",
)
_BASE_ARTIFACT_RUNTIME_BINDINGS = {
    "hermes_installer.registry.manual_jarvis_skills": (
        "PINNED_REVISION", "PINNED_TREE", "PRIMARY_PROFILE", "PRIMARY_SKILLS", "PLUGIN_PENDING",
        "_BUNDLE_SKILL_COUNT", "_BUNDLE_PROFILE_COUNT", "_ARTIFACT_LIMIT", "_MEMBER_LIMIT",
        "package_files", "_ROOT_UPDATE_ARTIFACT_CACHE_SEAL", "_ROOT_UPDATE_ARTIFACT_CACHE",
        "_BASE_ARTIFACT_INPUTS", "_BASE_ARTIFACT_SOURCE_LIMIT", "_BASE_ARTIFACT_CODE_LIMIT",
        "_BASE_ARTIFACT_CLOSURE_LIMIT", "_BASE_ARTIFACT_RUNTIME_ENTRYPOINTS",
        "_BASE_ARTIFACT_YAML_ORIGINS", "_PLUGIN_CONTRACT_FIELDS", "_BASE_ARTIFACT_RUNTIME_BINDINGS",
        "_BASE_ARTIFACT_RUNTIME_FUNCTIONS", "_BASE_ARTIFACT_RUNTIME_METHODS",
        "_BASE_ARTIFACT_RUNTIME_CLASSES", "_BASE_ARTIFACT_RUNTIME_CLASS_BINDINGS",
        "_BASE_ARTIFACT_MODULES", "_BASE_ARTIFACT_YAML_TABLES",
        "contextmanager", "_canonical_json", "_sha256", "_zip_write",
    ),
    "hermes_installer.registry.native": (
        "_DISCOVERY_ROOTS", "_PROFILE_NAME", "_SKILL_NAME", "PRIMARY_USER_SOURCE_PROFILE_ID",
        "PRIMARY_USER_DISPLAY_NAME", "_PRIMARY_USER_IDENTITY_INSTRUCTIONS",
        "_STANDALONE_HERMES", "PRIMARY_NATIVE_PROFILE_KEY", "RawResource", "RegistryError", "RegistryResolver",
        "ResolvedResource", "VerifiedSource", "_merge_policy_values",
    ),
    "hermes_installer.registry.resolver": (
        "_VERSION", "_CLAUSE", "_KINDS", "_SINGULAR", "Resource", "ResourceKind",
    ),
    "hermes_installer.registry.source": ("PinnedSource", "BundledRegistrySource"),
    "hermes_installer.registry.resources_runtime": (
        "_PLUGIN_NEXT_STEP", "_CRON_NEXT_STEP", "_WEBHOOK_NEXT_STEP", "_CHANNEL_NEXT_STEP",
        "_MCP_NEXT_STEPS",
    ),
    "hermes_installer.registry.jarvis_master_semantics": (
        "OVERLAY_PATH", "UPSTREAM_REPOSITORY", "UPSTREAM_VERSION", "UPSTREAM_REVISION",
        "UPSTREAM_TREE", "OVERLAY_ID", "APPROVAL_COMMIT", "OVERLAY_SHA256",
    ),
    "hermes_installer.components.native_plugins": (
        "_PLUGIN_IDS", "_PLUGIN_VERSIONS", "_PLUGIN_BLOCKERS", "NATIVE_PLUGIN_ADAPTERS",
        "_PLUGIN_BY_ID",
    ),
}
_BASE_ARTIFACT_RUNTIME_FUNCTIONS = {
    "hermes_installer.registry.manual_jarvis_skills": (
        "_build_manual_jarvis_skills_artifact_uncached", "build_manual_jarvis_skills_artifact",
        "_root_held_update_artifact_cache", "_root_artifact_source_witness",
        "_loaded_compiler_identity", "_literal_runtime_value", "_unique_pairs",
        "_runtime_file_witness", "_canonical_json", "_sha256", "_zip_write",
    ),
    "hermes_installer.registry.native": (
        "_yaml", "_load", "_declared_roots", "_jarvis_identity_text",
        "effective_native_profile_spec", "_profile_files", "_skill_file",
    ),
    "hermes_installer.registry.resolver": (
        "_merge_policy_values", "_parts", "_compare", "satisfies", "_policy_overlay_matches",
    ),
    "hermes_installer.registry.source": ("load_bundled_source", "_git_blob", "_git_tree"),
    "hermes_installer.registry.resources_runtime": (
        "_safe_identity", "materialize_runtime_resource", "_registration", "_validate_cron",
        "_validate_channel_declaration", "_validate_bundle_declaration", "_validate_webhook_declaration",
        "_valid_header_name", "_cron_instant_matches", "_cron_field_matches",
    ),
    "hermes_installer.registry.jarvis_master_semantics": (
        "_read_overlay", "overlay_identity", "_apply_profile", "effective_profile_spec",
        "effective_bundle_spec",
    ),
    "hermes_installer.components.native_plugins": (
        "resolve_native_plugin_adapter", "native_plugin_handler_available",
    ),
}
_BASE_ARTIFACT_RUNTIME_METHODS = {
    "hermes_installer.registry.native": {
        "NativeRegistry": ("from_verified_source", "discover", "discover_all", "_runtime_artifact", "crosswalk", "materialize"),
    },
    "hermes_installer.registry.resolver": {
        "RegistryResolver": ("__init__", "document_digest", "_parse", "_references", "_selector", "resolve"),
    },
    "hermes_installer.registry.source": {
        "PinnedSource": ("from_mapping",), "BundledRegistrySource": ("__init__", "load"),
    },
}
_BASE_ARTIFACT_RUNTIME_CLASSES = {
    "hermes_installer.registry.types": ("ResourceKind", "Resource"),
    "hermes_installer.registry.resolver": ("RawResource", "ResolvedResource"),
    "hermes_installer.registry.native": ("NativeDiscovery", "NativeResourceBinding"),
    "hermes_installer.registry.source": ("VerifiedSource",),
    "hermes_installer.registry.resources_runtime": (
        "ResourceIdentity", "ResourceReadiness", "ResourceRuntimeArtifact",
    ),
}
_BASE_ARTIFACT_RUNTIME_CLASS_BINDINGS = {
    "hermes_installer.registry.source": {
        "BundledRegistrySource": ("MAX_ARCHIVE_BYTES", "MAX_EXPANDED_BYTES", "ROOTS"),
    },
}
_BASE_ARTIFACT_MODULES = (
    ("hermes_installer", "hermes_installer/__init__.py"),
    ("hermes_installer.state", "hermes_installer/state.py"),
    ("hermes_installer.network", "hermes_installer/network.py"),
    ("hermes_installer.components", "hermes_installer/components/__init__.py"),
    ("hermes_installer.components.catalog", "hermes_installer/components/catalog.py"),
    ("hermes_installer.components.skill_refs", "hermes_installer/components/skill_refs.py"),
    ("hermes_installer.components.native_plugins", "hermes_installer/components/native_plugins.py"),
    ("hermes_installer.components.public_registries", "hermes_installer/components/public_registries.py"),
    ("hermes_installer.registry", "hermes_installer/registry/__init__.py"),
    ("hermes_installer.registry.types", "hermes_installer/registry/types.py"),
    ("hermes_installer.registry.resolver", "hermes_installer/registry/resolver.py"),
    ("hermes_installer.registry.source", "hermes_installer/registry/source.py"),
    ("hermes_installer.registry.native", "hermes_installer/registry/native.py"),
    ("hermes_installer.registry.resources_runtime", "hermes_installer/registry/resources_runtime.py"),
    ("hermes_installer.registry.manual_jarvis_skills", "hermes_installer/registry/manual_jarvis_skills.py"),
    ("hermes_installer.registry.jarvis_master_semantics", "hermes_installer/registry/jarvis_master_semantics.py"),
)

_BASE_ARTIFACT_YAML_TABLES = (
    ("SafeLoader", "yaml_constructors"), ("SafeLoader", "yaml_multi_constructors"),
    ("SafeLoader", "yaml_implicit_resolvers"), ("SafeLoader", "yaml_path_resolvers"),
    ("SafeDumper", "yaml_representers"), ("SafeDumper", "yaml_multi_representers"),
)


def _runtime_file_witness(path, *, expected_path, expected_uid, expected_gid,
                          expected_mode, expected_size, expected_sha256, size_limit):
    path = Path(path)
    if str(path) != expected_path:
        raise ManualJarvisSkillsError("pinned runtime file origin differs")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        named_before = path.stat(follow_symlinks=False)
        identity = (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid
                or before.st_gid != expected_gid or stat.S_IMODE(before.st_mode) != expected_mode
                or before.st_nlink != 1 or before.st_size < 0 or before.st_size > size_limit
                or (expected_size is not None and before.st_size != expected_size)
                or identity[:2] != (named_before.st_dev, named_before.st_ino)):
            raise ManualJarvisSkillsError("pinned runtime file custody differs")
        digest = hashlib.sha256()
        total = 0
        remaining = size_limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
            if total > size_limit:
                raise ManualJarvisSkillsError("pinned runtime file exceeds its byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        named_after = path.stat(follow_symlinks=False)
        if (digest.hexdigest() != expected_sha256
                or identity != (after.st_dev, after.st_ino, after.st_size,
                                after.st_mtime_ns, after.st_ctime_ns)
                or identity != (named_after.st_dev, named_after.st_ino, named_after.st_size,
                                named_after.st_mtime_ns, named_after.st_ctime_ns)):
            raise ManualJarvisSkillsError("pinned runtime file content changed")
        return (expected_path, expected_sha256, identity, before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode), before.st_nlink)
    finally:
        os.close(descriptor)


class _RootUpdateArtifactCache:
    __slots__ = ("seal", "operation", "thread_id", "is_current", "witness",
                 "artifact", "artifact_sha256", "source_witness", "poisoned")

    def __init__(self, operation, is_current, witness):
        self.seal = _ROOT_UPDATE_ARTIFACT_CACHE_SEAL
        self.operation = operation
        self.thread_id = threading.get_ident()
        self.is_current = is_current
        self.witness = witness
        self.artifact = None
        self.artifact_sha256 = None
        self.source_witness = None
        self.poisoned = False

    def invalidate(self):
        self.artifact = None
        self.artifact_sha256 = None
        self.source_witness = None
        self.poisoned = True

    def clear(self):
        self.invalidate()


@contextmanager
def _root_held_update_artifact_cache(operation, *, is_current, witness):
    """Install one private byte entry for Core's exact held Root update call."""
    if (type(operation) is not object or not callable(is_current) or not callable(witness)
            or _ROOT_UPDATE_ARTIFACT_CACHE.get() is not None):
        raise ManualJarvisSkillsError("Root update artifact cache scope is invalid")
    entry = _RootUpdateArtifactCache(operation, is_current, witness)
    if not entry.is_current():
        raise ManualJarvisSkillsError("Root update artifact cache requires the held sealed operation")
    token = _ROOT_UPDATE_ARTIFACT_CACHE.set(entry)
    try:
        yield
    finally:
        entry.clear()
        _ROOT_UPDATE_ARTIFACT_CACHE.reset(token)


def _literal_runtime_value(value, *, depth=0, budget=None):
    """Snapshot bounded built-in compiler globals without invoking user code."""
    if budget is None:
        budget = [100_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 24:
        raise ManualJarvisSkillsError("loaded Resources compiler state exceeds its bound")
    value_type = type(value)
    if value_type is float:
        return ("float", value.hex())
    if value is None or value_type in {bool, int, str, bytes}:
        return (value_type.__name__, value)
    if isinstance(value, types.FunctionType):
        return ("function", value, value.__code__, id(value.__code__), value.__module__,
                value.__qualname__, _literal_runtime_value(
                    value.__defaults__, depth=depth + 1, budget=budget),
                _literal_runtime_value(value.__kwdefaults__, depth=depth + 1, budget=budget))
    if value_type in {tuple, list}:
        return (value_type.__name__, tuple(
            _literal_runtime_value(item, depth=depth + 1, budget=budget) for item in value))
    if value_type is dict:
        rows = [(_literal_runtime_value(key, depth=depth + 1, budget=budget),
                 _literal_runtime_value(item, depth=depth + 1, budget=budget))
                for key, item in value.items()]
        return ("dict", tuple(sorted(rows, key=lambda row: repr(row[0]))))
    if value_type in {set, frozenset}:
        rows = [_literal_runtime_value(item, depth=depth + 1, budget=budget) for item in value]
        return (value_type.__name__, tuple(sorted(rows, key=repr)))
    return ("identity", type(value).__module__, type(value).__qualname__, id(value))


def _loaded_compiler_identity(source_root):
    """Bind the exact loaded source/compiler code and YAML delegates used here."""
    import importlib

    modules = []
    runtime_budget = [100_000]
    for module_name, relative in _BASE_ARTIFACT_MODULES:
        module = importlib.import_module(module_name)
        expected_path = source_root.joinpath(*relative.split("/")).resolve(strict=True)
        module_file = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        if (not isinstance(module_file, str)
                or Path(module_file).resolve(strict=True) != expected_path
                or getattr(spec, "origin", None) != str(expected_path)):
            raise ManualJarvisSkillsError("loaded Resources compiler source identity differs")
        modules.append((module_name, module, expected_path, spec))
        package_path = getattr(module, "__path__", None)
        if package_path is not None:
            modules.append(("package-path", module_name,
                            tuple(str(Path(item).resolve(strict=True)) for item in package_path)))
        selected_bindings = set(_BASE_ARTIFACT_RUNTIME_BINDINGS.get(module_name, ()))
        for name in sorted(selected_bindings):
            if name not in vars(module):
                raise ManualJarvisSkillsError("required Resources builder binding is missing")
            value = vars(module)[name]
            literal = _literal_runtime_value(value, budget=runtime_budget)
            modules.append(("binding", module_name, name, id(value), literal))

        def function_identity(name, function):
            if not isinstance(function, types.FunctionType) or function.__module__ != module_name:
                raise ManualJarvisSkillsError("required loaded Resources compiler function differs")
            wrapped = None
            if module_name == "hermes_installer.registry.manual_jarvis_skills" and name == "_root_held_update_artifact_cache":
                # contextmanager() exposes a contextlib wrapper. Pin that exact
                # standard wrapper and its source-defined wrapped function.
                wrapped = getattr(function, "__wrapped__", None)
                expected_wrapper = contextmanager(wrapped) if isinstance(wrapped, types.FunctionType) else None
                if (wrapped is None or not isinstance(wrapped, types.FunctionType)
                        or wrapped.__module__ != module_name
                        or wrapped.__name__ != name
                        or Path(wrapped.__code__.co_filename).resolve(strict=True) != expected_path
                        or expected_wrapper is None
                        or function.__code__ is not expected_wrapper.__code__):
                    raise ManualJarvisSkillsError("required loaded Resources compiler function differs")
            elif Path(function.__code__.co_filename).resolve(strict=True) != expected_path:
                raise ManualJarvisSkillsError("required loaded Resources compiler function differs")
            modules.append(("function", module_name, name, function, function.__code__,
                            id(function.__code__), _literal_runtime_value(
                                function.__defaults__, budget=runtime_budget),
                            _literal_runtime_value(function.__kwdefaults__, budget=runtime_budget),
                            tuple(_literal_runtime_value(cell.cell_contents, budget=runtime_budget)
                                  for cell in (function.__closure__ or ())),
                            wrapped, getattr(wrapped, "__code__", None),
                            (_literal_runtime_value(wrapped.__defaults__, budget=runtime_budget)
                             if wrapped is not None else None),
                            (_literal_runtime_value(wrapped.__kwdefaults__, budget=runtime_budget)
                             if wrapped is not None else None),
                            (tuple(_literal_runtime_value(cell.cell_contents, budget=runtime_budget)
                                   for cell in (wrapped.__closure__ or ()))
                             if wrapped is not None else None)))

        for name in _BASE_ARTIFACT_RUNTIME_FUNCTIONS.get(module_name, ()):
            function = vars(module).get(name)
            function_identity(name, function)
        for class_name, method_names in _BASE_ARTIFACT_RUNTIME_METHODS.get(module_name, {}).items():
            cls = vars(module).get(class_name)
            if not isinstance(cls, type):
                raise ManualJarvisSkillsError("required loaded Resources compiler class differs")
            modules.append(("class", module_name, class_name, cls))
            for method_name in method_names:
                descriptor = vars(cls).get(method_name)
                function = (descriptor.__func__ if isinstance(descriptor, (classmethod, staticmethod))
                            else descriptor)
                function_identity(f"{class_name}.{method_name}", function)
        for class_name in _BASE_ARTIFACT_RUNTIME_CLASSES.get(module_name, ()):
            cls = vars(module).get(class_name)
            if not isinstance(cls, type) or cls.__module__ != module_name:
                raise ManualJarvisSkillsError("required loaded Resources compiler record differs")
            fields = getattr(cls, "__dataclass_fields__", None)
            if type(fields) is dict:
                field_rows = tuple(
                    (name, _literal_runtime_value(field.type, budget=runtime_budget),
                     field.init, field.repr, field.compare, field.hash,
                     _literal_runtime_value(field.default, budget=runtime_budget),
                     _literal_runtime_value(field.default_factory, budget=runtime_budget))
                    for name, field in sorted(fields.items()))
            else:
                field_rows = ()
            init_function = vars(cls).get("__init__")
            if isinstance(init_function, types.FunctionType):
                init_code = init_function.__code__
                if (init_code.co_filename != "<string>"
                        and Path(init_code.co_filename).resolve(strict=True) != expected_path):
                    raise ManualJarvisSkillsError("loaded Resources compiler record origin differs")
                init_identity = (init_function, init_code, id(init_code),
                                 _literal_runtime_value(init_function.__defaults__, budget=runtime_budget),
                                 _literal_runtime_value(init_function.__kwdefaults__, budget=runtime_budget))
            else:
                init_identity = None
            members = getattr(cls, "__members__", None)
            enum_rows = (tuple((name, _literal_runtime_value(member.value, budget=runtime_budget))
                               for name, member in members.items())
                         if isinstance(members, Mapping) else ())
            modules.append(("record", module_name, class_name, cls,
                            _literal_runtime_value(getattr(cls, "__slots__", ()), budget=runtime_budget),
                            field_rows, init_identity, enum_rows))
        for class_name, attribute_names in _BASE_ARTIFACT_RUNTIME_CLASS_BINDINGS.get(
                module_name, {}).items():
            cls = vars(module).get(class_name)
            if not isinstance(cls, type) or cls.__module__ != module_name:
                raise ManualJarvisSkillsError("required loaded Resources compiler class differs")
            modules.append(("class-bindings", module_name, class_name,
                            tuple((name, _literal_runtime_value(
                                getattr(cls, name), budget=runtime_budget))
                                  for name in attribute_names)))
        if module_name == "hermes_installer.components.native_plugins":
            rows = getattr(module, "NATIVE_PLUGIN_ADAPTERS", None)
            by_id = getattr(module, "_PLUGIN_BY_ID", None)
            contract_type = getattr(module, "NativePluginAdapterContract", None)
            if (type(rows) is not tuple or type(by_id) is not dict or not isinstance(contract_type, type)
                    or set(by_id) != {getattr(row, "adapter_id", None) for row in rows}
                    or any(type(row) is not contract_type for row in rows)
                    or any(type(row) is not contract_type for row in by_id.values())):
                raise ManualJarvisSkillsError("loaded native plugin contract table differs")
            def contract_row(row):
                return tuple((name, _literal_runtime_value(
                    getattr(row, name), budget=runtime_budget))
                    for name in _PLUGIN_CONTRACT_FIELDS)
            modules.append(("native-plugin-contracts",
                            tuple(contract_row(row) for row in rows),
                            tuple((key, contract_row(by_id[key])) for key in sorted(by_id))))

    import yaml
    expected_python = _BASE_ARTIFACT_RUNTIME_ENTRYPOINTS.get(sys.executable)
    if expected_python is None:
        raise ManualJarvisSkillsError("pinned Python invocation path differs")
    (expected_target, expected_version, expected_uid, expected_gid, expected_mode,
     expected_size, expected_sha, expected_prefix, expected_base_prefix) = expected_python
    if (tuple(sys.version_info[:3]) != expected_version
            or sys.implementation.name != "cpython"
            or yaml.__version__ != "6.0.3"
            or not callable(yaml.safe_load) or not callable(yaml.safe_dump)
            or not callable(yaml.load) or not callable(yaml.dump)):
        raise ManualJarvisSkillsError("pinned Resources compiler runtime identity differs")
    expected_yaml_path, yaml_uid, yaml_gid, yaml_mode, yaml_sha = \
        _BASE_ARTIFACT_YAML_ORIGINS[sys.executable]
    yaml_file = Path(yaml.__file__).resolve(strict=True)
    yaml_spec = getattr(yaml, "__spec__", None)
    if getattr(yaml_spec, "origin", None) != expected_yaml_path:
        raise ManualJarvisSkillsError("pinned YAML package origin differs")
    yaml_witness = _runtime_file_witness(
        yaml_file, expected_path=expected_yaml_path, expected_uid=yaml_uid,
        expected_gid=yaml_gid, expected_mode=yaml_mode, expected_size=None,
        expected_sha256=yaml_sha, size_limit=1024 * 1024)
    python_file = Path(sys.executable).resolve(strict=True)
    python_witness = _runtime_file_witness(
        python_file, expected_path=expected_target, expected_uid=expected_uid,
        expected_gid=expected_gid, expected_mode=expected_mode, expected_size=expected_size,
        expected_sha256=expected_sha, size_limit=expected_size)
    prefix = str(Path(sys.prefix).resolve(strict=True))
    base_prefix = str(Path(sys.base_prefix).resolve(strict=True))
    if prefix != expected_prefix or base_prefix != expected_base_prefix:
        raise ManualJarvisSkillsError("pinned Python environment identity differs")
    modules.append(("python", sys.implementation.name, tuple(sys.version_info[:3]),
                    sys.executable, python_witness, prefix, base_prefix, sys.implementation.cache_tag))
    modules.append(("yaml", yaml, yaml.__version__, yaml_file,
                    yaml.safe_load, getattr(yaml.safe_load, "__code__", None),
                    yaml.safe_dump, getattr(yaml.safe_dump, "__code__", None),
                    yaml.load, getattr(yaml.load, "__code__", None),
                    yaml.dump, getattr(yaml.dump, "__code__", None),
                    yaml.SafeLoader, yaml.SafeDumper))
    modules.append(("yaml-origin", yaml_spec, yaml_witness))
    for class_name, table_name in _BASE_ARTIFACT_YAML_TABLES:
        loader_dumper = getattr(yaml, class_name)
        table = getattr(loader_dumper, table_name, None)
        if type(table) is not dict:
            raise ManualJarvisSkillsError("pinned YAML parser table differs")
        modules.append(("yaml-table", class_name, table_name,
                        _literal_runtime_value(table, budget=runtime_budget)))
    return tuple(modules)


def _root_artifact_source_witness(source_root, expected_input_sha256):
    """Hash the exact Root-owned, provenance-bound files used by the builder."""
    source_root = Path(source_root)
    resolved_root = source_root.resolve(strict=True)
    if (resolved_root != source_root or source_root.name != "src"
            or source_root.parent.parent != Path("/opt")
            or not re.fullmatch(r"hermes-installer-core-[0-9a-f]{9,64}",
                                source_root.parent.name)):
        raise ManualJarvisSkillsError("fixed Resources builder source root differs")

    def read_fixed(relative, *, mode, maximum, base=source_root):
        parts = PurePosixPath(relative).parts
        if (not parts or PurePosixPath(relative).is_absolute()
                or any(part in {"", ".", ".."} for part in parts)):
            raise ManualJarvisSkillsError("fixed Resources builder input path differs")
        fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        try:
            for component in (*Path(base).parts[1:], *parts[:-1]):
                child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                st = os.fstat(child)
                if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                        or stat.S_IMODE(st.st_mode) & 0o022):
                    os.close(child)
                    raise ManualJarvisSkillsError("Resources builder directory custody differs")
                os.close(fd)
                fd = child
            name = parts[-1]
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1
                    or before.st_size < 0 or before.st_size > maximum):
                raise ManualJarvisSkillsError("Resources builder input custody differs")
            file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try:
                opened = os.fstat(file_fd)
                if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                     opened.st_ctime_ns) !=
                        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                         before.st_ctime_ns)):
                    raise ManualJarvisSkillsError("Resources builder input changed before read")
                chunks = []
                remaining = maximum + 1
                while remaining:
                    chunk = os.read(file_fd, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                after_fd = os.fstat(file_fd)
                after_name = os.stat(name, dir_fd=fd, follow_symlinks=False)
                signature = (before.st_dev, before.st_ino, before.st_size,
                             before.st_mtime_ns, before.st_ctime_ns)
                if (len(data) != before.st_size or len(data) > maximum
                        or signature != (after_fd.st_dev, after_fd.st_ino, after_fd.st_size,
                                         after_fd.st_mtime_ns, after_fd.st_ctime_ns)
                        or signature != (after_name.st_dev, after_name.st_ino, after_name.st_size,
                                         after_name.st_mtime_ns, after_name.st_ctime_ns)):
                    raise ManualJarvisSkillsError("Resources builder input changed during read")
                return hashlib.sha256(data).hexdigest(), signature, data
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)

    if (type(expected_input_sha256) is not tuple
            or tuple(path for path, _digest in expected_input_sha256) != _BASE_ARTIFACT_INPUTS
            or any(type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                   for _path, digest in expected_input_sha256)):
        raise ManualJarvisSkillsError("reviewed Resources builder input pins differ")
    expected_digests = dict(expected_input_sha256)
    rows = []
    total = 0
    for relative in _BASE_ARTIFACT_INPUTS:
        mode = 0o644
        maximum = _BASE_ARTIFACT_CODE_LIMIT if relative.endswith(".py") else _BASE_ARTIFACT_SOURCE_LIMIT
        digest, signature, _data = read_fixed(relative, mode=mode, maximum=maximum)
        if digest != expected_digests[relative]:
            raise ManualJarvisSkillsError("Resources builder input differs from its reviewed digest")
        total += signature[2]
        if total > _BASE_ARTIFACT_CLOSURE_LIMIT:
            raise ManualJarvisSkillsError("Resources builder input closure exceeds its bound")
        rows.append((relative, digest, signature))

    generation = source_root.parent
    receipt_digest, receipt_sig, receipt_raw = read_fixed(
        ".source-provenance.json", mode=0o444, maximum=4096, base=generation)
    total += receipt_sig[2]
    if total > _BASE_ARTIFACT_CLOSURE_LIMIT:
        raise ManualJarvisSkillsError("Resources builder input closure exceeds its bound")
    try:
        receipt = json.loads(receipt_raw, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError):
        raise ManualJarvisSkillsError("Resources source provenance is malformed") from None
    if (type(receipt) is not dict
            or set(receipt) != {"schema", "source_commit", "archive_sha256"}
            or type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or not isinstance(receipt.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", receipt["source_commit"]) is None
            or not isinstance(receipt.get("archive_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt["archive_sha256"]) is None
            or source_root.parent.name != "hermes-installer-core-" + receipt["source_commit"][:9]
            or receipt_raw != _canonical_json(receipt)):
        raise ManualJarvisSkillsError("Resources source provenance differs")
    return (tuple(rows), receipt_digest, receipt_sig,
            receipt["source_commit"], receipt["archive_sha256"])


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class ManualJarvisSkillsError(RuntimeError):
    """The manual MVP skill stage cannot safely create or verify this generation."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_manual_jarvis_skills_artifact_uncached() -> bytes:
    """Build a deterministic import package from the checked-in verified source."""
    from .native import NativeRegistry
    from .source import load_bundled_source

    source = load_bundled_source()
    if source.revision != PINNED_REVISION or source.source_tree != PINNED_TREE:
        raise ManualJarvisSkillsError("verified Resources source differs from the manual stage pin")
    registry = NativeRegistry.from_verified_source(source)
    from . import jarvis_master_semantics as master_semantics
    overlay_identity = master_semantics.overlay_identity()
    if (overlay_identity["upstream_revision"] != source.revision
            or overlay_identity["upstream_tree"] != source.source_tree):
        raise ManualJarvisSkillsError("Jarvis semantic overlay is not pinned to the verified Resources source")
    discovery = registry.discover_all()
    rows = [item for item in discovery.resources if item.resource.kind.value == "skills"]
    profiles = [item for item in discovery.resources if item.resource.kind.value == "profiles"]
    by_id = {item.resource.id: item for item in rows}
    if (len(by_id) != _BUNDLE_SKILL_COUNT or len(profiles) != _BUNDLE_PROFILE_COUNT
            or not set(PRIMARY_SKILLS).issubset(by_id)):
        raise ManualJarvisSkillsError("verified Resources identities differ from the reviewed full bundle")

    compiled = registry.materialize(discovery)
    members: list[dict[str, Any]] = []
    profile_members: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    try:
        import yaml
    except ImportError:
        raise ManualJarvisSkillsError("PyYAML is required to retain native profile aliases") from None
    helper_bytes = Path(__file__).read_bytes()
    for skill_id in sorted(by_id):
        staged_path = f"homes/skills/{skill_id}/SKILL.md"
        content = compiled.get(staged_path)
        if not isinstance(content, bytes) or not content or len(content) > _MEMBER_LIMIT:
            raise ManualJarvisSkillsError("verified Jarvis skill output is missing or exceeds its size bound")
        if not content.startswith(f"---\nname: {skill_id}\n".encode("utf-8")):
            raise ManualJarvisSkillsError("compiled native skill identity differs from its pinned source")
        item = by_id[skill_id]
        key = f"skills/{skill_id}@{item.resource.version}"
        raw = registry.resolver.raw[key]
        zip_path = f"skills/{skill_id}/SKILL.md"
        files[zip_path] = content
        members.append({
            "skill_id": skill_id,
            "version": item.resource.version,
            "source_path": registry.paths[key],
            "source_document_sha256": raw.content_digest,
            "effective_spec_sha256": _sha256(_canonical_json(dict(item.effective_spec or item.resource.body))),
            "archive_path": zip_path,
            "size_bytes": len(content),
            "sha256": _sha256(content),
        })

    effective_prompt_hashes: dict[str, dict[str, str]] = {}
    from .native import effective_native_profile_spec, _profile_files
    for item in sorted(profiles, key=lambda value: value.resource.id):
        profile_id = item.resource.id
        raw_key = f"profiles/{profile_id}@{item.resource.version}"
        raw = registry.resolver.raw[raw_key]
        source_spec = item.effective_spec or item.resource.body
        baseline_spec = effective_native_profile_spec(profile_id, source_spec)
        baseline = _profile_files(item, registry.paths[raw_key], raw.document, effective_spec=baseline_spec)
        baseline_prompt = baseline[f"homes/profiles/{profile_id}/SOUL.md"]
        effective_prompt = compiled[f"homes/profiles/{profile_id}/SOUL.md"]
        for suffix in ("SOUL.md", "profile.yaml"):
            staged_path = f"homes/profiles/{profile_id}/{suffix}"
            content = compiled.get(staged_path)
            if not isinstance(content, bytes) or not content or len(content) > _MEMBER_LIMIT:
                raise ManualJarvisSkillsError("compiled internal profile prompt is missing or oversized")
            archive_path = f"registry/profiles/{profile_id}/{suffix}"
            files[archive_path] = content
        profile_meta = yaml.safe_load(files[f"registry/profiles/{profile_id}/profile.yaml"])
        alias = profile_meta.get("display_name") if isinstance(profile_meta, dict) else None
        if not isinstance(alias, str) or not alias:
            raise ManualJarvisSkillsError("compiled internal profile alias is missing")
        profile_members.append({
            "source_id": profile_id,
            "version": item.resource.version,
            "source_path": registry.paths[raw_key],
            "source_document_sha256": raw.content_digest,
            # The resolver digest is over canonical parsed document content;
            # retain a separate digest for the exact upstream YAML member.
            "source_declaration_sha256": _sha256(source.files[registry.paths[raw_key]]),
            "identity_sha256": _sha256(files[f"registry/profiles/{profile_id}/SOUL.md"]),
            "upstream_compiled_identity_sha256": _sha256(baseline_prompt),
            "profile_yaml_sha256": _sha256(files[f"registry/profiles/{profile_id}/profile.yaml"]),
            "native_alias": alias,
            "overlay_id": overlay_identity["overlay_id"] if profile_id in {"hermes", "orchestrator"} else None,
            "overlay_sha256": overlay_identity["sha256"] if profile_id in {"hermes", "orchestrator"} else None,
        })
        effective_prompt_hashes[profile_id] = {
            "upstream_compiled_prompt_sha256": _sha256(baseline_prompt),
            "effective_prompt_sha256": _sha256(effective_prompt),
        }

    # Keep the complete generated resource declaration/catalog/adapter bundle
    # beside the private profile records. Hermes only scans `skills/`; this
    # registry namespace remains data until a separately reviewed dispatcher
    # activates a concrete adapter.
    package_members: list[dict[str, Any]] = []
    # Keep the exact upstream source declarations for all overlay targets in
    # the offline package, distinct from the derivative effective outputs.
    overlay_source_paths = {
        "profiles/hermes.yaml",
        "profiles/orchestrator.yaml",
        "bundles/hermes-runtime.yaml",
    }
    for relative in sorted(overlay_source_paths):
        content = source.files.get(relative)
        if not isinstance(content, bytes):
            raise ManualJarvisSkillsError("upstream overlay source declaration is missing")
        archive_path = f"registry/package/upstream-source/{relative}"
        files[archive_path] = content
        package_members.append({"archive_path": archive_path, "size_bytes": len(content),
                                "sha256": _sha256(content)})
    overlay_bytes = package_files("hermes_installer").joinpath(
        "registry", "bundle_data", "jarvis-master-semantics.json").read_bytes()
    overlay_archive_path = "registry/package/installer-overlays/jarvis-master-semantics.json"
    files[overlay_archive_path] = overlay_bytes
    package_members.append({"archive_path": overlay_archive_path, "size_bytes": len(overlay_bytes),
                            "sha256": _sha256(overlay_bytes)})
    for relative, content in compiled.items():
        if relative.startswith("homes/"):
            continue
        archive_path = f"registry/package/{relative}"
        files[archive_path] = content
        package_members.append({"archive_path": archive_path, "size_bytes": len(content),
                                "sha256": _sha256(content)})

    bundle_key = next((key for key in registry.resolver.raw
                       if key.startswith("bundles/hermes-runtime@")), None)
    if bundle_key is None:
        raise ManualJarvisSkillsError("pinned Hermes runtime bundle source is missing")
    bundle_archive_path = registry.paths[bundle_key]
    effective_bundle_path = f"registry/package/{bundle_archive_path}"
    upstream_bundle_path = "bundles/hermes-runtime.yaml"

    selected = [
        {"kind": row.resource.kind.value, "id": row.resource.id, "version": row.resource.version}
        for row in discovery.resources
    ]
    manifest = {
        "schema": 1,
        "stage": "manual-owned-bundled-resources-import",
        "managed_installer_authority": False,
        "target_home_role": "jarvis-primary-home",
        "target_profile": {"source_id": PRIMARY_PROFILE, "native_key": "default", "display_name": "Jarvis"},
        "source": {
            "repository": source.repository,
            "revision": source.revision,
            "git_tree": source.source_tree,
            "catalog_version": source.catalog_version,
            "content_digest": source.content_digest,
            "archive_sha256": "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1",
        },
        "effective_overlay": {
            **overlay_identity,
            "source_declarations": {
                path: _sha256(source.files[path]) for path in sorted(overlay_source_paths)
            },
            "compiled_profiles": {
                profile_id: effective_prompt_hashes[profile_id]
                for profile_id in ("hermes", "orchestrator")
            },
            "compiled_bundle": {
                "source_path": upstream_bundle_path,
                "source_document_sha256": _sha256(source.files[upstream_bundle_path]),
                "effective_archive_path": effective_bundle_path,
                "effective_sha256": _sha256(files[effective_bundle_path]),
            },
            "authority_note": "Workflow prompt/configuration only; no native grants, accounts, isolation, or runtime capability.",
        },
        "bundled_resource_inventory": sorted(selected, key=lambda row: (row["kind"], row["id"])),
        "skill_members": members,
        "profile_members": profile_members,
        "package_members": package_members,
        "installer": {"archive_path": "manual_stage_jarvis_skills.py",
                      "size_bytes": len(helper_bytes), "sha256": _sha256(helper_bytes)},
        "reference_closure": {
            "status": "complete-for-bundled-native-skill-files-and-profile-prompt-records",
            "external_files": [],
            "explanation": (
                "All 396 native skills and all 208 effective profile prompts/aliases are "
                "compiled from the vendored offline source. Profile prompt material is "
                "retained below a private registry namespace and is not copied into "
                "Hermes' selectable profile roster. The pinned upstream declarations remain "
                "verbatim beside the separately hashed installer-owned Jarvis workflow overlay. "
                "The pinned declarations contain no "
                "external support-file closure."
            ),
        },
        "plugin": PLUGIN_PENDING,
        "readiness": {
            "bundled": True, "validated": True, "materialized": False,
            "discovered": False, "authenticated": False, "functional": False,
            "enabled": False, "target_verified": False,
        },
    }
    buffer = tempfile.SpooledTemporaryFile(max_size=_ARTIFACT_LIMIT)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        _zip_write(archive, "manifest.json", _canonical_json(manifest))
        for name in sorted(files):
            _zip_write(archive, name, files[name])
        _zip_write(archive, "manual_stage_jarvis_skills.py", helper_bytes)
    buffer.seek(0)
    result = buffer.read(_ARTIFACT_LIMIT + 1)
    buffer.close()
    if len(result) > _ARTIFACT_LIMIT:
        raise ManualJarvisSkillsError("manual Jarvis skill artifact exceeds its bound")
    return result


def build_manual_jarvis_skills_artifact() -> bytes:
    """Build a base artifact, reusing bytes only inside Core's held update."""
    entry = _ROOT_UPDATE_ARTIFACT_CACHE.get()
    if entry is None:
        return _build_manual_jarvis_skills_artifact_uncached()
    if (entry.seal is not _ROOT_UPDATE_ARTIFACT_CACHE_SEAL
            or threading.get_ident() != entry.thread_id or not entry.is_current()):
        entry.invalidate()
        raise ManualJarvisSkillsError("Root update artifact cache authority changed")
    try:
        if entry.poisoned:
            raise ManualJarvisSkillsError("Root update artifact cache operation was invalidated")
        current_witness = entry.witness()
        if entry.artifact is None:
            artifact = _build_manual_jarvis_skills_artifact_uncached()
            if (type(artifact) is not bytes or not artifact or len(artifact) > _ARTIFACT_LIMIT
                    or not entry.is_current() or entry.witness() != current_witness):
                raise ManualJarvisSkillsError("Resources builder inputs changed during artifact build")
            entry.artifact = artifact
            entry.artifact_sha256 = _sha256(artifact)
            entry.source_witness = current_witness
        elif (current_witness != entry.source_witness
              or type(entry.artifact) is not bytes or not entry.artifact
              or len(entry.artifact) > _ARTIFACT_LIMIT
              or _sha256(entry.artifact) != entry.artifact_sha256):
            raise ManualJarvisSkillsError("Resources builder input witness changed during Root update")
        if not entry.is_current():
            raise ManualJarvisSkillsError("Root update artifact cache operation ended")
        return entry.artifact
    except BaseException:
        entry.invalidate()
        raise


def _zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, data)


def _read_artifact(archive_bytes: bytes, expected_sha256: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    if (not isinstance(expected_sha256, str) or not _HEX64.fullmatch(expected_sha256)
            or not isinstance(archive_bytes, bytes) or not archive_bytes
            or len(archive_bytes) > _ARTIFACT_LIMIT or _sha256(archive_bytes) != expected_sha256):
        raise ManualJarvisSkillsError("manual stage artifact digest or size is invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise ValueError
            members_by_name = {info.filename: info for info in infos}
            if any(PurePosixPath(name).is_absolute() or "\\" in name
                   or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
                   for name in names):
                raise ValueError
            if any(
                info.file_size > (
                    1024 * 1024 if info.filename == "manifest.json" else
                    _PACKAGE_MEMBER_LIMIT if info.filename.startswith("registry/package/") else
                    _MEMBER_LIMIT
                )
                or info.compress_type != zipfile.ZIP_STORED
                or (info.create_system == 3 and not stat.S_ISREG(info.external_attr >> 16))
                for info in members_by_name.values()
            ):
                raise ValueError
            manifest_bytes = archive.read("manifest.json")
            if len(manifest_bytes) > 1024 * 1024:
                raise ValueError
            manifest = json.loads(manifest_bytes)
            members = manifest["skill_members"]
            profiles = manifest["profile_members"]
            package_members = manifest["package_members"]
            expected_paths = {row["archive_path"] for row in members}
            profile_paths = {f"registry/profiles/{row['source_id']}/{suffix}"
                             for row in profiles for suffix in ("SOUL.md", "profile.yaml")}
            package_paths = {row["archive_path"] for row in package_members}
            skill_ids = [row["skill_id"] for row in members]
            profile_ids = [row["source_id"] for row in profiles]
            if (set(names) != expected_paths | profile_paths | package_paths |
                    {"manifest.json", "manual_stage_jarvis_skills.py"}):
                raise ValueError
            if (not package_paths or len(expected_paths) != len(members)
                    or len(profile_paths) != 2 * len(profiles)
                    or len(package_paths) != len(package_members)
                    or any(PurePosixPath(name).name == "SKILL.md" for name in package_paths)
                    or len(set(skill_ids)) != _BUNDLE_SKILL_COUNT
                    or len(set(profile_ids)) != _BUNDLE_PROFILE_COUNT
                    or PRIMARY_PROFILE not in profile_ids):
                raise ValueError
            if (manifest["schema"] != 1 or manifest["stage"] != "manual-owned-bundled-resources-import"
                    or manifest["managed_installer_authority"] is not False
                    or manifest["source"]["repository"] !=
                    "https://github.com/Togarriapa/HermesAgent_Resources"
                    or manifest["source"]["revision"] != PINNED_REVISION
                    or manifest["source"]["git_tree"] != PINNED_TREE
                    or manifest["source"]["catalog_version"] != PINNED_VERSION
                    or manifest["target_home_role"] != "jarvis-primary-home"
                    or manifest["target_profile"] != {
                        "source_id": "hermes", "native_key": "default", "display_name": "Jarvis"}
                    or manifest["source"]["archive_sha256"] !=
                    "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
                    or manifest["reference_closure"].get("external_files") != []
                    or len(members) != _BUNDLE_SKILL_COUNT or len(profiles) != _BUNDLE_PROFILE_COUNT
                    or not set(PRIMARY_SKILLS).issubset(set(skill_ids))):
                raise ValueError
            overlay = manifest.get("effective_overlay")
            expected_overlay = None
            overlay_file = "registry/package/installer-overlays/jarvis-master-semantics.json"
            if overlay is None:
                # One exact pre-overlay package is retained by the root CAS on
                # the enrolled Pi. It is accepted only so root can verify and
                # explicitly migrate that exact owned generation.
                if expected_sha256 != LEGACY_MATERIALIZED_ARTIFACT_SHA256:
                    raise ValueError
            else:
                from .jarvis_master_semantics import overlay_identity
                expected_overlay = overlay_identity()
                if (not isinstance(overlay, dict)
                        or any(overlay.get(key) != value for key, value in expected_overlay.items())
                        or overlay.get("authority_note") !=
                        "Workflow prompt/configuration only; no native grants, accounts, isolation, or runtime capability."):
                    raise ValueError
            files = {}
            helper = archive.read("manual_stage_jarvis_skills.py")
            if (len(helper) != manifest["installer"]["size_bytes"]
                    or _sha256(helper) != manifest["installer"]["sha256"]):
                raise ValueError
            for row in members:
                name = row["archive_path"]
                if (name not in expected_paths or row["size_bytes"] > _MEMBER_LIMIT
                        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", row["skill_id"])
                        or name != f"skills/{row['skill_id']}/SKILL.md"):
                    raise ValueError
                content = archive.read(name)
                if (len(content) != row["size_bytes"] or _sha256(content) != row["sha256"]
                        or not content.startswith(f"---\nname: {row['skill_id']}\n".encode())):
                    raise ValueError
                files[name] = content
            for row in profiles:
                if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", row["source_id"]):
                    raise ValueError
                for suffix in ("SOUL.md", "profile.yaml"):
                    name = f"registry/profiles/{row['source_id']}/{suffix}"
                    content = archive.read(name)
                    expected_hash = row["identity_sha256"] if suffix == "SOUL.md" else row["profile_yaml_sha256"]
                    if not content or len(content) > _MEMBER_LIMIT or _sha256(content) != expected_hash:
                        raise ValueError
                    files[name] = content
            for name in package_paths:
                content = archive.read(name)
                row = next(row for row in package_members if row["archive_path"] == name)
                if (len(content) != row["size_bytes"]
                        or len(content) > _PACKAGE_MEMBER_LIMIT or _sha256(content) != row["sha256"]
                        or not name.startswith("registry/package/")
                        or PurePosixPath(name).name == "SKILL.md"):
                    raise ValueError
                files[name] = content
            if overlay is None:
                if any(name.startswith("registry/package/upstream-source/")
                       or name == overlay_file for name in files):
                    raise ValueError
                if any("overlay_id" in row or "overlay_sha256" in row
                       or "upstream_compiled_identity_sha256" in row for row in profiles):
                    raise ValueError
                if expected_sha256 != LEGACY_MATERIALIZED_ARTIFACT_SHA256:
                    raise ValueError
                if manifest["plugin"].get("state") != "not-imported":
                    raise ValueError
                return manifest, files
            source_declarations = overlay.get("source_declarations")
            expected_source_paths = {
                "profiles/hermes.yaml", "profiles/orchestrator.yaml", "bundles/hermes-runtime.yaml"
            }
            if not isinstance(source_declarations, dict) or set(source_declarations) != expected_source_paths:
                raise ValueError
            for source_path, digest in source_declarations.items():
                archived_source = f"registry/package/upstream-source/{source_path}"
                if archived_source not in files or _sha256(files[archived_source]) != digest:
                    raise ValueError
            if _sha256(files.get(overlay_file, b"")) != expected_overlay["sha256"]:
                raise ValueError
            rows_by_id = {row["source_id"]: row for row in profiles}
            if any(rows_by_id[profile_id].get("source_declaration_sha256")
                   != source_declarations[f"profiles/{profile_id}.yaml"]
                   for profile_id in ("hermes", "orchestrator")):
                raise ValueError
            compiled_profiles = overlay.get("compiled_profiles")
            if not isinstance(compiled_profiles, dict) or set(compiled_profiles) != {"hermes", "orchestrator"}:
                raise ValueError
            for profile_id in ("hermes", "orchestrator"):
                row = rows_by_id[profile_id]
                compiled = compiled_profiles[profile_id]
                if (row.get("overlay_id") != expected_overlay["overlay_id"]
                        or row.get("overlay_sha256") != expected_overlay["sha256"]
                        or not isinstance(compiled, dict)
                        or compiled.get("upstream_compiled_prompt_sha256") != row.get("upstream_compiled_identity_sha256")
                        or compiled.get("effective_prompt_sha256") != row.get("identity_sha256")
                        or compiled.get("effective_prompt_sha256") != _sha256(files[f"registry/profiles/{profile_id}/SOUL.md"])):
                    raise ValueError
            for profile_id, row in rows_by_id.items():
                if profile_id not in {"hermes", "orchestrator"} and (row.get("overlay_id") is not None
                                                                       or row.get("overlay_sha256") is not None):
                    raise ValueError
            compiled_bundle = overlay.get("compiled_bundle")
            if (not isinstance(compiled_bundle, dict)
                    or compiled_bundle.get("source_path") != "bundles/hermes-runtime.yaml"
                    or compiled_bundle.get("source_document_sha256") != source_declarations["bundles/hermes-runtime.yaml"]
                    or compiled_bundle.get("effective_archive_path") not in files
                    or _sha256(files[compiled_bundle["effective_archive_path"]]) != compiled_bundle.get("effective_sha256")):
                raise ValueError
            if manifest["plugin"].get("state") != "not-imported":
                raise ValueError
            return manifest, files
    except (OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        raise ManualJarvisSkillsError("manual stage artifact contents are malformed or do not match its pin") from None


def verify_same_materialization_transition(
    previous_manifest: Mapping[str, Any], previous_files: Mapping[str, bytes],
    next_manifest: Mapping[str, Any], next_files: Mapping[str, bytes],
) -> bool:
    """Classify only an exact helper metadata/byte change.

    Both complete archives must first pass `_read_artifact`; the transition
    boundary separately verifies each embedded helper's bytes against its
    installer row. The helper is not materialized into the Resources tree.
    """
    def installer_row(manifest):
        if type(manifest) is not dict:
            return None
        value = manifest.get("installer")
        if (type(value) is not dict
                or set(value) != {"archive_path", "size_bytes", "sha256"}
                or value.get("archive_path") != _HELPER_ARCHIVE_PATH
                or type(value.get("size_bytes")) is not int
                or not 0 < value["size_bytes"] <= 1024 * 1024
                or not isinstance(value.get("sha256"), str)
                or _HEX64.fullmatch(value["sha256"]) is None):
            return None
        return value

    if installer_row(previous_manifest) is None or installer_row(next_manifest) is None:
        return False
    if (type(previous_files) is not dict or type(next_files) is not dict
            or _HELPER_ARCHIVE_PATH in previous_files or _HELPER_ARCHIVE_PATH in next_files
            or any(not isinstance(path, str) or not isinstance(data, bytes)
                   for mapping in (previous_files, next_files) for path, data in mapping.items())):
        return False
    old_non_installer = dict(previous_manifest)
    new_non_installer = dict(next_manifest)
    old_non_installer.pop("installer")
    new_non_installer.pop("installer")
    # Dict equality covers each path and complete byte string; `_read_artifact`
    # has already enforced the declared member sizes and hashes.
    return old_non_installer == new_non_installer and previous_files == next_files


def _same_materialization_digests(manifest: Mapping[str, Any], files: Mapping[str, bytes]):
    shared_manifest = dict(manifest)
    shared_manifest.pop("installer", None)
    rows = [{"path": path, "size_bytes": len(content), "sha256": _sha256(content)}
            for path, content in sorted(files.items()) if path != _HELPER_ARCHIVE_PATH]
    return (_sha256(_canonical_json(shared_manifest)),
            _sha256(_canonical_json(rows)), len(rows))


def _read_transition_archive(archive_bytes: bytes, expected_sha256: str):
    manifest, files = _read_artifact(archive_bytes, expected_sha256)
    installer = manifest.get("installer")
    if (type(installer) is not dict
            or set(installer) != {"archive_path", "size_bytes", "sha256"}
            or installer.get("archive_path") != _HELPER_ARCHIVE_PATH
            or type(installer.get("size_bytes")) is not int
            or not 0 < installer["size_bytes"] <= 1024 * 1024
            or not isinstance(installer.get("sha256"), str)
            or _HEX64.fullmatch(installer["sha256"]) is None):
        raise ManualJarvisSkillsError("helper-only transition installer metadata differs")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            helper = archive.read(_HELPER_ARCHIVE_PATH)
    except (OSError, KeyError, zipfile.BadZipFile):
        raise ManualJarvisSkillsError("helper-only transition member is unavailable") from None
    if (len(helper) != installer["size_bytes"]
            or _sha256(helper) != installer["sha256"]):
        raise ManualJarvisSkillsError("helper-only transition member digest differs")
    return manifest, files, helper


def _verify_owner_skill_overlay_transition(previous_manifest, previous_files, previous_sha256,
                                           manifest, files):
    """Permit replacing an owned generation only for one pinned skill document."""
    if previous_sha256 == LEGACY_MATERIALIZED_ARTIFACT_SHA256:
        return
    try:
        if set(previous_files) != set(files):
            raise ValueError
        def normalized(source):
            value = json.loads(_canonical_json(source))
            for row in value["skill_members"]:
                row.pop("size_bytes", None)
                row.pop("sha256", None)
            return value
        if normalized(previous_manifest) != normalized(manifest):
            raise ValueError
        old_rows = {row["skill_id"]: row for row in previous_manifest["skill_members"]}
        new_rows = {row["skill_id"]: row for row in manifest["skill_members"]}
        if len(old_rows) != _BUNDLE_SKILL_COUNT or set(old_rows) != set(new_rows):
            raise ValueError
        changed_paths = {name for name in files if files[name] != previous_files[name]}
        changed_ids = {skill_id for skill_id, row in old_rows.items()
                       if previous_files.get(row["archive_path"]) != files.get(row["archive_path"])}
        if (len(changed_ids) > 1 or len(changed_paths) > 1
                or changed_ids != {skill_id for skill_id, row in old_rows.items()
                                   if row["archive_path"] in changed_paths}
                or (changed_paths and changed_paths != {
                    old_rows[next(iter(changed_ids))]["archive_path"]})):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ManualJarvisSkillsError(
            "owned Resources replacement must change exactly one pinned SKILL.md document") from None


def _regular_owned(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    mode_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if path.is_symlink() or not mode_ok or info.st_uid != os.geteuid():
        raise ManualJarvisSkillsError("manual stage path is linked, non-regular, or not owned by this Hermes user")
    return info


def _hash_regular_file(path: Path, *, max_bytes: int) -> str:
    info = _regular_owned(path, directory=False)
    if info.st_nlink != 1 or info.st_size > max_bytes:
        raise ManualJarvisSkillsError("manual stage member has an unexpected link count or size")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        digest = hashlib.sha256()
        total = 0
        while block := os.read(fd, 65536):
            total += len(block)
            if total > max_bytes:
                raise ManualJarvisSkillsError("manual stage member exceeds its read bound")
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _open_stage_parent(root: Path, parts: tuple[str, ...]) -> tuple[int, list[int]]:
    """Create/verify exact 0755 parent directories below the private staging root."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    current = os.open(root, flags | getattr(os, "O_CLOEXEC", 0))
    descriptors.append(current)
    try:
        if os.fstat(current).st_uid != os.geteuid():
            raise ManualJarvisSkillsError("staging root is not owned by the Hermes user")
        for part in parts:
            created = False
            try:
                os.mkdir(part, 0o755, dir_fd=current)
                created = True
            except FileExistsError:
                pass
            child = os.open(part, flags | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink < 2):
                os.close(child)
                raise ManualJarvisSkillsError("staging parent is not a verified owned directory")
            if created:
                os.fchmod(child, 0o755)
                info = os.fstat(child)
            if stat.S_IMODE(info.st_mode) != 0o755:
                os.close(child)
                raise ManualJarvisSkillsError("staging parent has unexpected directory permissions")
            descriptors.append(child)
            current = child
        return current, descriptors
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _repair_owned_generation_directory_modes(target: Path, relative_dirs: set[str]) -> None:
    """Repair only verified umask-created 0775 dirs below an exact owned generation."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(target, flags | getattr(os, "O_CLOEXEC", 0))
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_uid != os.geteuid() or root_info.st_nlink < 2
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ManualJarvisSkillsError("generation root custody differs")
        # The exact file/directory sets and all file digests have already been
        # checked by the caller. Accept only the known 0755->0775 umask drift.
        for relative in sorted(relative_dirs, key=lambda value: (value.count("/"), value)):
            parent = os.dup(root_fd)
            try:
                parts = PurePosixPath(relative).parts
                for index, part in enumerate(parts):
                    child = os.open(part, flags | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
                    info = os.fstat(child)
                    named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                            or info.st_nlink < 2 or info.st_dev != named.st_dev
                            or info.st_ino != named.st_ino
                            or stat.S_IMODE(info.st_mode) not in {0o755, 0o775}):
                        os.close(child)
                        raise ManualJarvisSkillsError("generation directory is not exactly owned")
                    os.close(parent)
                    parent = child
                os.fchmod(parent, 0o755)
                if stat.S_IMODE(os.fstat(parent).st_mode) != 0o755:
                    raise ManualJarvisSkillsError("generation directory mode repair failed")
            finally:
                try:
                    os.close(parent)
                except OSError:
                    pass
    finally:
        os.close(root_fd)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Publish one complete directory without replacing even an empty conflict."""
    import ctypes
    import errno
    import sys

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(destination), 0x00000004)
    else:
        raise ManualJarvisSkillsError("atomic no-replace directory publication is unavailable on this OS")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ManualJarvisSkillsError("the revision-owned Jarvis skill generation path already exists")
        raise OSError(error, os.strerror(error), str(destination))


def _exchange_directories(left: Path, right: Path) -> None:
    """Atomically exchange two directory names on the same filesystem."""
    import ctypes
    import errno
    import sys
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(left), -100, os.fsencode(right), 2)
    else:
        raise ManualJarvisSkillsError("atomic owned-generation exchange is unavailable on this OS")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(right))


def _owned_generation_journal(files: Mapping[str, bytes], artifact_sha256: str) -> bytes:
    return _canonical_json({
        "schema": 1,
        "stage": "manual-owned-bundled-resources-import",
        "artifact_sha256": artifact_sha256,
        "source_revision": PINNED_REVISION,
        "source_tree": PINNED_TREE,
        "profile_source_id": PRIMARY_PROFILE,
        "user_visible_profile": {"source_id": PRIMARY_PROFILE, "native_key": "default", "display_name": "Jarvis"},
        "internal_profile_count": _BUNDLE_PROFILE_COUNT - 1,
        "target_home_role": "jarvis-primary-home",
        "members": [
            {"path": f"{_GENERATION}/{name}", "sha256": _sha256(content), "size_bytes": len(content)}
            for name, content in sorted(files.items())
        ],
    })


def _verify_owned_generation(target: Path, files: Mapping[str, bytes], artifact_sha256: str) -> set[str]:
    """Prove one complete generation against its exact artifact and ownership marker."""
    info = _regular_owned(target, directory=True)
    if info.st_nlink < 2 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ManualJarvisSkillsError("existing skill generation root permissions differ")
    expected_journal = _owned_generation_journal(files, artifact_sha256)
    marker = target / _OWNER_FILE
    if _hash_regular_file(marker, max_bytes=2 * 1024 * 1024) != _sha256(expected_journal):
        raise ManualJarvisSkillsError("existing skill generation is unowned or its ownership journal changed")
    expected_files = set(files) | {_OWNER_FILE}
    expected_dirs = {
        "/".join(PurePosixPath(name).parts[:depth])
        for name in files for depth in range(1, len(PurePosixPath(name).parts))
    }
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    for base, dirs, names in os.walk(target, followlinks=False):
        base_path = Path(base)
        for dirname in dirs:
            directory = base_path / dirname
            directory_info = _regular_owned(directory, directory=True)
            relative = directory.relative_to(target).as_posix()
            if (directory_info.st_nlink < 2
                    or stat.S_IMODE(directory_info.st_mode) not in {0o755, 0o775}):
                raise ManualJarvisSkillsError("existing generation directory permissions differ")
            actual_dirs.add(relative)
        for filename in names:
            candidate = base_path / filename
            _regular_owned(candidate, directory=False)
            actual_files.add(candidate.relative_to(target).as_posix())
    if actual_files != expected_files or actual_dirs != expected_dirs:
        raise ManualJarvisSkillsError("owned Resources generation contains missing or untracked files")
    for name, content in files.items():
        limit = _PACKAGE_MEMBER_LIMIT if name.startswith("registry/package/") else _MEMBER_LIMIT
        if _hash_regular_file(target / name, max_bytes=limit) != _sha256(content):
            raise ManualJarvisSkillsError("owned Resources generation member changed")
    return actual_dirs


def _install_manual_jarvis_skills(
    archive_bytes: bytes, *, hermes_home: str | Path, expected_sha256: str,
    replace_owned_from_archive: bytes | None = None,
    replace_owned_from_sha256: str | None = None,
    migration_kind: str = "overlay",
    transition_shared_manifest_sha256: str | None = None,
    transition_shared_materialization_sha256: str | None = None,
    transition_shared_member_count: int | None = None,
    transition_backup_name: str | None = None,
) -> dict[str, Any]:
    """Atomically add one revision-namespaced skill generation to a user's Hermes home.

    Existing home state and skill files are never overwritten or adopted. The
    manifest inside the generation is the manual-stage ownership journal.
    Run as the existing Hermes home owner, without sudo.
    """
    manifest, files = _read_artifact(archive_bytes, expected_sha256)
    previous_manifest = previous_files = None
    if replace_owned_from_archive is not None or replace_owned_from_sha256 is not None:
        if not isinstance(replace_owned_from_archive, bytes):
            raise ManualJarvisSkillsError("owned-generation migration archive is missing")
        previous_manifest, previous_files = _read_artifact(
            replace_owned_from_archive, replace_owned_from_sha256)
        if migration_kind == "overlay":
            _verify_owner_skill_overlay_transition(previous_manifest, previous_files,
                replace_owned_from_sha256, manifest, files)
        elif migration_kind == "helper-only":
            old_manifest, old_files, old_helper = _read_transition_archive(
                replace_owned_from_archive, replace_owned_from_sha256)
            new_manifest, new_files, new_helper = _read_transition_archive(
                archive_bytes, expected_sha256)
            if (not verify_same_materialization_transition(
                    old_manifest, old_files, new_manifest, new_files)
                    or new_helper != Path(__file__).read_bytes()):
                raise ManualJarvisSkillsError(
                    "helper-only transition differs from the reviewed current helper")
            expected_shared = _same_materialization_digests(new_manifest, new_files)
            if (expected_shared != (transition_shared_manifest_sha256,
                                    transition_shared_materialization_sha256,
                                    transition_shared_member_count)):
                raise ManualJarvisSkillsError("helper-only transition proof digest differs")
            previous_manifest, previous_files = old_manifest, old_files
        else:
            raise ManualJarvisSkillsError("owned-generation transition kind is unsupported")
    home_input = Path(hermes_home)
    if not home_input.is_absolute():
        raise ManualJarvisSkillsError("Hermes home must be an explicit absolute path")
    if home_input.resolve(strict=True) != home_input:
        raise ManualJarvisSkillsError("Hermes home path contains a symbolic-link component")
    home = home_input.lstat()
    if (not stat.S_ISDIR(home.st_mode) or stat.S_ISLNK(home.st_mode)
            or home.st_uid != os.geteuid()):
        raise ManualJarvisSkillsError("Hermes home must be a real directory owned by the current user")
    soul = home_input / "SOUL.md"
    soul_info = _regular_owned(soul, directory=False)
    if soul_info.st_size == 0:
        raise ManualJarvisSkillsError("Jarvis primary SOUL.md is empty")

    skills_root = home_input / "skills"
    try:
        _regular_owned(skills_root, directory=True)
    except FileNotFoundError:
        skills_root.mkdir(mode=0o755)
        skills_fd = os.open(skills_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            if os.fstat(skills_fd).st_uid != os.geteuid():
                raise ManualJarvisSkillsError("new skills root is not owned by the Hermes user")
            os.fchmod(skills_fd, 0o755)
        finally:
            os.close(skills_fd)
        _regular_owned(skills_root, directory=True)
    target = skills_root / _GENERATION
    journal_bytes = _owned_generation_journal(files, expected_sha256)
    migration_backup: Path | None = None

    try:
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
    if target_info is not None:
        _regular_owned(target, directory=True)
        if (target_info.st_nlink < 2 or stat.S_IMODE(target_info.st_mode) != 0o700):
            raise ManualJarvisSkillsError("existing skill generation root permissions differ")
        owner_path = target / _OWNER_FILE
        try:
            owner_digest = _hash_regular_file(owner_path, max_bytes=2 * 1024 * 1024)
        except FileNotFoundError:
            owner_digest = None
        if owner_digest != _sha256(journal_bytes):
            if previous_manifest is None or previous_files is None or replace_owned_from_sha256 is None:
                raise ManualJarvisSkillsError("existing skill generation is unowned or its ownership journal changed")
            _verify_owned_generation(target, previous_files, replace_owned_from_sha256)
            migration_backup = target
        if migration_backup is None:
            expected_files = set(files) | {_OWNER_FILE}
            actual_files: set[str] = set()
            expected_directories = {
                "/".join(PurePosixPath(name).parts[:depth])
                for name in files for depth in range(1, len(PurePosixPath(name).parts))
            }
            actual_directories: set[str] = set()
            for base, dirs, names in os.walk(target, followlinks=False):
                base_path = Path(base)
                for dirname in dirs:
                    directory_path = base_path / dirname
                    directory_info = _regular_owned(directory_path, directory=True)
                    relative_dir = directory_path.relative_to(target).as_posix()
                    if (directory_info.st_nlink < 2
                            or stat.S_IMODE(directory_info.st_mode) not in {0o755, 0o775}):
                        raise ManualJarvisSkillsError("existing generation directory permissions differ")
                    actual_directories.add(relative_dir)
                for filename in names:
                    candidate = base_path / filename
                    _regular_owned(candidate, directory=False)
                    actual_files.add(candidate.relative_to(target).as_posix())
            if actual_files != expected_files or actual_directories != expected_directories:
                raise ManualJarvisSkillsError(
                    "owned Resources generation contains missing or untracked files; preserving it")
            for name, content in files.items():
                destination = target / name
                member_limit = (_PACKAGE_MEMBER_LIMIT if name.startswith("registry/package/")
                                else _MEMBER_LIMIT)
                if _hash_regular_file(destination, max_bytes=member_limit) != _sha256(content):
                    raise ManualJarvisSkillsError("an owned skill changed after staging; preserving it as a user edit")
            if any(stat.S_IMODE((target / relative).lstat().st_mode) == 0o775
                   for relative in actual_directories):
                _repair_owned_generation_directory_modes(target, actual_directories)
            return {
                "state": "already-staged",
                "materialized": True,
                "discovered": False,
                "artifact_sha256": expected_sha256,
                "generation_path": str(target),
                "skills": sorted(row["skill_id"] for row in manifest["skill_members"]),
                "profiles_preserved_internal": sorted(row["source_id"] for row in manifest["profile_members"]),
            }

    if migration_kind == "helper-only":
        if (not isinstance(transition_backup_name, str)
                or _HELPER_BACKUP_NAME.fullmatch(transition_backup_name) is None):
            raise ManualJarvisSkillsError("helper transition backup identity is invalid")
        temp = home_input / transition_backup_name
        try:
            os.mkdir(temp, 0o700)
        except FileExistsError:
            raise ManualJarvisSkillsError("helper transition backup identity already exists") from None
        temp_info = temp.lstat()
        if (not stat.S_ISDIR(temp_info.st_mode) or temp_info.st_uid != os.geteuid()
                or temp_info.st_gid != os.getegid() or stat.S_IMODE(temp_info.st_mode) != 0o700):
            raise ManualJarvisSkillsError("helper transition backup directory custody differs")
    else:
        temp = Path(tempfile.mkdtemp(prefix=".jarvis-resources-skills-", dir=home_input))
    exchanged = False
    preserve_temp = False
    try:
        for relative, content in sorted(files.items()):
            path = PurePosixPath(relative)
            is_skill = (len(path.parts) == 3 and path.parts[0] == "skills"
                        and path.parts[2] == "SKILL.md")
            is_internal_profile = (len(path.parts) == 4
                                   and path.parts[:2] == ("registry", "profiles")
                                   and path.parts[3] in {"SOUL.md", "profile.yaml"})
            is_registry_package = (len(path.parts) >= 3 and path.parts[:2] == ("registry", "package"))
            if not (is_skill or is_internal_profile or is_registry_package):
                raise ManualJarvisSkillsError("package contains an unsupported native skill path")
            out = temp.joinpath(*path.parts)
            parent_fd, descriptors = _open_stage_parent(temp, path.parts[:-1])
            try:
                fd = os.open(path.parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                             0o644, dir_fd=parent_fd)
                try:
                    view = memoryview(content)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
        marker = temp / _OWNER_FILE
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(journal_bytes)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directories = [Path(base) for base, _dirs, _names in os.walk(temp, topdown=False)]
        for directory in directories:
            child_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
        temp_fd = os.open(temp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        if migration_backup is not None:
            assert previous_files is not None and replace_owned_from_sha256 is not None
            # Re-prove the old exact tree immediately before its one atomic
            # exchange. The previous tree moves outside skills/ in the same
            # syscall, so Hermes never sees two copies of the 396 skill IDs.
            _verify_owned_generation(target, previous_files, replace_owned_from_sha256)
            _exchange_directories(target, temp)
            exchanged = True
            preserve_temp = True
            try:
                _verify_owned_generation(target, files, expected_sha256)
                _verify_owned_generation(temp, previous_files, replace_owned_from_sha256)
            except BaseException:
                try:
                    _exchange_directories(target, temp)
                    exchanged = False
                    preserve_temp = False
                except BaseException:
                    # Keep both complete generations in place for explicit
                    # recovery rather than risk deleting either one.
                    pass
                raise
        else:
            _rename_noreplace(temp, target)
        skills_fd = os.open(skills_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(skills_fd)
        finally:
            os.close(skills_fd)
    except BaseException:
        if temp.exists() and not temp.is_symlink() and not preserve_temp:
            shutil.rmtree(temp)
        raise
    result = {
        "state": "staged",
        "materialized": True,
        "discovered": False,
        "artifact_sha256": expected_sha256,
        "generation_path": str(target),
        "skills": sorted(row["skill_id"] for row in manifest["skill_members"]),
        "profiles_preserved_internal": sorted(row["source_id"] for row in manifest["profile_members"]),
        "next_step": "Run the pinned Hermes skill list/view probe; qualify model-selected use and non-skill integrations separately.",
    }
    if exchanged:
        result["previous_generation_backup"] = str(temp)
        result["previous_artifact_sha256"] = replace_owned_from_sha256
    return result


def install_manual_jarvis_skills(
    archive_bytes: bytes, *, hermes_home: str | Path, expected_sha256: str,
    replace_owned_from_archive: bytes | None = None,
    replace_owned_from_sha256: str | None = None,
) -> dict[str, Any]:
    """Existing owner-overlay/legacy importer; helper-only rebind is separate."""
    return _install_manual_jarvis_skills(
        archive_bytes, hermes_home=hermes_home, expected_sha256=expected_sha256,
        replace_owned_from_archive=replace_owned_from_archive,
        replace_owned_from_sha256=replace_owned_from_sha256,
        migration_kind="overlay")


def install_same_materialization_transition(
    next_archive: bytes, previous_archive: bytes, *, hermes_home: str | Path,
    next_sha256: str, previous_sha256: str,
    shared_manifest_sha256: str, shared_materialization_sha256: str,
    shared_member_count: int, backup_name: str,
) -> dict[str, Any]:
    """Install only a parsed helper-only update; preserve the old tree as backup."""
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    return _install_manual_jarvis_skills(
        next_archive, hermes_home=hermes_home, expected_sha256=next_sha256,
        replace_owned_from_archive=previous_archive,
        replace_owned_from_sha256=previous_sha256,
        migration_kind="helper-only",
        transition_shared_manifest_sha256=shared_manifest_sha256,
        transition_shared_materialization_sha256=shared_materialization_sha256,
        transition_shared_member_count=shared_member_count,
        transition_backup_name=backup_name)


def restore_same_materialization_generation(
    current_archive: bytes, restore_archive: bytes, *, hermes_home: str | Path,
    current_sha256: str, restore_sha256: str, backup_name: str,
    shared_manifest_sha256: str, shared_materialization_sha256: str,
    shared_member_count: int,
) -> dict[str, Any]:
    """Restore A0 from its exact retained exchange directory after cohort abort."""
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    current_manifest, current_files, current_helper = _read_transition_archive(
        current_archive, current_sha256)
    restore_manifest, restore_files, _restore_helper = _read_transition_archive(
        restore_archive, restore_sha256)
    if (not verify_same_materialization_transition(
            restore_manifest, restore_files, current_manifest, current_files)
            or current_helper != Path(__file__).read_bytes()
            or _same_materialization_digests(current_manifest, current_files)
                != (shared_manifest_sha256, shared_materialization_sha256, shared_member_count)):
        raise ManualJarvisSkillsError("restore pair is not the exact reviewed helper-only transition")
    home_input = Path(hermes_home)
    if (not home_input.is_absolute() or home_input != _JARVIS_HOME
            or home_input.resolve(strict=True) != home_input):
        raise ManualJarvisSkillsError("restore home is not the fixed Jarvis home")
    home_info = home_input.lstat()
    if (not stat.S_ISDIR(home_info.st_mode) or stat.S_ISLNK(home_info.st_mode)
            or home_info.st_uid != os.geteuid() or home_info.st_gid != os.getegid()):
        raise ManualJarvisSkillsError("restore home custody differs")
    if _HELPER_BACKUP_NAME.fullmatch(backup_name) is None:
        raise ManualJarvisSkillsError("restore backup identity is invalid")
    target = home_input / "skills" / _GENERATION
    backup = home_input / backup_name
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    _verify_owned_generation(target, current_files, current_sha256)
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    _verify_owned_generation(backup, restore_files, restore_sha256)
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    # Reprove both directories immediately before the single atomic exchange.
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    _verify_owned_generation(target, current_files, current_sha256)
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    _verify_owned_generation(backup, restore_files, restore_sha256)
    _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
    _exchange_directories(target, backup)
    try:
        _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
        _verify_owned_generation(target, restore_files, restore_sha256)
        _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
        _verify_owned_generation(backup, current_files, current_sha256)
    except BaseException:
        try:
            _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
            _exchange_directories(target, backup)
            _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
            _verify_owned_generation(target, current_files, current_sha256)
            _verify_helper_transition_origin(argparse.Namespace(home=str(hermes_home)))
            _verify_owned_generation(backup, restore_files, restore_sha256)
        except BaseException:
            # Preserve both complete trees if an atomic reverse exchange fails.
            pass
        raise
    skills_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(skills_fd)
    finally:
        os.close(skills_fd)
    return {
        "state": "restored", "artifact_sha256": restore_sha256,
        "generation_path": str(target), "retained_generation_backup": str(backup),
        "retained_artifact_sha256": current_sha256,
    }


def _proc_identity(pid: int) -> tuple[int, int, str, tuple[int, ...]]:
    """Read the fixed runuser parent's stable PID lineage without privileged proc access."""
    proc = Path("/proc") / str(pid)
    try:
        def stat_identity(raw: bytes) -> tuple[int, int]:
            close = raw.rfind(b")")
            fields = raw[close + 2:].split()
            if close < 0 or len(fields) <= 19:
                raise ValueError
            return int(fields[1]), int(fields[19])

        def status_identity(raw: str) -> tuple[int, tuple[int, ...]]:
            fields = {}
            for line in raw.splitlines():
                key, separator, value = line.partition(":")
                if separator and key in {"PPid", "Uid"}:
                    if key in fields:
                        raise ValueError
                    fields[key] = value.split()
            if set(fields) != {"PPid", "Uid"} or len(fields["Uid"]) != 4:
                raise ValueError
            return int(fields["PPid"][0]), tuple(int(value) for value in fields["Uid"])

        stat_before = stat_identity((proc / "stat").read_bytes())
        status_before = status_identity((proc / "status").read_text(encoding="ascii"))
        comm_before = (proc / "comm").read_text(encoding="ascii").rstrip("\n")
        stat_after = stat_identity((proc / "stat").read_bytes())
        status_after = status_identity((proc / "status").read_text(encoding="ascii"))
        comm_after = (proc / "comm").read_text(encoding="ascii").rstrip("\n")
        if (stat_before != stat_after or status_before != status_after
                or comm_before != comm_after or stat_before[0] != status_before[0]
                or comm_before != "runuser"):
            raise ValueError
        return stat_before[0], stat_before[1], comm_before, status_before[1]
    except (OSError, StopIteration, UnicodeError, ValueError, IndexError):
        raise ManualJarvisSkillsError("helper-only importer process identity is unavailable") from None


def _verify_helper_transition_origin(args: argparse.Namespace) -> Path:
    """Require the exact root->runuser->admin pipe invocation before any effect.

    The root caller separately owns and consumes its in-process prepared
    transition and verifies the captured runuser process before writing its
    private frame. This unprivileged child check proves only a root-created
    read-only pipe, a stable root-UID runuser parent lineage, and the current
    installed generation; hashes and CLI values are never authority.
    """
    try:
        account = pwd.getpwnam("admin")
        uid = account.pw_uid
        if (not sys.platform.startswith("linux") or os.getresuid() != (uid, uid, uid)
                or os.geteuid() != uid or os.getresgid() !=
                (account.pw_gid, account.pw_gid, account.pw_gid)):
            raise ValueError

        pipe = os.fstat(0)
        flags = fcntl.fcntl(0, fcntl.F_GETFL)
        pipe_link = os.readlink("/proc/self/fd/0")
        if (not stat.S_ISFIFO(pipe.st_mode) or pipe.st_uid != 0
                or flags & os.O_ACCMODE != os.O_RDONLY
                or pipe_link != f"pipe:[{pipe.st_ino}]"):
            raise ValueError

        parent_pid = os.getppid()
        if parent_pid <= 1:
            raise ValueError
        parent_parent_pid, parent_start, parent_comm, parent_uids = _proc_identity(parent_pid)
        if (parent_pid != os.getppid() or parent_parent_pid <= 1
                or parent_parent_pid == os.getpid() or parent_start <= 0
                or parent_comm != "runuser" or parent_uids != (0, 0, 0, 0)):
            raise ValueError

        home = Path(args.home)
        if not home.is_absolute() or home.resolve(strict=True) != home:
            raise ValueError
        home_stat = home.lstat()
        if not stat.S_ISDIR(home_stat.st_mode) or stat.S_ISLNK(home_stat.st_mode) or home_stat.st_uid != uid:
            raise ValueError
        skills_root = home / "skills"
        skills_stat = skills_root.lstat()
        if (not stat.S_ISDIR(skills_stat.st_mode) or stat.S_ISLNK(skills_stat.st_mode)
                or skills_stat.st_uid != uid):
            raise ValueError
        target = home / "skills" / _GENERATION
        target_stat = target.lstat()
        if (not stat.S_ISDIR(target_stat.st_mode) or stat.S_ISLNK(target_stat.st_mode)
                or target_stat.st_uid != uid):
            raise ValueError
        # Recheck the inherited pipe and complete parent tuple after target
        # custody checks; unreadable or changed lineage remains fail-closed.
        pipe_after = os.fstat(0)
        pipe_link_after = os.readlink("/proc/self/fd/0")
        parent_identity_after = _proc_identity(parent_pid)
        if (os.getppid() != parent_pid
                or parent_identity_after != (parent_parent_pid, parent_start,
                                             parent_comm, parent_uids)
                or pipe_after.st_ino != pipe.st_ino or pipe_after.st_dev != pipe.st_dev
                or pipe_after.st_uid != 0 or not stat.S_ISFIFO(pipe_after.st_mode)
                or fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or pipe_link_after != f"pipe:[{pipe_after.st_ino}]" ):
            raise ValueError
        return target
    except (AttributeError, OSError, KeyError, TypeError, ValueError, ManualJarvisSkillsError):
        raise ManualJarvisSkillsError(
            "helper-only transition requires the fixed root runuser and inherited root pipe") from None


def install_and_verify_manual_jarvis_skills(
    archive_bytes: bytes, *, hermes_home: str | Path, expected_sha256: str,
    hermes_source: str | Path, python: str | Path,
    replace_owned_from_archive: bytes | None = None,
    replace_owned_from_sha256: str | None = None,
) -> dict[str, Any]:
    """Stage bundled skills/internal identities, then prove Hermes reads the skills.

    This read-back is intentionally separate from the ownership-safe file write:
    a failure leaves the verified, namespaced files available for a later retry,
    but does not issue a discovery receipt or claim functional tool effects.
    """
    staged = install_manual_jarvis_skills(
        archive_bytes, hermes_home=hermes_home, expected_sha256=expected_sha256,
        replace_owned_from_archive=replace_owned_from_archive,
        replace_owned_from_sha256=replace_owned_from_sha256)
    manifest, package_files = _read_artifact(archive_bytes, expected_sha256)
    previous_manifest = previous_files = None
    if staged.get("previous_generation_backup") is not None:
        if replace_owned_from_archive is None or replace_owned_from_sha256 is None:
            raise ManualJarvisSkillsError("replacement backup receipt has no verified source artifact")
        previous_manifest, previous_files = _read_artifact(
            replace_owned_from_archive, replace_owned_from_sha256)
    def rollback_previous_generation() -> None:
        backup_value = staged.get("previous_generation_backup")
        if backup_value is None or previous_files is None or replace_owned_from_sha256 is None:
            return
        home = Path(hermes_home)
        target = home / "skills" / _GENERATION
        backup = Path(backup_value)
        _verify_owned_generation(target, package_files, expected_sha256)
        _verify_owned_generation(backup, previous_files, replace_owned_from_sha256)
        _exchange_directories(target, backup)
        _verify_owned_generation(target, previous_files, replace_owned_from_sha256)
        _verify_owned_generation(backup, package_files, expected_sha256)
    skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
    try:
        from .native_install import NativeInstallError, discover_and_load_selected

        receipt = discover_and_load_selected(
            hermes_source=hermes_source,
            python=python,
            hermes_root=hermes_home,
            profile_id="default",
            skill_ids=skill_ids,
            timeout=300.0,
        )
    except (NativeInstallError, OSError, ValueError) as exc:
        try:
            rollback_previous_generation()
        except Exception:
            raise ManualJarvisSkillsError(
                "native discovery failed and owned generation rollback needs explicit recovery"
            ) from None
        raise ManualJarvisSkillsError(
            "Hermes did not discover and load the staged Jarvis Resources skills; "
            "the prior owned generation was restored when this was an upgrade"
        ) from None
    if (receipt.hermes_revision != PINNED_HERMES_REVISION
            or not receipt.discovered_profile or not receipt.profile_identity_loaded
            or set(receipt.loaded_skills) != set(skill_ids)
            or any(receipt.content_digests.get(f"skill:{name}") !=
                   _sha256(package_files[f"skills/{name}/SKILL.md"]) for name in skill_ids)):
        try:
            rollback_previous_generation()
        except Exception:
            raise ManualJarvisSkillsError(
                "Hermes discovery receipt failed and owned generation rollback needs explicit recovery"
            ) from None
        raise ManualJarvisSkillsError("Hermes discovery receipt did not cover the pinned primary Resources closure")
    loaded_skill_digests = [
        {"skill_id": name, "sha256": receipt.content_digests[f"skill:{name}"]}
        for name in sorted(skill_ids)
    ]
    other_declarations = len(manifest["bundled_resource_inventory"]) - len(skill_ids) - len(manifest["profile_members"])
    return {
        "state": "discovered",
        "materialized": True,
        "discovered": True,
        "artifact_sha256": expected_sha256,
        "generation_path": staged["generation_path"],
        "primary_native_home": "default",
        "selectable_profile_mutations": [],
        "resource_counts": {
            "native_skills": len(skill_ids),
            "internal_profiles": len(manifest["profile_members"]) - 1,
            "source_profiles_preserved": len(manifest["profile_members"]),
            "other_declarations_preserved": other_declarations,
        },
        "native_receipt": {
            "hermes_revision": receipt.hermes_revision,
            "python_version": receipt.python_version,
            "profile_id": receipt.profile_id,
            "profile_identity_loaded": receipt.profile_identity_loaded,
            "loaded_skill_count": len(receipt.loaded_skills),
            "loaded_skill_inventory_sha256": _sha256(_canonical_json(loaded_skill_digests)),
            "active_primary_prompt_sha256": receipt.content_digests.get("profile:default"),
            "bundled_primary_prompt_sha256": _sha256(package_files["registry/profiles/hermes/SOUL.md"]),
            "active_prompt_matches_bundled_primary": (
                receipt.content_digests.get("profile:default") ==
                _sha256(package_files["registry/profiles/hermes/SOUL.md"])),
        },
        "effective_overlay": manifest["effective_overlay"],
        "previous_generation_backup": staged.get("previous_generation_backup"),
        "functional": False,
        "enabled": False,
        "target_verified": False,
        "pending": [
            "Native discovery and content loading are verified; actual model-selected skill use and external effects remain unverified.",
            "The 207 secondary identities and all 208 compiled prompt records are retained under the private registry namespace; only the existing default profile remains selectable.",
            "The user's existing SOUL.md is preserved; a false active_prompt_matches_bundled_primary means the source Jarvis prompt remains internal until a safe ownership-aware prompt integration is reviewed.",
            "Non-skill adapters are retained as offline declarations/artifacts but dispatch, enrichment, authentication, and functional effects remain pending.",
        ],
    }


def install_bundled_resources(*, hermes_home: str | Path, hermes_source: str | Path,
                              python: str | Path, replace_owned_from_archive: bytes | None = None,
                              replace_owned_from_sha256: str | None = None) -> dict[str, Any]:
    """Build from the checked-in offline bundle and install through the owned importer."""
    artifact = build_manual_jarvis_skills_artifact()
    return install_and_verify_manual_jarvis_skills(
        artifact,
        hermes_home=hermes_home,
        expected_sha256=_sha256(artifact),
        hermes_source=hermes_source,
        python=python,
        replace_owned_from_archive=replace_owned_from_archive,
        replace_owned_from_sha256=replace_owned_from_sha256,
    )


def build_to_file(destination: str | Path) -> str:
    data = build_manual_jarvis_skills_artifact()
    path = Path(destination)
    if not path.is_absolute():
        raise ManualJarvisSkillsError("artifact output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ManualJarvisSkillsError("refusing to overwrite an existing manual stage artifact")
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        _rename_noreplace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return _sha256(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build the verified manual Jarvis skill artifact")
    build.add_argument("--output", required=True)
    install = sub.add_parser("install", help="stage the artifact into an existing Jarvis Hermes home")
    install.add_argument("--bundle", required=True)
    install.add_argument("--home", required=True)
    install.add_argument("--expected-sha256", required=True)
    install.add_argument("--hermes-source", required=True,
                         help="Exact pinned Hermes source checkout used for native read-back")
    install.add_argument("--python", required=True,
                         help="Official PM-managed Python 3.14 interpreter used for native read-back")
    bundled = sub.add_parser("import-bundled", help="build offline from the checked-in bundle and import as the Hermes home owner")
    bundled.add_argument("--home", required=True)
    bundled.add_argument("--hermes-source", required=True)
    bundled.add_argument("--python", required=True)
    bundled.add_argument("--replace-owned-from-sha256")
    overlay = sub.add_parser("install-overlay", help="replace one exact owner Resources overlay generation")
    overlay.add_argument("--home", required=True)
    overlay.add_argument("--hermes-source", required=True)
    overlay.add_argument("--python", required=True)
    overlay.add_argument("--expected-sha256", required=True)
    overlay.add_argument("--previous-sha256", required=True)
    transition = sub.add_parser(
        "import-helper-transition",
        help="replace only an exact same-materialization installer-helper generation",
    )
    transition.add_argument("--home", required=True)
    transition.add_argument("--next-sha256", required=True)
    transition.add_argument("--previous-sha256", required=True)
    transition.add_argument("--shared-manifest-sha256", required=True)
    transition.add_argument("--shared-materialization-sha256", required=True)
    transition.add_argument("--shared-member-count", required=True, type=int)
    transition.add_argument("--backup-name", required=True)
    restore = sub.add_parser(
        "restore-helper-transition",
        help="restore the exact retained prior generation from an authorized helper transition",
    )
    restore.add_argument("--home", required=True)
    restore.add_argument("--current-sha256", required=True)
    restore.add_argument("--restore-sha256", required=True)
    restore.add_argument("--shared-manifest-sha256", required=True)
    restore.add_argument("--shared-materialization-sha256", required=True)
    restore.add_argument("--shared-member-count", required=True, type=int)
    restore.add_argument("--backup-name", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            digest = build_to_file(args.output)
            print(json.dumps({"state": "built", "path": str(Path(args.output)),
                              "sha256": digest}, sort_keys=True))
        elif args.command == "install":
            bundle = Path(args.bundle)
            if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > _ARTIFACT_LIMIT:
                raise ManualJarvisSkillsError("bundle path is not a bounded regular file")
            result = install_and_verify_manual_jarvis_skills(
                bundle.read_bytes(), hermes_home=args.home,
                expected_sha256=args.expected_sha256,
                hermes_source=args.hermes_source, python=args.python,
            )
        elif args.command == "install-overlay":
            incoming = sys.stdin.buffer.read(2 * _ARTIFACT_LIMIT + 16 + 1)
            if len(incoming) < 16 or len(incoming) > 2 * _ARTIFACT_LIMIT + 16:
                raise ManualJarvisSkillsError("overlay transaction input is outside its bound")
            next_size, previous_size = struct.unpack(">QQ", incoming[:16])
            if (not 0 < next_size <= _ARTIFACT_LIMIT or not 0 < previous_size <= _ARTIFACT_LIMIT
                    or len(incoming) != 16 + next_size + previous_size):
                raise ManualJarvisSkillsError("overlay transaction framing differs")
            next_archive = incoming[16:16 + next_size]
            previous_archive = incoming[16 + next_size:]
            result = install_and_verify_manual_jarvis_skills(
                next_archive, hermes_home=args.home, expected_sha256=args.expected_sha256,
                hermes_source=args.hermes_source, python=args.python,
                replace_owned_from_archive=previous_archive,
                replace_owned_from_sha256=args.previous_sha256)
        elif args.command == "import-helper-transition":
            target = _verify_helper_transition_origin(args)
            incoming = sys.stdin.buffer.read(2 * _ARTIFACT_LIMIT + 16 + 1)
            if len(incoming) < 16 or len(incoming) > 2 * _ARTIFACT_LIMIT + 16:
                raise ManualJarvisSkillsError("helper-only transition input is outside its bound")
            next_size, previous_size = struct.unpack(">QQ", incoming[:16])
            if (not 0 < next_size <= _ARTIFACT_LIMIT
                    or not 0 < previous_size <= _ARTIFACT_LIMIT
                    or len(incoming) != 16 + next_size + previous_size):
                raise ManualJarvisSkillsError("helper-only transition framing differs")
            next_archive = incoming[16:16 + next_size]
            previous_archive = incoming[16 + next_size:]
            old_manifest, old_files, _old_helper = _read_transition_archive(
                previous_archive, args.previous_sha256)
            new_manifest, new_files, new_helper = _read_transition_archive(
                next_archive, args.next_sha256)
            if (not verify_same_materialization_transition(
                    old_manifest, old_files, new_manifest, new_files)
                    or new_helper != Path(__file__).read_bytes()):
                raise ManualJarvisSkillsError(
                    "archives are not the exact reviewed helper-only transition")
            _verify_helper_transition_origin(args)
            _verify_owned_generation(target, old_files, args.previous_sha256)
            result = install_same_materialization_transition(
                next_archive, previous_archive, hermes_home=args.home,
                next_sha256=args.next_sha256, previous_sha256=args.previous_sha256,
                shared_manifest_sha256=args.shared_manifest_sha256,
                shared_materialization_sha256=args.shared_materialization_sha256,
                shared_member_count=args.shared_member_count,
                backup_name=args.backup_name)
        elif args.command == "restore-helper-transition":
            target = _verify_helper_transition_origin(args)
            incoming = sys.stdin.buffer.read(2 * _ARTIFACT_LIMIT + 16 + 1)
            if len(incoming) < 16 or len(incoming) > 2 * _ARTIFACT_LIMIT + 16:
                raise ManualJarvisSkillsError("helper-only restore input is outside its bound")
            current_size, restore_size = struct.unpack(">QQ", incoming[:16])
            if (not 0 < current_size <= _ARTIFACT_LIMIT
                    or not 0 < restore_size <= _ARTIFACT_LIMIT
                    or len(incoming) != 16 + current_size + restore_size):
                raise ManualJarvisSkillsError("helper-only restore framing differs")
            current_archive = incoming[16:16 + current_size]
            restore_archive = incoming[16 + current_size:]
            current_manifest, current_files, _current_helper = _read_transition_archive(
                current_archive, args.current_sha256)
            _verify_helper_transition_origin(args)
            _verify_owned_generation(target, current_files, args.current_sha256)
            result = restore_same_materialization_generation(
                current_archive, restore_archive, hermes_home=args.home,
                current_sha256=args.current_sha256,
                restore_sha256=args.restore_sha256,
                backup_name=args.backup_name,
                shared_manifest_sha256=args.shared_manifest_sha256,
                shared_materialization_sha256=args.shared_materialization_sha256,
                shared_member_count=args.shared_member_count)
        else:
            previous_archive = None
            previous_sha256 = args.replace_owned_from_sha256
            if previous_sha256 is not None:
                if previous_sha256 != LEGACY_MATERIALIZED_ARTIFACT_SHA256:
                    raise ManualJarvisSkillsError("only the exact enrolled legacy generation can be migrated")
                previous_archive = sys.stdin.buffer.read(_ARTIFACT_LIMIT + 1)
                if len(previous_archive) > _ARTIFACT_LIMIT:
                    raise ManualJarvisSkillsError("previous owned artifact exceeds its bounded input")
            result = install_bundled_resources(
                hermes_home=args.home,
                hermes_source=args.hermes_source,
                python=args.python,
                replace_owned_from_archive=previous_archive,
                replace_owned_from_sha256=previous_sha256,
            )
        if args.command != "build":
            print(json.dumps(result, sort_keys=True))
    except (ManualJarvisSkillsError, OSError) as exc:
        parser.exit(2, f"manual Jarvis skill stage refused: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
