"""Load selected native adapters only from the root-mounted HI08 closure.

The only filesystem location this module accepts is the deterministic target
derived from the peer-bound no-argument package binder.  The mount itself must
already exist in the service namespace; this module cannot create or select a
mount.  Package and resolver metadata remain presentation only, and every
effect is re-authorized by the root broker.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
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
_MAX_ENTRYPOINT_BYTES = 32 * 1024 * 1024
_MAX_CLOSURE_FILES = 200_000
_MAX_CLOSURE_BYTES = 4 * 1024 * 1024 * 1024


class NativePluginLoadUnavailable(PermissionError):
    """Selected package mount, manifest, or adapter source is unavailable."""


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


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise NativePluginLoadUnavailable("native manifest contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise NativePluginLoadUnavailable("native manifest path escapes its closure")
    if path.as_posix() != value:
        raise NativePluginLoadUnavailable("native manifest path is not normalized")
    return value


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


def _manifest(raw: bytes, *, selected: RootSelectedPluginEffects) -> dict[str, Any]:
    value = _json_document(raw, maximum=_MAX_ENTRYPOINT_BYTES, label="native entrypoint manifest")
    if set(value) != {"schema", "package_id", "profile_id", "generation", "closure_files", "adapters", "dependencies"}:
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

    adapters = value["adapters"]
    dependencies = value["dependencies"]
    if not isinstance(adapters, list) or not adapters or len(adapters) > 692 or not isinstance(dependencies, list):
        raise NativePluginLoadUnavailable("native adapter or dependency list is malformed")
    adapter_ids: set[str] = set()
    module_names: set[str] = set()
    for row in adapters:
        fields = {"adapter_id", "relative_module_path", "module_name", "entrypoint_symbol",
                  "artifact_sha256", "allowed_internal_modules", "allowed_dependency_artifact_ids", "action_ids"}
        if not isinstance(row, dict) or set(row) != fields:
            raise NativePluginLoadUnavailable("native adapter row has unknown or missing fields")
        adapter_id, module_name = row["adapter_id"], row["module_name"]
        relative = _relative_path(row["relative_module_path"])
        if (not isinstance(adapter_id, str) or not _ID.fullmatch(adapter_id) or adapter_id in adapter_ids
                or not isinstance(module_name, str) or not _MODULE.fullmatch(module_name) or module_name in module_names
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
    for adapter in adapters:
        if adapter["adapter_id"] not in by_adapter or set(adapter["action_ids"]) != by_adapter[adapter["adapter_id"]]:
            raise NativePluginLoadUnavailable("native package adapters do not match the root selected resolver")
        if resolver_adapter_by_adapter[adapter["adapter_id"]] != adapter["artifact_sha256"]:
            raise NativePluginLoadUnavailable("native resolver adapter digest differs from the pinned module")
    if set(by_adapter) != adapter_ids:
        raise NativePluginLoadUnavailable("root resolver selected an adapter absent from the pinned manifest")
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

    __slots__ = ("_selection", "mount_target", "entrypoint_sha256", "_adapters")

    def __init__(self, selection: RootSelectedPluginEffects, mount_target: Path,
                 entrypoint_sha256: str, adapters: MappingProxyType) -> None:
        self._selection = selection
        self.mount_target = mount_target
        self.entrypoint_sha256 = entrypoint_sha256
        self._adapters = adapters

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
            _adapter.register(ctx, runtime_context)

        module.register = register
        prepared[adapter_id] = module
    # Publish atomically after every adapter and key has been validated.
    if any(key in predeclared for key in prepared):
        raise NativePluginLoadUnavailable("selected native plugin key collided during loader preparation")
    predeclared.update(prepared)
    return tuple(prepared)


def bind_current_native_plugin_package(authority: object) -> SelectedNativePackage:
    """Bind, verify and import only the root-selected closure for this process.

    This does not create an invocation context or grant. The caller must obtain
    the runtime context from the enrolled root context adapter before calling a
    selected adapter's ``register`` method.
    """
    selection = bind_selected_plugin_effects(authority)
    target = selected_mount_target(selection.package_id, selection.profile_id,
                                   selection.generation, selection.compiled_closure_sha256)
    try:
        _require_private_readonly_mount(target, Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
        root = target.resolve(strict=True)
        if root != target or root.is_symlink() or not root.is_dir():
            raise NativePluginLoadUnavailable("root-selected native mount target is not a fixed directory")
        raw_manifest = _read_regular_nofollow(root / "manifest.json", maximum=_MAX_ENTRYPOINT_BYTES)
        manifest = _manifest(raw_manifest, selected=selection)
        modules = _verify_closure(root, manifest)
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
                resolver_manifest_by_adapter[adapter_id], entrypoint,
            )
        return SelectedNativePackage(selection, target, selection.entrypoint_sha256,
                                     MappingProxyType(loaded))
    except NativePluginBindingUnavailable as exc:
        raise NativePluginLoadUnavailable("root native package binding is unavailable") from None
    except NativePluginLoadUnavailable:
        raise
    except OSError:
        raise NativePluginLoadUnavailable("root native package mount is unavailable") from None
