"""Root-owned fixed build result custody and attestation (HW-T03).

Worker input is restricted to one reviewed operation identifier, generation,
and the empty parameter object. A root composition resolves pinned artifacts
and invokes its managed build-job launcher. This module validates the terminal
isolation/exit receipt and atomically publishes a complete digest-checked tree
to a private CAS. Runtime composition owns handler registration; `handlers()`
exposes only fixed target IDs for which a target-fact inspector is qualified.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import platform
import re
import secrets
import stat
import sys
import time
import base64
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest

BUILD_ATTESTATION_STORE = Path("/var/lib/hermes-installer/build-attestations")
MAX_OUTPUT_FILES = 512
MAX_OUTPUT_BYTES = 2 * 1024**3
BUILD_MOUNT_TARGETS = {
    "builder": "/run/hermes-installer/build/builder",
    "source": "/run/hermes-installer/build/source",
    "toolchain": "/run/hermes-installer/build/toolchain",
    "work": "/run/hermes-installer/build/work",
    "output": "/run/hermes-installer/build/output",
}
OPERATION_TARGETS = {
    "coral-cpython39-source-build-v1": "coral-cpython-build:start",
    "colibri-source-build-v1": "colibri-source-build:start",
}
REQUIRED_LIMITS = {
    "PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
    "NoNewPrivileges": "yes", "ProtectSystem": "strict",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise AuthorityDenied("build.digest", f"{label} digest is invalid")
    return value


def managed_process_identity_digest(*, process_id: str, generation: str, uid: int, pid: int,
                                    start_ticks: int, cgroup_id: str,
                                    mount_namespace_inode: int,
                                    network_namespace_inode: int) -> str:
    return hashlib.sha256(_canonical({
        "process_id": process_id, "generation": generation, "uid": uid, "pid": pid,
        "start_ticks": start_ticks, "cgroup_id": cgroup_id,
        "mount_namespace_inode": mount_namespace_inode,
        "network_namespace_inode": network_namespace_inode,
    })).hexdigest()


def _safe_output_name(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AuthorityDenied("build.output", "build output name is invalid")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise AuthorityDenied("build.output", "build output name escapes its enrolled output root")
    return path.as_posix()


def _resolve_argv_recipe(value: Any) -> tuple[Mapping[str, Any], ...]:
    """Validate Sol's strict tagged argv grammar before a runner sees it."""
    if not isinstance(value, (tuple, list)) or not value or len(value) > 128:
        raise AuthorityDenied("build.argv", "protected build argv recipe is malformed")
    result = []
    for node in value:
        if not isinstance(node, Mapping):
            raise AuthorityDenied("build.argv", "build argv nodes must use the tagged protected grammar")
        if set(node) == {"literal"}:
            literal = node["literal"]
            if (not isinstance(literal, str) or "\x00" in literal or "\n" in literal
                    or "\r" in literal or len(literal) > 4096):
                raise AuthorityDenied("build.argv", "protected build literal is invalid")
            result.append({"literal": literal})
            continue
        if set(node) != {"build_path"} or not isinstance(node["build_path"], Mapping):
            raise AuthorityDenied("build.argv", "build argv node has unknown tags or fields")
        item = node["build_path"]
        if set(item) != {"mount_id", "relative_path"}:
            raise AuthorityDenied("build.argv", "build path node fields are invalid")
        mount_id, relative_path = item["mount_id"], item["relative_path"]
        if (not isinstance(mount_id, str) or mount_id not in BUILD_MOUNT_TARGETS
                or not isinstance(relative_path, str)):
            raise AuthorityDenied("build.argv", "build path mount is not an enrolled fixed mount")
        if relative_path:
            if _safe_output_name(relative_path) != relative_path:
                raise AuthorityDenied("build.argv", "build path is not normalized")
        result.append({"build_path": {"mount_id": mount_id, "relative_path": relative_path}})
    first = result[0]
    if first != {"build_path": {"mount_id": "builder", "relative_path": ""}}:
        raise AuthorityDenied("build.argv", "argv[0] must resolve to the enrolled builder executable mount")
    return tuple(result)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _recipe_digest(profile: Any) -> str:
    return hashlib.sha256(_canonical({
        "target_id": profile.target_id, "generation": profile.generation,
        "build_service_enrollment_id": profile.build_service_enrollment_id,
        "build_service_generation": profile.build_service_generation,
        "source_artifact_id": profile.source_artifact_id, "source_sha256": profile.source_sha256,
        "toolchain_artifact_id": profile.toolchain_artifact_id,
        "toolchain_sha256": profile.toolchain_sha256,
        "builder_artifact_id": profile.builder_artifact_id, "builder_sha256": profile.builder_sha256,
        "argv_recipe": _plain(profile.argv_recipe), "environment": dict(profile.environment),
        "max_lifetime_seconds": profile.max_lifetime_seconds,
        "service_generation_digest": profile.service_generation_digest,
        "output_specs": {
            name: {"relative_path": item.relative_path, "kind": item.kind,
                  "maximum_bytes": item.maximum_bytes, "executable_role": item.executable_role,
                  "target_facts": _plain(item.target_facts)}
            for name, item in sorted(profile.output_specs.items())
        },
    })).hexdigest()


@dataclass(frozen=True, slots=True)
class ResolvedBuildInputs:
    target_id: str
    generation: str
    service_generation_digest: str
    build_service_enrollment_id: str
    build_service_generation: str
    enrollment_id: str
    operation_id: str
    selection_digest: str
    source_artifact_id: str
    source_sha256: str
    source_root: Path
    source_tree_files: tuple[Any, ...]
    source_tree_manifest_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    toolchain_root: Path
    toolchain_tree_files: tuple[Any, ...]
    toolchain_tree_manifest_sha256: str
    builder_artifact_id: str
    builder_sha256: str
    builder_executable: Path
    argv_recipe: tuple[Mapping[str, Any], ...]
    environment: Mapping[str, str]
    output_specs: Mapping[str, BuildOutputSpec]
    output_root: Path
    output_root_id: str
    output_owner_uid: int
    max_lifetime_seconds: int


@dataclass(frozen=True, slots=True)
class ManagedBuildResult:
    """Terminal receipt emitted only by the root managed build-job launcher."""
    process_id: str
    generation: str
    uid: int
    pid: int
    start_ticks: int
    exit_code: int | None
    timed_out: bool
    cancelled: bool
    cleanup_verified: bool
    started_monotonic: float
    finished_monotonic: float
    kernel_limits: Mapping[str, str]
    terminal_success_record_id: str = ""
    process_identity_digest: str = ""
    cgroup_id: str = ""
    mount_namespace_inode: int = 0
    network_namespace_inode: int = 0
    bounded_log_digest: str = ""
    log_bytes: int = 0


class FixedBuildCatalog(Protocol):
    def resolve(self, target_id: str, generation: str) -> Any: ...


class FixedBuildJobLauncher(Protocol):
    """Root-owned managed process boundary; worker adapters cannot supply it."""
    def run_selected_build(self, inputs: ResolvedBuildInputs, *, context: HostContext,
                           authorization: EffectAuthorization, peer_pid: int,
                           peer_pidfd: int, timeout: float,
                           cancelled: Callable[[], bool]) -> ManagedBuildResult: ...


@dataclass(frozen=True, slots=True)
class BuildOutputSpec:
    """Finite root-enrolled output constraint; output digests are observed later."""
    relative_path: str
    kind: str
    maximum_bytes: int
    executable_role: str
    target_facts: Mapping[str, Any]

    def __post_init__(self) -> None:
        _safe_output_name(self.relative_path)
        if (self.kind not in {"file", "tree"} or type(self.maximum_bytes) is not int
                or not 1 <= self.maximum_bytes <= MAX_OUTPUT_BYTES
                or not isinstance(self.executable_role, str) or not self.executable_role
                or not isinstance(self.target_facts, Mapping) or not self.target_facts):
            raise AuthorityDenied("build.output_spec", "protected output constraint is invalid")

    @property
    def path(self) -> str:
        return self.relative_path


@dataclass(frozen=True, slots=True)
class BuildOutput:
    relative_path: str
    kind: str
    sha256: str
    size_bytes: int
    executable_role: str
    observed_target_facts: Mapping[str, Any]
    tree_file_manifest_sha256: str | None = None

    @property
    def name(self) -> str:
        return self.relative_path

    @property
    def artifact_id(self) -> str:
        if self.kind == "tree":
            return f"build-output:{self.sha256}:tree"
        suffix = "x" if self.executable else "d"
        return f"build-output:{self.sha256}:file:{suffix}"

    @property
    def executable(self) -> bool:
        return self.kind == "file" and self.executable_role != "data"

    def to_wire(self) -> dict[str, Any]:
        return {"relative_path": self.relative_path, "kind": self.kind,
                "sha256": self.sha256, "size_bytes": self.size_bytes,
                "executable_role": self.executable_role,
                "observed_target_facts": _plain(self.observed_target_facts),
                "tree_file_manifest_sha256": self.tree_file_manifest_sha256}


class BuildOutputFactInspector(Protocol):
    """Root-owned observer of ELF, interpreter ABI and resolved library facts."""
    def inspect(self, profile: Any, spec: Any, path: Path) -> Mapping[str, Any]: ...


class RootManagedPythonProbe(Protocol):
    """Executes only the enrolled output interpreter through an isolated root-managed probe."""
    def inspect_cpython39(self, profile: Any, executable: Path) -> Mapping[str, Any]: ...


class ProtectedBuildArtifactRootResolver:
    """Resolve inspector inputs only from the immutable protected artifact catalog.

    The build runner and inspector intentionally resolve the same pinned source
    and toolchain independently: the runner binds their verified trees into
    read-only mounts, while post-exit inspection rechecks catalog membership
    and bytes before trusting source recipes or shared-library closures.
    """

    def __init__(self, artifact_catalog: Any, staging_root: Path, *, owner_uid: int = 0):
        if (not isinstance(staging_root, Path) or not staging_root.is_absolute()
                or type(owner_uid) is not int or owner_uid < 0
                or not callable(getattr(artifact_catalog, "resolve", None))
                or not callable(getattr(artifact_catalog, "materialize_tree", None))
                or not isinstance(getattr(artifact_catalog, "artifacts", None), Mapping)):
            raise AuthorityDenied("build.artifact_resolver", "root protected artifact resolver is unavailable")
        self.artifact_catalog = artifact_catalog
        self.staging_root = staging_root
        self.owner_uid = owner_uid

    def _resolve(self, artifact_id: str, digest: str) -> Path:
        spec = self.artifact_catalog.artifacts.get(artifact_id)
        if spec is None or spec.sha256 != digest:
            raise AuthorityDenied("build.artifact", "inspector artifact differs from protected build pins")
        try:
            resolved = (self.artifact_catalog.materialize_tree(
                artifact_id, digest, self.staging_root, expected_uid=self.owner_uid)
                if spec.tree_files else self.artifact_catalog.resolve(
                    artifact_id, digest, self.staging_root, expected_uid=self.owner_uid))
            path = Path(resolved.path)
            info = path.lstat()
            if (path != path.resolve(strict=True)
                    or (spec.tree_files and not stat.S_ISDIR(info.st_mode))
                    or (not spec.tree_files and not stat.S_ISREG(info.st_mode))
                    or info.st_uid != self.owner_uid or info.st_mode & 0o222):
                raise ValueError("artifact root custody")
            return path
        except Exception:
            raise AuthorityDenied("build.artifact", "pinned source or toolchain cannot be re-resolved") from None

    def source_root(self, profile: Any) -> Path:
        return self._resolve(profile.source_artifact_id, profile.source_sha256)

    def toolchain_root(self, profile: Any) -> Path:
        return self._resolve(profile.toolchain_artifact_id, profile.toolchain_sha256)


class LinuxBuildOutputFactInspector:
    """Read-only ELF/sysconfig and isolated runtime inspector for ARM64 outputs."""
    def __init__(self, *, toolchain_root_resolver: Callable[[Any], Path],
                 source_root_resolver: Callable[[Any], Path], runtime_probe: RootManagedPythonProbe | None,
                 owner_uid: int = 0):
        if (not callable(toolchain_root_resolver) or not callable(source_root_resolver)
                or (runtime_probe is not None
                    and not callable(getattr(runtime_probe, "inspect_cpython39", None)))
                or type(owner_uid) is not int):
            raise AuthorityDenied("build.inspector", "root source/toolchain resolvers and managed runtime probe are required")
        self.toolchain_root_resolver = toolchain_root_resolver
        self.source_root_resolver = source_root_resolver
        self.runtime_probe = runtime_probe
        self.owner_uid = owner_uid

    @staticmethod
    def _elf(path: Path) -> tuple[dict[str, Any], tuple[str, ...]]:
        try:
            data = path.read_bytes()
        except OSError:
            raise AuthorityDenied("build.elf", "native output cannot be read") from None
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise AuthorityDenied("build.elf", "native output is not little-endian ELF64")
        machine = int.from_bytes(data[18:20], "little")
        if data[7] not in {0, 3}:
            raise AuthorityDenied("build.elf", "ELF OS ABI is not Linux compatible")
        phoff = int.from_bytes(data[32:40], "little")
        phentsize = int.from_bytes(data[54:56], "little")
        phnum = int.from_bytes(data[56:58], "little")
        if machine != 183 or phentsize < 56 or phnum > 4096 or phoff + phentsize * phnum > len(data):
            raise AuthorityDenied("build.elf", "ELF machine or program-header table is invalid")
        segments = []
        dynamic = None
        for index in range(phnum):
            offset = phoff + index * phentsize
            p_type = int.from_bytes(data[offset:offset + 4], "little")
            p_offset = int.from_bytes(data[offset + 8:offset + 16], "little")
            p_vaddr = int.from_bytes(data[offset + 16:offset + 24], "little")
            p_filesz = int.from_bytes(data[offset + 32:offset + 40], "little")
            if p_offset + p_filesz > len(data):
                raise AuthorityDenied("build.elf", "ELF segment exceeds the file bounds")
            if p_type == 1:
                segments.append((p_vaddr, p_offset, p_filesz))
            elif p_type == 2:
                dynamic = (p_offset, p_filesz)
        needed: list[str] = []
        if dynamic is not None:
            dyn_offset, dyn_size = dynamic
            string_address = string_size = None
            dynamic_rows = []
            for offset in range(dyn_offset, dyn_offset + dyn_size, 16):
                if offset + 16 > len(data):
                    raise AuthorityDenied("build.elf", "ELF dynamic table is truncated")
                tag = int.from_bytes(data[offset:offset + 8], "little", signed=True)
                value = int.from_bytes(data[offset + 8:offset + 16], "little")
                if tag == 0:
                    break
                dynamic_rows.append((tag, value))
                if tag == 5:
                    string_address = value
                elif tag == 10:
                    string_size = value
            if string_address is not None and string_size is not None:
                string_offset = None
                for vaddr, offset, file_size in segments:
                    if vaddr <= string_address < vaddr + file_size:
                        string_offset = offset + string_address - vaddr
                        break
                if string_offset is None or string_offset + string_size > len(data):
                    raise AuthorityDenied("build.elf", "ELF dynamic string table is outside load segments")
                strings = data[string_offset:string_offset + string_size]
                for tag, value in dynamic_rows:
                    if tag != 1:
                        continue
                    if value >= len(strings):
                        raise AuthorityDenied("build.elf", "ELF dependency name is invalid")
                    end = strings.find(b"\0", value)
                    if end < 0:
                        raise AuthorityDenied("build.elf", "ELF dependency name is unterminated")
                    needed.append(strings[value:end].decode("ascii"))
        return {"elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux"}, tuple(needed)

    @staticmethod
    def _safe_toolchain_path(root: Path, candidate: Path, owner_uid: int) -> Path:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve(strict=True)):
            raise AuthorityDenied("build.dependency", "native library resolves outside the pinned sysroot")
        info = resolved.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o222:
            raise AuthorityDenied("build.dependency", "native library is not immutable root-owned input")
        return resolved

    def _resolve_library(self, root: Path, name: str) -> Path:
        matches = []
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            if name in files or (Path(current) / name).is_symlink():
                try:
                    matches.append(self._safe_toolchain_path(root, Path(current) / name, self.owner_uid))
                except (OSError, AuthorityDenied):
                    continue
        if len(set(matches)) != 1:
            raise AuthorityDenied("build.dependency", "native dependency is missing or ambiguous in the pinned sysroot")
        return matches[0]

    def _dependency_closure(self, root: Path, direct: tuple[str, ...]) -> list[dict[str, str]]:
        pending = list(direct)
        observed = {}
        while pending:
            name = pending.pop()
            if name in observed or name.startswith("linux-vdso"):
                continue
            library = self._resolve_library(root, name)
            facts, needed = self._elf(library)
            info = library.lstat()
            observed[name] = {"name": name, "absolute_path": str(library),
                              "sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                              "owner_uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}
            pending.extend(needed)
        return [observed[name] for name in sorted(observed)]

    @staticmethod
    def _python_config(tree: Path) -> Mapping[str, Any]:
        candidates = list(tree.glob("_sysconfigdata_*.py"))
        if len(candidates) != 1:
            raise AuthorityDenied("build.python_abi", "CPython sysconfig data is missing or ambiguous")
        import ast
        try:
            module = ast.parse(candidates[0].read_text(encoding="utf-8"))
            values = None
            for statement in module.body:
                if isinstance(statement, ast.Assign) and any(
                        isinstance(target, ast.Name) and target.id == "build_time_vars"
                        for target in statement.targets):
                    values = ast.literal_eval(statement.value)
                    break
            if not isinstance(values, dict):
                raise ValueError("build_time_vars")
            return values
        except (OSError, UnicodeError, SyntaxError, ValueError):
            raise AuthorityDenied("build.python_abi", "CPython sysconfig data is not literal protected data") from None

    @staticmethod
    def _version_at_least(value: str, required: tuple[int, int]) -> bool:
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)(?:\.[0-9]+)?", value)
        return bool(match and (int(match.group(1)), int(match.group(2))) >= required)

    def _verify_colibri_recipe(self, profile: Any) -> None:
        source_root = Path(self.source_root_resolver(profile)).resolve(strict=True)
        expected = {
            "c/Makefile": "10666421bde71dabbe69f02624434c477321caae655144c2057814182b6e7604",
            "c/setup.sh": "1f1b7e8fdc727cc1d37e31403e949de3ae869e5add6eac963bcd8822330492cb",
        }
        for relative, digest in expected.items():
            path = source_root / relative
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o222:
                raise AuthorityDenied("build.source_evidence", "pinned Colibri build source is not immutable root-owned content")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AuthorityDenied("build.source_evidence", "Colibri build recipe source does not match reviewed pins")
        recipe_text = (source_root / "c/Makefile").read_text(encoding="utf-8").lower()
        setup_text = (source_root / "c/setup.sh").read_text(encoding="utf-8").lower()
        if "aarch64" not in recipe_text or "-fopenmp" not in recipe_text + setup_text:
            raise AuthorityDenied("build.source_evidence", "Colibri ARM64/OpenMP build branch is absent")
        unsafe = ("-march=native", "-mcpu=native", "-mtune=native", "-mavx", "-msse", "-mavx2")
        invocation_values = [
            node["literal"] for node in profile.argv_recipe
            if isinstance(node, Mapping) and set(node) == {"literal"}
        ] + list(profile.environment.values())
        if any(any(flag in value.lower() for flag in unsafe) for value in [*invocation_values, recipe_text, setup_text]):
            raise AuthorityDenied("build.source_evidence", "build recipe enables unmeasured host CPU instructions")
        build_text = recipe_text + " " + setup_text + " " + " ".join(invocation_values)
        selected_arch_flags = re.findall(r"-(?:march|mcpu|mtune)=([^\s\"']+)", build_text)
        if any(flag != "armv8-a" for flag in selected_arch_flags):
            raise AuthorityDenied("build.source_evidence", "build recipe uses an unmeasured ARM CPU feature level")
        if sys.platform != "linux" or platform.machine().lower() not in {"aarch64", "arm64"}:
            raise AuthorityDenied("build.target", "native Colibri build requires the enrolled Linux ARM64 host")

    def inspect(self, profile: Any, spec: Any, path: Path) -> Mapping[str, Any]:
        sysroot = Path(self.toolchain_root_resolver(profile)).resolve(strict=True)
        if spec.relative_path == "c/colibri":
            self._verify_colibri_recipe(profile)
            facts, needed = self._elf(path)
            closure = self._dependency_closure(sysroot, needed)
            names = sorted({entry["name"] for entry in closure})
            if not {"libgomp.so.1", "libm.so.6", "libc.so.6"}.issubset(names):
                raise AuthorityDenied("build.dependency", "Colibri runtime dependency closure is incomplete")
            return {**facts, "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                    "resolved_dependency_closure": closure,
                    "instruction_policy": "actual target compatible ARM64 flags; no x86 default or unmeasured CPUflags"}
        if spec.relative_path == "runtime/bin/python3.9":
            if self.runtime_probe is None:
                raise AuthorityDenied("build.python_probe", "root-managed CPython ABI probe is unavailable")
            if sys.platform != "linux" or platform.machine().lower() not in {"aarch64", "arm64"}:
                raise AuthorityDenied("build.target", "CPython output probe requires Linux ARM64")
            facts, needed = self._elf(path)
            tree = path.parent.parent / "lib/python3.9"
            config = self._python_config(tree)
            if config.get("SOABI") != "cpython-39-aarch64-linux-gnu" or config.get("Py_DEBUG") not in {0, False}:
                raise AuthorityDenied("build.python_abi", "built CPython sysconfig ABI is not the enrolled nondebug ABI")
            closure = self._dependency_closure(sysroot, needed)
            try:
                runtime = self.runtime_probe.inspect_cpython39(profile, path)
            except Exception:
                raise AuthorityDenied("build.python_abi", "root-managed CPython runtime probe failed") from None
            if (not isinstance(runtime, Mapping) or runtime.get("python_version") != "3.9.25"
                    or runtime.get("soabi") != "cpython-39-aarch64-linux-gnu"
                    or runtime.get("debug") is not False
                    or not isinstance(runtime.get("glibc_version"), str)
                    or not self._version_at_least(runtime["glibc_version"], (2, 34))):
                raise AuthorityDenied("build.python_abi", "actual CPython runtime ABI/glibc facts do not satisfy enrollment")
            return {**facts, "python_version": runtime["python_version"], "soabi": runtime["soabi"],
                    "debug": runtime["debug"], "glibc_minimum": "2.34 for selected TFLite wheel",
                    "observed_glibc_version": runtime["glibc_version"],
                    "resolved_dependency_closure": closure}
        if spec.relative_path == "runtime/lib/python3.9":
            tree = path
            extensions = []
            for current, _, files in os.walk(tree, topdown=True, followlinks=False):
                for filename in files:
                    candidate = Path(current) / filename
                    if filename.endswith(".so") or ".so." in filename:
                        facts, needed = self._elf(candidate)
                        closure = self._dependency_closure(sysroot, needed)
                        extensions.append({"relative_path": candidate.relative_to(tree).as_posix(),
                                           **facts,
                                           "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
                                           "resolved_dependency_closure": closure})
            config = self._python_config(tree)
            if config.get("SOABI") != "cpython-39-aarch64-linux-gnu" or config.get("VERSION") not in {"3.9", "3.9.25"}:
                raise AuthorityDenied("build.python_abi", "CPython extension closure is not pinned to 3.9.25 ARM64")
            return {"python_version": "3.9.25", "target": "linux-aarch64",
                    "all_native_extensions": "ELF64EM_AARCH64, actual dependency closure verified",
                    "native_extension_manifest": extensions}
        raise AuthorityDenied("build.output_spec", "no reviewed native fact inspector exists for this output")


@dataclass(frozen=True, slots=True)
class BuildAttestation:
    schema: int
    attestation_id: str
    attestation_sha256: str
    target_id: str
    enrollment_id: str
    generation: str
    operation_id: str
    source_artifact_id: str
    source_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    builder_artifact_id: str
    builder_sha256: str
    recipe_sha256: str
    outputs: tuple[BuildOutput, ...]
    process_id: str
    process_uid: int
    process_pid: int
    process_start_ticks: int
    exit_code: int
    cleanup_verified: bool
    cgroup_id: str
    mount_namespace_inode: int
    network_namespace_inode: int
    started_monotonic: float
    finished_monotonic: float
    kernel_limits: Mapping[str, str]
    service_generation_digest: str
    process_identity_digest: str
    terminal_success_record_id: str
    bounded_log_digest: str
    log_bytes: int
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    @property
    def receipt_id(self) -> str:
        return self.attestation_id

    @property
    def build_target_id(self) -> str:
        return self.target_id

    @property
    def build_generation(self) -> str:
        return self.generation

    @property
    def recipe_digest(self) -> str:
        return self.recipe_sha256

    @property
    def receipt_digest(self) -> str:
        return self.attestation_sha256

    @property
    def root_signature(self) -> str:
        return self.signature

    def unsigned_wire(self) -> dict[str, Any]:
        return {
            "schema": 1, "receipt_id": self.attestation_id,
            "build_target_id": self.target_id, "enrollment_id": self.enrollment_id,
            "build_generation": self.generation, "operation_id": self.operation_id,
            "service_generation_digest": self.service_generation_digest,
            "recipe_digest": self.recipe_sha256,
            "source_artifact_id": self.source_artifact_id, "source_sha256": self.source_sha256,
            "toolchain_artifact_id": self.toolchain_artifact_id,
            "toolchain_sha256": self.toolchain_sha256,
            "builder_artifact_id": self.builder_artifact_id, "builder_sha256": self.builder_sha256,
            "process_identity_digest": self.process_identity_digest,
            "terminal_success_record_id": self.terminal_success_record_id,
            "output_records": [item.to_wire() for item in self.outputs],
            "execution": {"process_id": self.process_id, "uid": self.process_uid,
                          "pid": self.process_pid, "start_ticks": self.process_start_ticks,
                          "exit_code": self.exit_code, "cleanup_verified": self.cleanup_verified,
                          "started_monotonic": self.started_monotonic,
                          "finished_monotonic": self.finished_monotonic,
                          "kernel_limits": dict(self.kernel_limits), "cgroup_id": self.cgroup_id,
                          "mount_namespace_inode": self.mount_namespace_inode,
                          "network_namespace_inode": self.network_namespace_inode,
                          "bounded_log_digest": self.bounded_log_digest, "log_bytes": self.log_bytes},
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        }

    def to_wire(self) -> dict[str, Any]:
        return {**self.unsigned_wire(), "receipt_digest": self.attestation_sha256,
                "root_signature": self.signature}


class ContentAddressedBuildStore:
    """Private immutable file CAS and atomic attestation-record publisher."""
    def __init__(self, root: Path, *, signing_key: bytes, owner_uid: int = 0,
                 maximum_output_bytes: int = MAX_OUTPUT_BYTES):
        if (not isinstance(root, Path) or not root.is_absolute() or type(owner_uid) is not int
                or owner_uid < 0 or type(maximum_output_bytes) is not int
                or not 1 <= maximum_output_bytes <= MAX_OUTPUT_BYTES
                or not isinstance(signing_key, bytes) or len(signing_key) != 32):
            raise AuthorityDenied("build.store", "build store configuration is invalid")
        self.root = root
        self.owner_uid = owner_uid
        self.maximum_output_bytes = maximum_output_bytes
        self._key = hmac.new(signing_key, b"hermes-installer:build-attestation:v1",
                             hashlib.sha256).digest()

    @classmethod
    def root_store(cls, *, authority_key: bytes) -> "ContentAddressedBuildStore":
        return cls(BUILD_ATTESTATION_STORE, signing_key=authority_key, owner_uid=0)

    def publish(self, profile: Any, *, enrollment_id: str, operation_id: str,
                process: ManagedBuildResult, fact_inspector: BuildOutputFactInspector,
                cancelled: Callable[[], bool] = lambda: False,
                output_root: Path | None = None,
                before_activate: Callable[[], None] | None = None) -> BuildAttestation:
        self._require_completed_isolated_process(profile, process)
        observed = self._inspect_complete_output_tree(profile, fact_inspector,
                                                      output_root=output_root)
        if cancelled():
            raise AuthorityDenied("build.expired", "build authorization expired before output publication")
        self._ensure_store()
        outputs_list = []
        for name in sorted(observed):
            row = observed[name]
            if row["kind"] == "file":
                stored = self._publish_output(name, row["sha256"], row["size_bytes"], row["source"],
                                              row["entries"][0]["executable"], cancelled=cancelled)
                outputs_list.append(BuildOutput(name, "file", row["sha256"], row["size_bytes"],
                                                row["executable_role"],
                                                row["observed_target_facts"], None))
            else:
                artifact_id = self._publish_tree(name, row, cancelled=cancelled)
                outputs_list.append(BuildOutput(name, "tree", row["sha256"],
                                                row["size_bytes"], row["executable_role"],
                                                row["observed_target_facts"], row["sha256"]))
        outputs = tuple(outputs_list)
        recipe_digest = _recipe_digest(profile)
        issued = time.monotonic()
        record = BuildAttestation(
            schema=1, attestation_id=secrets.token_urlsafe(24), attestation_sha256="0" * 64,
            target_id=profile.target_id, enrollment_id=enrollment_id, generation=profile.generation,
            operation_id=operation_id, source_artifact_id=profile.source_artifact_id,
            source_sha256=profile.source_sha256, toolchain_artifact_id=profile.toolchain_artifact_id,
            toolchain_sha256=profile.toolchain_sha256, builder_artifact_id=profile.builder_artifact_id,
            builder_sha256=profile.builder_sha256, recipe_sha256=recipe_digest, outputs=outputs,
            process_id=process.process_id, process_uid=process.uid, process_pid=process.pid,
            process_start_ticks=process.start_ticks, exit_code=0, cleanup_verified=True,
            cgroup_id=process.cgroup_id, mount_namespace_inode=process.mount_namespace_inode,
            network_namespace_inode=process.network_namespace_inode,
            started_monotonic=process.started_monotonic, finished_monotonic=process.finished_monotonic,
            kernel_limits=dict(process.kernel_limits),
            service_generation_digest=profile.service_generation_digest,
            process_identity_digest=process.process_identity_digest,
            terminal_success_record_id=process.terminal_success_record_id,
            bounded_log_digest=process.bounded_log_digest, log_bytes=process.log_bytes,
            issued_monotonic=issued, expires_monotonic=issued + min(600, profile.max_lifetime_seconds),
            signature="",
        )
        digest = hashlib.sha256(_canonical(record.unsigned_wire())).hexdigest()
        record = replace(record, attestation_sha256=digest)
        signature = hmac.new(self._key, _canonical(record.to_wire() | {"root_signature": ""}),
                             hashlib.sha256).hexdigest()
        record = replace(record, signature=signature)
        self._publish_attestation(record, cancelled=cancelled)
        if before_activate is not None:
            before_activate()
        self._publish_current(record, cancelled=cancelled)
        return record

    def resolve(self, profile: Any) -> BuildAttestation:
        """Load and cryptographically verify the current receipt for a fixed profile."""
        self._ensure_store()
        index = self._read_protected_json(self._index_path(profile.target_id, profile.generation))
        if (not isinstance(index, dict) or set(index) != {"schema", "target_id", "generation",
                                                           "attestation_id", "attestation_sha256"}
                or index["schema"] != 1 or index["target_id"] != profile.target_id
                or index["generation"] != profile.generation):
            raise AuthorityDenied("build.attestation", "current build receipt index is invalid")
        record_path = self.root / "attestations" / (index["attestation_id"] + ".json")
        record = self._parse_attestation(self._read_protected_json(record_path))
        self._verify_attestation(record, profile)
        if record.attestation_sha256 != index["attestation_sha256"]:
            raise AuthorityDenied("build.attestation", "current receipt index digest does not match")
        return record

    def resolve_output(self, profile: Any, relative_path: str) -> Path:
        """Resolve one enrolled output path only through the current signed receipt."""
        record = self.resolve(profile)
        output = next((item for item in record.outputs if item.relative_path == relative_path), None)
        if output is None:
            raise AuthorityDenied("build.output_id", "output path is outside the current build receipt")
        return self.resolve_output_object(output)

    def attest_outputs(self, profile: Any) -> Mapping[str, str]:
        """Return the verified path-to-digest projection for root runtime binding."""
        record = self.resolve(profile)
        return {item.name: item.sha256 for item in record.outputs}

    def _require_completed_isolated_process(self, profile: Any,
                                            process: ManagedBuildResult) -> None:
        if not isinstance(process, ManagedBuildResult):
            raise AuthorityDenied("build.process", "managed build completion receipt is missing")
        now = time.monotonic()
        limits = dict(process.kernel_limits)
        if (not process.process_id or process.generation != profile.generation
                or process.uid != profile.output_owner_uid or process.pid <= 1
                or process.start_ticks <= 0 or process.exit_code != 0
                or process.timed_out or process.cancelled or not process.cleanup_verified
                or not process.terminal_success_record_id
                or process.process_identity_digest != managed_process_identity_digest(
                    process_id=process.process_id, generation=process.generation, uid=process.uid,
                    pid=process.pid, start_ticks=process.start_ticks, cgroup_id=process.cgroup_id,
                    mount_namespace_inode=process.mount_namespace_inode,
                    network_namespace_inode=process.network_namespace_inode)
                or not isinstance(process.cgroup_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,512}", process.cgroup_id)
                or type(process.mount_namespace_inode) is not int or process.mount_namespace_inode <= 0
                or type(process.network_namespace_inode) is not int or process.network_namespace_inode <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", process.bounded_log_digest)
                or type(process.log_bytes) is not int or not 0 <= process.log_bytes <= 1024 * 1024
                or not 0 < process.started_monotonic <= process.finished_monotonic <= now
                or process.finished_monotonic - process.started_monotonic > profile.max_lifetime_seconds
                or set(limits) != set(REQUIRED_LIMITS)
                or any(limits.get(key) != value for key, value in REQUIRED_LIMITS.items())):
            raise AuthorityDenied("build.process", "build process did not complete within its isolated lease")

    @staticmethod
    def _fact_matches(required: Any, observed: Any) -> bool:
        if isinstance(required, Mapping):
            return isinstance(observed, Mapping) and all(
                key in observed and ContentAddressedBuildStore._fact_matches(value, observed[key])
                for key, value in required.items())
        if isinstance(required, (list, tuple)):
            return isinstance(observed, (list, tuple)) and all(value in observed for value in required)
        return type(required) is type(observed) and required == observed

    def _inspect_complete_output_tree(self, profile: Any,
                                     inspector: BuildOutputFactInspector,
                                     *, output_root: Path | None = None) -> dict[str, dict[str, Any]]:
        root = Path(output_root if output_root is not None else profile.output_root)
        self._check_owned_directory(root, profile.output_owner_uid, mode=0o700)
        try:
            specs = dict(profile.output_specs)
        except (AttributeError, TypeError):
            raise AuthorityDenied("build.output_spec", "root-enrolled output constraints are unavailable") from None
        if not specs or len(specs) > MAX_OUTPUT_FILES or not callable(getattr(inspector, "inspect", None)):
            raise AuthorityDenied("build.output_spec", "protected output constraints or fact inspector are unavailable")
        normalized = {}
        for name, raw in specs.items():
            try:
                spec = BuildOutputSpec(raw.relative_path, raw.kind, raw.maximum_bytes,
                                       raw.executable_role, raw.target_facts)
            except Exception:
                raise AuthorityDenied("build.output_spec", "protected output constraint is malformed") from None
            if name != spec.relative_path:
                raise AuthorityDenied("build.output_spec", "output constraint key differs from its path")
            normalized[name] = spec
        names = sorted(normalized)
        for index, name in enumerate(names):
            if any(other.startswith(name + "/") for other in names[index + 1:]):
                raise AuthorityDenied("build.output_spec", "output constraints overlap")

        files: dict[str, tuple[Path, os.stat_result]] = {}
        directories: set[str] = set()
        for current, dirs, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            for dirname in list(dirs):
                candidate = current_path / dirname
                info = candidate.lstat()
                relative = candidate.relative_to(root).as_posix()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != profile.output_owner_uid
                        or info.st_mode & 0o022):
                    raise AuthorityDenied("build.output_custody", "build output directory custody is invalid")
                directories.add(relative)
            for filename in filenames:
                candidate = current_path / filename
                relative = _safe_output_name(candidate.relative_to(root).as_posix())
                info = candidate.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != profile.output_owner_uid
                        or info.st_mode & 0o022 or info.st_nlink != 1):
                    raise AuthorityDenied("build.output_custody", "build output file custody is invalid")
                files[relative] = (candidate, info)

        result: dict[str, dict[str, Any]] = {}
        assigned: set[str] = set()
        total_all = 0
        for name, spec in normalized.items():
            base = root / name
            try:
                base_info = base.lstat()
            except OSError:
                raise AuthorityDenied("build.output_manifest", "required build output is missing") from None
            if stat.S_ISLNK(base_info.st_mode):
                raise AuthorityDenied("build.output_custody", "build output root cannot be a symlink")
            if spec.kind == "file":
                if not stat.S_ISREG(base_info.st_mode) or name not in files:
                    raise AuthorityDenied("build.output_manifest", "required build file output is missing")
                members = {name: files[name]}
            else:
                if not stat.S_ISDIR(base_info.st_mode) or base_info.st_uid != profile.output_owner_uid:
                    raise AuthorityDenied("build.output_manifest", "required build output tree is missing")
                prefix = name + "/"
                members = {path: value for path, value in files.items() if path.startswith(prefix)}
                if not members:
                    raise AuthorityDenied("build.output_manifest", "required build output tree is empty")
            if set(members) & assigned:
                raise AuthorityDenied("build.output_manifest", "build outputs overlap")
            assigned.update(members)
            entries = []
            bytes_total = 0
            for relative, (candidate, info) in sorted(members.items()):
                bytes_total += info.st_size
                total_all += info.st_size
                if bytes_total > spec.maximum_bytes or total_all > self.maximum_output_bytes:
                    raise AuthorityDenied("build.output_bounds", "build output exceeds its enrolled bound")
                digest = self._hash_file(candidate, info.st_size)
                entries.append({"relative_path": relative[len(name) + 1:] if spec.kind == "tree" else relative,
                                "sha256": digest, "size_bytes": info.st_size,
                                "executable": bool(info.st_mode & 0o111)})
            manifest_bytes = _canonical(entries)
            digest = hashlib.sha256(manifest_bytes).hexdigest() if spec.kind == "tree" else entries[0]["sha256"]
            try:
                observed_facts = inspector.inspect(profile, spec, base)
            except Exception:
                raise AuthorityDenied("build.target_facts", "root could not verify native output target facts") from None
            if not isinstance(observed_facts, Mapping) or not self._fact_matches(spec.target_facts, observed_facts):
                raise AuthorityDenied("build.target_facts", "observed native output facts differ from enrollment")
            if spec.kind == "file":
                expected_exec = spec.executable_role in {"colibri-engine", "coral-cpython39"}
                if entries[0]["executable"] != expected_exec:
                    raise AuthorityDenied("build.output_role", "native executable mode differs from its enrolled role")
            result[name] = {"kind": spec.kind, "sha256": digest, "size_bytes": bytes_total,
                            "executable_role": spec.executable_role,
                            "observed_target_facts": dict(observed_facts),
                            "tree_file_manifest_sha256": digest if spec.kind == "tree" else None,
                            "source": base, "members": members, "entries": entries}
        allowed_dirs: set[str] = set()
        for name, spec in normalized.items():
            parent = PurePosixPath(name).parent
            while parent.as_posix() != ".":
                allowed_dirs.add(parent.as_posix())
                parent = parent.parent
            if spec.kind == "tree":
                allowed_dirs.add(name)
                prefix = name + "/"
                for directory in directories:
                    if directory.startswith(prefix) and any(path.startswith(directory + "/") for path in files):
                        allowed_dirs.add(directory)
        if assigned != set(files) or directories != allowed_dirs:
            raise AuthorityDenied("build.output_manifest", "build produced unreviewed files or directories")
        return result

    @staticmethod
    def _hash_file(path: Path, expected_size: int) -> str:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                raise AuthorityDenied("build.output_race", "build output changed during verification")
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > expected_size:
                    raise AuthorityDenied("build.output_race", "build output changed during verification")
                digest.update(block)
            if total != expected_size:
                raise AuthorityDenied("build.output_race", "build output changed during verification")
            return digest.hexdigest()
        finally:
            os.close(fd)

    def _publish_output(self, name: str, digest: str, size: int, source: Path,
                        executable: bool, *, cancelled: Callable[[], bool]) -> BuildOutput:
        if cancelled():
            raise AuthorityDenied("build.expired", "build authorization expired during CAS publication")
        role = "x" if executable else "d"
        object_dir = self.root / "objects" / (digest + "-" + role)
        self._mkdir_private(object_dir)
        destination = object_dir / "payload"
        mode = 0o555 if executable else 0o444
        try:
            info = destination.lstat()
        except FileNotFoundError:
            info = None
        if info is None:
            temp = object_dir / (".payload." + secrets.token_hex(12))
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                digest_check = hashlib.sha256()
                total = 0
                source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    source_info = os.fstat(source_fd)
                    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size != size:
                        raise AuthorityDenied("build.output_race", "output changed during CAS publication")
                    while True:
                        if cancelled():
                            raise AuthorityDenied("build.expired", "build authorization expired during CAS copy")
                        block = os.read(source_fd, 1024 * 1024)
                        if not block:
                            break
                        total += len(block)
                        digest_check.update(block)
                        view = memoryview(block)
                        while view:
                            view = view[os.write(fd, view):]
                finally:
                    os.close(source_fd)
                if total != size or digest_check.hexdigest() != digest:
                    raise AuthorityDenied("build.output_race", "output changed during CAS publication")
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temp, destination, follow_symlinks=False)
            except FileExistsError:
                pass
            finally:
                temp.unlink(missing_ok=True)
            self._fsync_dir(object_dir)
            info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                or self._hash_file(destination, size) != digest):
            raise AuthorityDenied("build.cas", "content-addressed object failed custody verification")
        return f"build-output:{digest}:file:{role}"

    def _tree_manifest(self, payload: Path) -> list[dict[str, Any]]:
        entries = []
        for current, dirs, files in os.walk(payload, topdown=True, followlinks=False):
            current_path = Path(current)
            for dirname in dirs:
                info = (current_path / dirname).lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid
                        or stat.S_IMODE(info.st_mode) != 0o555):
                    raise AuthorityDenied("build.cas", "published tree directory custody is invalid")
            for filename in files:
                path = current_path / filename
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in {0o444, 0o555}):
                    raise AuthorityDenied("build.cas", "published tree file custody is invalid")
                relative = path.relative_to(payload).as_posix()
                entries.append({"relative_path": relative, "sha256": self._hash_file(path, info.st_size),
                                "size_bytes": info.st_size, "executable": bool(info.st_mode & 0o111)})
        return sorted(entries, key=lambda row: row["relative_path"])

    def _publish_tree(self, name: str, row: Mapping[str, Any], *, cancelled: Callable[[], bool]) -> str:
        digest = row["sha256"]
        object_dir = self.root / "objects" / (digest + "-tree")
        payload = object_dir / "payload"
        if not object_dir.exists():
            temporary = self.root / "objects" / (".tree." + secrets.token_hex(16))
            temp_payload = temporary / "payload"
            temp_payload.mkdir(parents=True, mode=0o700)
            try:
                for entry, (source, source_info) in sorted(row["members"].items()):
                    if cancelled():
                        raise AuthorityDenied("build.expired", "build authorization expired during tree copy")
                    relative = entry[len(name) + 1:]
                    destination = temp_payload / relative
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    src_fd = os.open(source, flags)
                    dst_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                      | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    try:
                        info = os.fstat(src_fd)
                        if info.st_size != source_info.st_size or not stat.S_ISREG(info.st_mode):
                            raise AuthorityDenied("build.output_race", "tree output changed during copy")
                        digest_check = hashlib.sha256()
                        total = 0
                        while True:
                            block = os.read(src_fd, 1024 * 1024)
                            if not block:
                                break
                            total += len(block)
                            digest_check.update(block)
                            view = memoryview(block)
                            while view:
                                view = view[os.write(dst_fd, view):]
                        expected = next(item for item in row["entries"] if item["relative_path"] == relative)
                        if total != expected["size_bytes"] or digest_check.hexdigest() != expected["sha256"]:
                            raise AuthorityDenied("build.output_race", "tree output changed during copy")
                        os.fchmod(dst_fd, 0o555 if expected["executable"] else 0o444)
                        os.fsync(dst_fd)
                    finally:
                        os.close(src_fd)
                        os.close(dst_fd)
                for current, dirs, _ in os.walk(temp_payload, topdown=False):
                    for dirname in dirs:
                        (Path(current) / dirname).chmod(0o555)
                temp_payload.chmod(0o555)
                self._fsync_dir(temp_payload)
                self._fsync_dir(temporary)
                try:
                    os.rename(temporary, object_dir)
                except FileExistsError:
                    pass
            except Exception:
                # Make the private temporary tree removable after a failed copy.
                for current, dirs, files in os.walk(temporary, topdown=False):
                    for filename in files:
                        (Path(current) / filename).chmod(0o600)
                    for dirname in dirs:
                        (Path(current) / dirname).chmod(0o700)
                if temporary.exists():
                    (temporary / "payload").chmod(0o700)
                    import shutil
                    shutil.rmtree(temporary, ignore_errors=True)
                raise
            self._fsync_dir(object_dir.parent)
        if self._tree_manifest(payload) != row["entries"]:
            raise AuthorityDenied("build.cas", "published output tree manifest differs from build output")
        return f"build-output:{digest}:tree"

    def _publish_attestation(self, record: BuildAttestation, *, cancelled: Callable[[], bool]) -> None:
        directory = self.root / "attestations"
        self._mkdir_private(directory)
        final = directory / (record.attestation_id + ".json")
        temporary = directory / ("." + record.attestation_id + ".tmp")
        data = _canonical(record.to_wire())
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if cancelled():
                raise AuthorityDenied("build.expired", "build authorization expired before receipt write")
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temporary, final, follow_symlinks=False)
        except FileExistsError:
            temporary.unlink(missing_ok=True)
            raise AuthorityDenied("build.attestation", "attestation identifier collision") from None
        temporary.unlink()
        self._fsync_dir(directory)

    def _publish_current(self, record: BuildAttestation, *, cancelled: Callable[[], bool]) -> None:
        if cancelled():
            raise AuthorityDenied("build.expired", "build authorization expired before receipt activation")
        directory = self.root / "current"
        self._mkdir_private(directory)
        path = self._index_path(record.target_id, record.generation)
        temporary = directory / ("." + secrets.token_hex(16) + ".tmp")
        data = _canonical({"schema": 1, "target_id": record.target_id,
                           "generation": record.generation,
                           "attestation_id": record.attestation_id,
                           "attestation_sha256": record.attestation_sha256})
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        if cancelled():
            temporary.unlink(missing_ok=True)
            raise AuthorityDenied("build.expired", "build authorization expired before receipt activation")
        existing = None
        try:
            existing = path.lstat()
        except FileNotFoundError:
            pass
        if existing is not None and (not stat.S_ISREG(existing.st_mode)
                                     or existing.st_uid != self.owner_uid
                                     or stat.S_IMODE(existing.st_mode) != 0o600):
            temporary.unlink(missing_ok=True)
            raise AuthorityDenied("build.index", "current receipt index custody is invalid")
        os.replace(temporary, path)
        self._fsync_dir(directory)

    def _index_path(self, target_id: str, generation: str) -> Path:
        key = hashlib.sha256((target_id + "\n" + generation).encode("ascii")).hexdigest()
        return self.root / "current" / (key + ".json")

    def _read_protected_json(self, path: Path) -> Any:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4 * 1024 * 1024):
                    raise AuthorityDenied("build.record_custody", "build record custody is invalid")
                data = bytearray()
                while len(data) <= 4 * 1024 * 1024:
                    block = os.read(fd, min(65536, 4 * 1024 * 1024 + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                if len(data) > 4 * 1024 * 1024:
                    raise AuthorityDenied("build.record_bounds", "build record exceeds its size bound")
            finally:
                os.close(fd)
            def unique_pairs(rows):
                result = {}
                for key, value in rows:
                    if key in result:
                        raise ValueError("duplicate key")
                    result[key] = value
                return result
            return json.loads(bytes(data).decode("ascii"), object_pairs_hook=unique_pairs)
        except AuthorityDenied:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise AuthorityDenied("build.record", "root build record is missing or malformed") from None

    def _parse_attestation(self, value: Any) -> BuildAttestation:
        required = {"schema", "receipt_id", "receipt_digest", "root_signature", "build_target_id",
                    "enrollment_id", "build_generation", "operation_id", "service_generation_digest",
                    "recipe_digest", "source_artifact_id", "source_sha256", "toolchain_artifact_id",
                    "toolchain_sha256", "builder_artifact_id", "builder_sha256", "process_identity_digest",
                    "terminal_success_record_id", "output_records", "execution", "issued_monotonic", "expires_monotonic"}
        if not isinstance(value, dict) or set(value) != required or not isinstance(value["execution"], dict):
            raise AuthorityDenied("build.attestation", "stored build receipt fields are invalid")
        execution = value["execution"]
        execution_fields = {"process_id", "uid", "pid", "start_ticks", "exit_code", "cleanup_verified",
                            "started_monotonic", "finished_monotonic", "kernel_limits", "cgroup_id",
                            "mount_namespace_inode", "network_namespace_inode", "bounded_log_digest", "log_bytes"}
        if set(execution) != execution_fields or not isinstance(execution["kernel_limits"], dict):
            raise AuthorityDenied("build.attestation", "stored terminal process evidence is invalid")
        if not isinstance(value["output_records"], list) or not 1 <= len(value["output_records"]) <= MAX_OUTPUT_FILES:
            raise AuthorityDenied("build.attestation", "stored output manifest is invalid")
        outputs = []
        output_fields = {"relative_path", "kind", "sha256", "size_bytes", "executable_role",
                         "observed_target_facts", "tree_file_manifest_sha256"}
        for raw in value["output_records"]:
            if not isinstance(raw, dict) or set(raw) != output_fields:
                raise AuthorityDenied("build.attestation", "stored output record is malformed")
            try:
                output = BuildOutput(**raw)
                _safe_output_name(output.relative_path)
                _sha(output.sha256, "output")
                if (output.kind not in {"file", "tree"} or type(output.size_bytes) is not int
                        or output.size_bytes < 1 or not isinstance(output.executable_role, str)
                        or not isinstance(output.observed_target_facts, dict)
                        or (output.kind == "tree" and output.tree_file_manifest_sha256 != output.sha256)
                        or (output.kind == "file" and output.tree_file_manifest_sha256 is not None)):
                    raise ValueError("output values")
            except (TypeError, ValueError, AuthorityDenied):
                raise AuthorityDenied("build.attestation", "stored output record is invalid") from None
            outputs.append(output)
        if len({item.relative_path for item in outputs}) != len(outputs):
            raise AuthorityDenied("build.attestation", "output paths are duplicated")
        try:
            return BuildAttestation(
                schema=value["schema"], attestation_id=value["receipt_id"],
                attestation_sha256=value["receipt_digest"], target_id=value["build_target_id"],
                enrollment_id=value["enrollment_id"], generation=value["build_generation"],
                operation_id=value["operation_id"], source_artifact_id=value["source_artifact_id"],
                source_sha256=value["source_sha256"], toolchain_artifact_id=value["toolchain_artifact_id"],
                toolchain_sha256=value["toolchain_sha256"], builder_artifact_id=value["builder_artifact_id"],
                builder_sha256=value["builder_sha256"], recipe_sha256=value["recipe_digest"],
                outputs=tuple(outputs), process_id=execution["process_id"], process_uid=execution["uid"],
                process_pid=execution["pid"], process_start_ticks=execution["start_ticks"],
                exit_code=execution["exit_code"], cleanup_verified=execution["cleanup_verified"],
                cgroup_id=execution["cgroup_id"], mount_namespace_inode=execution["mount_namespace_inode"],
                network_namespace_inode=execution["network_namespace_inode"],
                started_monotonic=execution["started_monotonic"],
                finished_monotonic=execution["finished_monotonic"], kernel_limits=execution["kernel_limits"],
                service_generation_digest=value["service_generation_digest"],
                process_identity_digest=value["process_identity_digest"],
                terminal_success_record_id=value["terminal_success_record_id"],
                bounded_log_digest=execution["bounded_log_digest"], log_bytes=execution["log_bytes"],
                issued_monotonic=value["issued_monotonic"], expires_monotonic=value["expires_monotonic"],
                signature=value["root_signature"],
            )
        except (KeyError, TypeError, ValueError):
            raise AuthorityDenied("build.attestation", "stored build receipt values are invalid") from None

    def _verify_attestation(self, record: BuildAttestation, profile: Any) -> None:
        digest = hashlib.sha256(_canonical(record.unsigned_wire())).hexdigest()
        signature = hmac.new(self._key, _canonical(record.to_wire() | {"root_signature": ""}),
                             hashlib.sha256).hexdigest()
        specs = dict(profile.output_specs)
        actual = {item.relative_path: item for item in record.outputs}
        now = time.monotonic()
        if (record.schema != 1 or digest != record.attestation_sha256
                or not hmac.compare_digest(signature, record.signature)
                or record.target_id != profile.target_id or record.generation != profile.generation
                or record.service_generation_digest != profile.service_generation_digest
                or record.enrollment_id == ""
                or OPERATION_TARGETS.get(record.operation_id) != profile.target_id
                or record.exit_code != 0 or not record.cleanup_verified
                or record.process_uid != profile.output_owner_uid or record.process_pid <= 1
                or record.process_start_ticks <= 0 or not record.terminal_success_record_id
                or record.process_identity_digest != managed_process_identity_digest(
                    process_id=record.process_id, generation=record.generation, uid=record.process_uid,
                    pid=record.process_pid, start_ticks=record.process_start_ticks, cgroup_id=record.cgroup_id,
                    mount_namespace_inode=record.mount_namespace_inode,
                    network_namespace_inode=record.network_namespace_inode)
                or not record.cgroup_id or record.mount_namespace_inode <= 0 or record.network_namespace_inode <= 0
                or not 0 < record.issued_monotonic <= now < record.expires_monotonic
                or record.expires_monotonic - record.issued_monotonic > 600
                or set(record.kernel_limits) != set(REQUIRED_LIMITS)
                or any(record.kernel_limits.get(key) != value for key, value in REQUIRED_LIMITS.items())
                or not 0 < record.started_monotonic <= record.finished_monotonic
                or record.finished_monotonic - record.started_monotonic > profile.max_lifetime_seconds
                or record.source_artifact_id != profile.source_artifact_id
                or record.source_sha256 != profile.source_sha256
                or record.toolchain_artifact_id != profile.toolchain_artifact_id
                or record.toolchain_sha256 != profile.toolchain_sha256
                or record.builder_artifact_id != profile.builder_artifact_id
                or record.builder_sha256 != profile.builder_sha256
                or record.recipe_sha256 != _recipe_digest(profile)
                or set(actual) != set(specs)):
            raise AuthorityDenied("build.attestation", "stored receipt does not match current root enrollment")
        for name, output in actual.items():
            spec = specs[name]
            if (output.kind != spec.kind or output.executable_role != spec.executable_role
                    or output.size_bytes > spec.maximum_bytes
                    or not ContentAddressedBuildStore._fact_matches(spec.target_facts, output.observed_target_facts)):
                raise AuthorityDenied("build.attestation", "receipt output facts differ from enrolled constraints")
            self.resolve_output_object(output)

    def resolve_output_object(self, output: BuildOutput) -> Path:
        if output.kind == "tree":
            if output.artifact_id != f"build-output:{output.sha256}:tree":
                raise AuthorityDenied("build.output_id", "tree output ID is malformed")
            path = self.root / "objects" / (output.sha256 + "-tree") / "payload"
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o555):
                raise AuthorityDenied("build.cas", "published tree root custody is invalid")
            entries = self._tree_manifest(path)
            if hashlib.sha256(_canonical(entries)).hexdigest() != output.tree_file_manifest_sha256:
                raise AuthorityDenied("build.cas", "published tree manifest digest differs")
            return path
        if output.kind != "file":
            raise AuthorityDenied("build.output_id", "output kind is invalid")
        executable = output.executable
        role = "x" if executable else "d"
        if output.artifact_id != f"build-output:{output.sha256}:file:{role}":
            raise AuthorityDenied("build.output_id", "file output ID is malformed")
        path = self.root / "objects" / (output.sha256 + "-" + role) / "payload"
        info = path.lstat()
        mode = 0o555 if executable else 0o444
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                or stat.S_IMODE(info.st_mode) != mode or info.st_size != output.size_bytes
                or self._hash_file(path, output.size_bytes) != output.sha256):
            raise AuthorityDenied("build.cas", "build output object failed hash or custody verification")
        return path

    def _ensure_store(self) -> None:
        current = Path(self.root.anchor)
        for part in self.root.parts[1:-1]:
            current /= part
            info = current.lstat()
            sticky_root_parent = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid not in {self.owner_uid, 0})
                    or (info.st_uid == self.owner_uid and info.st_mode & 0o022)
                    or (info.st_uid == 0 and info.st_mode & 0o022 and not sticky_root_parent)):
                raise AuthorityDenied("build.store_custody", "build store ancestor is not protected")
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        self._check_owned_directory(self.root, self.owner_uid, mode=0o700)
        self._mkdir_private(self.root / "objects")
        self._mkdir_private(self.root / "attestations")

    def _mkdir_private(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        self._check_owned_directory(path, self.owner_uid, mode=0o700)

    @staticmethod
    def _check_owned_directory(path: Path, uid: int, *, mode: int | None = None) -> None:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
            raise AuthorityDenied("build.store_custody", "private build directory custody is invalid")

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class RootBuildExecutionService:
    """Handler for fixed `process.start` selections; does not expose caller paths."""
    def __init__(self, *, build_catalog: FixedBuildCatalog, artifact_catalog: Any,
                 artifact_staging_root: Path, launcher: FixedBuildJobLauncher,
                 fact_inspector: BuildOutputFactInspector, authority_key: bytes | None = None,
                 service_catalog: Any,
                 allowed_operation_ids: frozenset[str] | None = None,
                 store: ContentAddressedBuildStore | None = None, expected_uid: int = 0,
                 monotonic: Callable[[], float] = time.monotonic):
        if type(expected_uid) is not int or os.geteuid() != expected_uid:
            raise AuthorityDenied("build.privilege", "fixed build execution requires enrolled root identity")
        if not artifact_staging_root.is_absolute():
            raise AuthorityDenied("build.artifacts", "artifact staging root must be absolute")
        self.catalog = build_catalog
        self.services = service_catalog
        self.artifacts = artifact_catalog
        self.artifact_staging_root = artifact_staging_root
        self.launcher = launcher
        self.fact_inspector = fact_inspector
        has_cpython_probe = callable(getattr(
            getattr(fact_inspector, "runtime_probe", None), "inspect_cpython39", None))
        default_operations = {"colibri-source-build-v1"}
        if has_cpython_probe:
            default_operations.add("coral-cpython39-source-build-v1")
        selected_operations = default_operations if allowed_operation_ids is None else set(allowed_operation_ids)
        if (not selected_operations or not selected_operations <= set(OPERATION_TARGETS)
                or "coral-cpython39-source-build-v1" in selected_operations and not has_cpython_probe):
            raise AuthorityDenied("build.operation", "build operation registration exceeds verified inspector support")
        self.allowed_operation_ids = frozenset(selected_operations)
        if store is None:
            if not isinstance(authority_key, bytes) or len(authority_key) != 32:
                raise AuthorityDenied("build.store", "root build signing key is unavailable")
            store = ContentAddressedBuildStore.root_store(authority_key=authority_key)
        elif not isinstance(store, ContentAddressedBuildStore):
            raise AuthorityDenied("build.store", "root content-addressed build store is invalid")
        self.store = store
        if self.store.owner_uid != expected_uid:
            raise AuthorityDenied("build.store_custody", "build store owner differs from the root executor identity")
        self.expected_uid = expected_uid
        self.monotonic = monotonic

    def handlers(self) -> Mapping[tuple[str, str], Any]:
        """Return only fixed operation targets supported by this inspector."""
        return MappingProxyType({
            ("process.start", OPERATION_TARGETS[operation_id]): self
            for operation_id in self.allowed_operation_ids
        })

    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float, peer_pid: int, peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                or not isinstance(payload, bytes) or len(payload) > 4096
                or type(peer_pid) is not int or peer_pid <= 0 or peer_pidfd is None
                or not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 600 or authorization.request_digest != canonical_digest(payload)):
            raise AuthorityDenied("build.request", "fixed build request is malformed")
        request = self._request(payload)
        if request["operation_id"] not in self.allowed_operation_ids:
            raise AuthorityDenied("build.operation", "this build target has no qualified root output inspector")
        target = OPERATION_TARGETS[request["operation_id"]]
        if (authorization.operation != "process.start" or authorization.target != target
                or context.operation != "process.start"
                or context.enrollment_id != request["enrollment_id"]
                or authorization.enrollment_id != request["enrollment_id"]
                or context.generation != request["generation"]
                or authorization.generation != request["generation"]):
            raise AuthorityDenied("build.binding", "grant does not bind this fixed build operation")
        resolver = getattr(self.catalog, "resolve_service", None)
        if not callable(resolver) or self.services is None:
            raise AuthorityDenied("build.service", "root service enrollment join is unavailable")
        profile, service_profile = resolver(target, request["generation"], self.services)
        if (profile.target_id != target or profile.generation != request["generation"]
                or profile.build_service_enrollment_id != service_profile.enrollment_id
                or profile.build_service_generation != service_profile.generation
                or type(service_profile.service_uid) is not int
                or type(service_profile.service_gid) is not int
                or profile.output_owner_uid != service_profile.service_uid
                or service_profile.service_uid <= 0 or service_profile.service_gid <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", profile.service_generation_digest)):
            raise AuthorityDenied("build.binding", "root catalog selected another build profile")
        deadline = self.monotonic() + timeout
        self._require_live(cancelled, deadline)
        inputs = self._resolve_inputs(profile, enrollment_id=request["enrollment_id"],
                                      operation_id=request["operation_id"],
                                      selection_digest=authorization.request_digest)
        self._require_live(cancelled, deadline)
        started = self.monotonic()
        job_deadline = min(deadline, started + profile.max_lifetime_seconds)
        try:
            process = self.launcher.run_selected_build(
                inputs, context=context, authorization=authorization, peer_pid=peer_pid,
                peer_pidfd=peer_pidfd, timeout=max(0.0, job_deadline - self.monotonic()),
                cancelled=lambda: cancelled() or self.monotonic() >= job_deadline,
            )
            self._require_live(cancelled, deadline)
            attestation = self.store.publish(profile, enrollment_id=request["enrollment_id"],
                                             operation_id=request["operation_id"], process=process,
                                             fact_inspector=self.fact_inspector,
                                             cancelled=lambda: cancelled() or self.monotonic() >= deadline,
                                             output_root=inputs.output_root,
                                             before_activate=lambda: self._remove_job_output_root(
                                                 inputs.output_root, profile.output_owner_uid))
            # The current-index rename in publish is the success linearization point;
            # cancellation after that point cannot revoke an already-issued receipt.
            return {"status": 200,
                    "body": base64.b64encode(_canonical(attestation.to_wire())).decode("ascii"),
                    "headers": {"content-type": "application/json"},
                    "receipt_id": attestation.attestation_id}
        finally:
            self._remove_job_output_root(inputs.output_root, profile.output_owner_uid)

    def _resolve_inputs(self, profile: Any, *, enrollment_id: str, operation_id: str,
                        selection_digest: str) -> ResolvedBuildInputs:
        resolved = []
        for artifact_id, digest in (
            (profile.source_artifact_id, profile.source_sha256),
            (profile.toolchain_artifact_id, profile.toolchain_sha256),
            (profile.builder_artifact_id, profile.builder_sha256),
        ):
            try:
                spec = self.artifacts.artifacts.get(artifact_id)
                if spec is None or spec.sha256 != digest:
                    raise ValueError("catalog pin")
                item = (self.artifacts.materialize_tree(artifact_id, digest, self.artifact_staging_root,
                                                       expected_uid=self.expected_uid)
                        if spec.tree_files else
                        self.artifacts.resolve(artifact_id, digest, self.artifact_staging_root,
                                               expected_uid=self.expected_uid))
                resolved.append(item)
            except Exception:
                raise AuthorityDenied("build.artifact", "pinned source, toolchain, or builder is unavailable") from None
        source, toolchain, builder = resolved
        builder_info = builder.path.lstat()
        if (not stat.S_ISREG(builder_info.st_mode) or not builder_info.st_mode & 0o111
                or builder_info.st_uid != self.expected_uid):
            raise AuthorityDenied("build.builder", "reviewed builder executable custody is invalid")
        if (source.sha256 != profile.source_sha256 or toolchain.sha256 != profile.toolchain_sha256
                or builder.sha256 != profile.builder_sha256):
            raise AuthorityDenied("build.artifact", "materialized build input digest changed")
        output_parent = Path(profile.output_root)
        ContentAddressedBuildStore._check_owned_directory(
            output_parent, profile.output_owner_uid, mode=0o700)
        output_root_id = secrets.token_hex(16)
        output = output_parent / ("job-" + output_root_id)
        try:
            output.mkdir(mode=0o700)
            if output.stat().st_uid != profile.output_owner_uid:
                os.chown(output, profile.output_owner_uid, -1, follow_symlinks=False)
            os.chmod(output, 0o700, follow_symlinks=False)
        except OSError:
            try:
                output.rmdir()
            except OSError:
                pass
            raise AuthorityDenied("build.output_custody", "fresh private output root could not be created") from None
        ContentAddressedBuildStore._check_owned_directory(output, profile.output_owner_uid, mode=0o700)
        output_specs = {}
        try:
            for relative_path, raw in profile.output_specs.items():
                output_specs[relative_path] = BuildOutputSpec(
                    raw.relative_path, raw.kind, raw.maximum_bytes,
                    raw.executable_role, raw.target_facts)
        except Exception:
            self._remove_job_output_root(output, profile.output_owner_uid)
            raise AuthorityDenied("build.output_spec", "protected output constraints are malformed") from None
        try:
            argv_recipe = _resolve_argv_recipe(profile.argv_recipe)
        except Exception:
            self._remove_job_output_root(output, profile.output_owner_uid)
            raise
        return ResolvedBuildInputs(
            profile.target_id, profile.generation, profile.service_generation_digest,
            profile.build_service_enrollment_id, profile.build_service_generation,
            enrollment_id, operation_id, selection_digest,
            source.artifact_id, source.sha256, source.path,
            tuple(source.tree_files), source.tree_manifest_sha256,
            toolchain.artifact_id, toolchain.sha256, toolchain.path,
            tuple(toolchain.tree_files), toolchain.tree_manifest_sha256, builder.artifact_id,
            builder.sha256, builder.path, argv_recipe, dict(profile.environment),
            output_specs, output, output_root_id,
            profile.output_owner_uid, profile.max_lifetime_seconds,
        )

    @staticmethod
    def _remove_job_output_root(path: Path, owner_uid: int) -> None:
        try:
            path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise AuthorityDenied("build.output_cleanup", "unique build output root cannot be inspected") from None
        # Cleanup failure must fail the build before the receipt's current-index
        # rename. In particular, never interpret changed ownership or a symlink
        # substitution as if the output root had already been removed.
        ContentAddressedBuildStore._check_owned_directory(path, owner_uid, mode=0o700)
        # This path is a uniquely created child of the protected enrolled output
        # root. Do not follow links while clearing the build-owned job output.
        for current, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for filename in files:
                item = Path(current) / filename
                info = item.lstat()
                if stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid:
                    item.chmod(0o600, follow_symlinks=False)
                    item.unlink()
                elif stat.S_ISLNK(info.st_mode):
                    item.unlink()
            for dirname in dirs:
                item = Path(current) / dirname
                info = item.lstat()
                if stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid:
                    item.chmod(0o700, follow_symlinks=False)
                    item.rmdir()
                elif stat.S_ISLNK(info.st_mode):
                    item.unlink()
        path.rmdir()

    @staticmethod
    def _request(payload: bytes) -> dict[str, Any]:
        try:
            value = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorityDenied("build.request", "fixed build request is malformed") from None
        if (not isinstance(value, dict)
                or set(value) != {"schema", "enrollment_id", "generation", "operation_id", "parameters"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or not isinstance(value["enrollment_id"], str) or not value["enrollment_id"]
                or not isinstance(value["generation"], str) or not value["generation"]
                or value["operation_id"] not in OPERATION_TARGETS or value["parameters"] != {}):
            raise AuthorityDenied("build.request", "fixed selection or empty parameter schema is invalid")
        return value

    def _require_live(self, cancelled: Callable[[], bool], deadline: float) -> None:
        if (cancelled() or not math.isfinite(deadline) or self.monotonic() >= deadline
                or os.geteuid() != self.expected_uid):
            raise AuthorityDenied("build.expired", "fresh authority, process custody, or deadline is unavailable")
