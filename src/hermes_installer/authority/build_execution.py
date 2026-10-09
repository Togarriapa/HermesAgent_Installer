"""Root-owned fixed build result custody and attestation (HW-T03).

Worker input is restricted to one reviewed operation identifier, generation,
and the empty parameter object. A root composition resolves pinned artifacts
and invokes its managed build-job launcher. This module validates the terminal
isolation/exit receipt and atomically publishes a complete digest-checked tree
to a private CAS. It remains unregistered until a concrete managed build-job
launcher is present in daemon composition.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Protocol

from .types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest

BUILD_ATTESTATION_STORE = Path("/var/lib/hermes-installer/build-attestations")
MAX_OUTPUT_FILES = 512
MAX_OUTPUT_BYTES = 2 * 1024**3
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
                      ensure_ascii=True).encode("ascii")


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise AuthorityDenied("build.digest", f"{label} digest is invalid")
    return value


def _safe_output_name(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AuthorityDenied("build.output", "build output name is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AuthorityDenied("build.output", "build output name escapes its enrolled output root")
    return path.as_posix()


def _recipe_digest(profile: Any) -> str:
    return hashlib.sha256(_canonical({
        "target_id": profile.target_id, "generation": profile.generation,
        "source_artifact_id": profile.source_artifact_id, "source_sha256": profile.source_sha256,
        "toolchain_artifact_id": profile.toolchain_artifact_id,
        "toolchain_sha256": profile.toolchain_sha256,
        "builder_artifact_id": profile.builder_artifact_id, "builder_sha256": profile.builder_sha256,
        "argv_recipe": list(profile.argv_recipe), "environment": dict(profile.environment),
        "max_lifetime_seconds": profile.max_lifetime_seconds,
        "required_outputs": dict(profile.required_outputs),
        "output_specs": {
            name: {"sha256": item.sha256, "size_bytes": item.size_bytes,
                  "max_size_bytes": item.max_size_bytes, "executable": item.executable}
            for name, item in sorted(profile.output_specs.items())
        },
    })).hexdigest()


@dataclass(frozen=True, slots=True)
class ResolvedBuildInputs:
    target_id: str
    generation: str
    source_artifact_id: str
    source_sha256: str
    source_root: Path
    toolchain_artifact_id: str
    toolchain_sha256: str
    toolchain_root: Path
    builder_artifact_id: str
    builder_sha256: str
    builder_executable: Path
    argv_recipe: tuple[str, ...]
    environment: Mapping[str, str]
    output_root: Path
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


class FixedBuildCatalog(Protocol):
    def resolve(self, target_id: str, generation: str) -> Any: ...


class FixedBuildJobLauncher(Protocol):
    """Root-owned managed process boundary; worker adapters cannot supply it."""
    def run(self, inputs: ResolvedBuildInputs, *, timeout: float,
            cancelled: Callable[[], bool]) -> ManagedBuildResult: ...


@dataclass(frozen=True, slots=True)
class BuildOutputSpec:
    """Root enrollment for one required output; metadata is never inferred."""
    path: str
    sha256: str
    size_bytes: int
    max_size_bytes: int
    executable: bool

    def __post_init__(self) -> None:
        _safe_output_name(self.path)
        _sha(self.sha256, "output")
        if (type(self.size_bytes) is not int or type(self.max_size_bytes) is not int
                or not 1 <= self.size_bytes <= self.max_size_bytes <= MAX_OUTPUT_BYTES
                or type(self.executable) is not bool):
            raise AuthorityDenied("build.output_spec", "protected output size or role is invalid")


@dataclass(frozen=True, slots=True)
class BuildOutput:
    name: str
    artifact_id: str
    sha256: str
    size_bytes: int
    executable: bool

    def to_wire(self) -> dict[str, Any]:
        return {"name": self.name, "artifact_id": self.artifact_id,
                "sha256": self.sha256, "size_bytes": self.size_bytes,
                "executable": self.executable}


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
    started_monotonic: float
    finished_monotonic: float
    kernel_limits: Mapping[str, str]
    signature: str

    def unsigned_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "attestation_id": self.attestation_id,
            "target_id": self.target_id, "enrollment_id": self.enrollment_id,
            "generation": self.generation, "operation_id": self.operation_id,
            "source_artifact_id": self.source_artifact_id, "source_sha256": self.source_sha256,
            "toolchain_artifact_id": self.toolchain_artifact_id,
            "toolchain_sha256": self.toolchain_sha256,
            "builder_artifact_id": self.builder_artifact_id, "builder_sha256": self.builder_sha256,
            "recipe_sha256": self.recipe_sha256,
            "outputs": [item.to_wire() for item in self.outputs],
            "execution": {"process_id": self.process_id, "uid": self.process_uid,
                          "pid": self.process_pid, "start_ticks": self.process_start_ticks,
                          "exit_code": self.exit_code, "cleanup_verified": self.cleanup_verified,
                          "started_monotonic": self.started_monotonic,
                          "finished_monotonic": self.finished_monotonic,
                          "kernel_limits": dict(self.kernel_limits)},
        }

    def to_wire(self) -> dict[str, Any]:
        return {**self.unsigned_wire(), "attestation_sha256": self.attestation_sha256,
                "signature": self.signature}


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
                process: ManagedBuildResult, cancelled: Callable[[], bool] = lambda: False) -> BuildAttestation:
        self._require_completed_isolated_process(profile, process)
        observed = self._inspect_complete_output_tree(profile)
        if cancelled():
            raise AuthorityDenied("build.expired", "build authorization expired before output publication")
        try:
            expected = dict(profile.attest_outputs())
        except Exception:
            raise AuthorityDenied("build.output_digest", "produced output differs from protected enrollment") from None
        if {name: row[0] for name, row in observed.items()} != expected:
            raise AuthorityDenied("build.output_manifest", "build output tree is incomplete or has unreviewed files")
        self._ensure_store()
        outputs = tuple(self._publish_output(name, *observed[name], cancelled=cancelled)
                        for name in sorted(observed))
        recipe_digest = _recipe_digest(profile)
        record = BuildAttestation(
            schema=1, attestation_id=secrets.token_urlsafe(24), attestation_sha256="0" * 64,
            target_id=profile.target_id, enrollment_id=enrollment_id, generation=profile.generation,
            operation_id=operation_id, source_artifact_id=profile.source_artifact_id,
            source_sha256=profile.source_sha256, toolchain_artifact_id=profile.toolchain_artifact_id,
            toolchain_sha256=profile.toolchain_sha256, builder_artifact_id=profile.builder_artifact_id,
            builder_sha256=profile.builder_sha256, recipe_sha256=recipe_digest, outputs=outputs,
            process_id=process.process_id, process_uid=process.uid, process_pid=process.pid,
            process_start_ticks=process.start_ticks, exit_code=0, cleanup_verified=True,
            started_monotonic=process.started_monotonic, finished_monotonic=process.finished_monotonic,
            kernel_limits=dict(process.kernel_limits), signature="",
        )
        digest = hashlib.sha256(_canonical(record.unsigned_wire())).hexdigest()
        record = replace(record, attestation_sha256=digest)
        signature = hmac.new(self._key, _canonical(record.to_wire() | {"signature": ""}),
                             hashlib.sha256).hexdigest()
        record = replace(record, signature=signature)
        self._publish_attestation(record, cancelled=cancelled)
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

    def resolve_output(self, profile: Any, artifact_id: str) -> Path:
        """Resolve a build output ID only through the current verified receipt."""
        record = self.resolve(profile)
        output = next((item for item in record.outputs if item.artifact_id == artifact_id), None)
        if output is None:
            raise AuthorityDenied("build.output_id", "output artifact is outside the current build receipt")
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
                or not 0 < process.started_monotonic <= process.finished_monotonic <= now
                or process.finished_monotonic - process.started_monotonic > profile.max_lifetime_seconds
                or any(limits.get(key) != value for key, value in REQUIRED_LIMITS.items())):
            raise AuthorityDenied("build.process", "build process did not complete within its isolated lease")

    def _inspect_complete_output_tree(self, profile: Any) -> dict[str, tuple[str, int, Path, bool]]:
        root = Path(profile.output_root)
        self._check_owned_directory(root, profile.output_owner_uid, mode=0o700)
        try:
            specs = dict(profile.output_specs)
        except (AttributeError, TypeError):
            raise AuthorityDenied("build.output_spec", "root-enrolled output size and executable metadata is unavailable") from None
        if not specs or len(specs) > MAX_OUTPUT_FILES:
            raise AuthorityDenied("build.output_spec", "protected output manifest is empty or oversized")
        required = {}
        for name, spec in specs.items():
            if not isinstance(spec, BuildOutputSpec) or _safe_output_name(name) != spec.path:
                raise AuthorityDenied("build.output_spec", "protected output manifest entry is invalid")
            required[name] = spec
        found: dict[str, tuple[str, int, Path, bool]] = {}
        total = 0
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in list(dirs):
                info = (current_path / name).lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != profile.output_owner_uid
                        or info.st_mode & 0o022):
                    raise AuthorityDenied("build.output_custody", "build output directory custody is invalid")
            for name in files:
                candidate = current_path / name
                relative = _safe_output_name(candidate.relative_to(root).as_posix())
                info = candidate.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != profile.output_owner_uid
                        or info.st_mode & 0o022 or info.st_nlink != 1):
                    raise AuthorityDenied("build.output_custody", "build output file custody is invalid")
                spec = required.get(relative)
                if spec is None or len(found) >= MAX_OUTPUT_FILES:
                    raise AuthorityDenied("build.output_manifest", "build produced an unreviewed output")
                total += info.st_size
                if (info.st_size != spec.size_bytes or info.st_size > spec.max_size_bytes
                        or total > self.maximum_output_bytes):
                    raise AuthorityDenied("build.output_bounds", "build output exceeds its storage bound")
                executable = bool(info.st_mode & 0o111)
                if executable != spec.executable:
                    raise AuthorityDenied("build.output_role", "output executable mode differs from root enrollment")
                digest = self._hash_file(candidate, info.st_size)
                if digest != spec.sha256:
                    raise AuthorityDenied("build.output_digest", "output digest differs from root enrollment")
                found[relative] = (digest, info.st_size, candidate, spec.executable)
        if set(found) != set(required):
            raise AuthorityDenied("build.output_manifest", "build did not produce the complete enrolled output set")
        return found

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
        return BuildOutput(name, f"build-output:{digest}:{role}", digest, size, executable)

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
        required = {"schema", "attestation_id", "attestation_sha256", "target_id", "enrollment_id",
                    "generation", "operation_id", "source_artifact_id", "source_sha256",
                    "toolchain_artifact_id", "toolchain_sha256", "builder_artifact_id",
                    "builder_sha256", "recipe_sha256", "outputs", "execution", "signature"}
        if (not isinstance(value, dict) or set(value) != required
                or not isinstance(value["execution"], dict)):
            raise AuthorityDenied("build.attestation", "stored build attestation fields are invalid")
        execution = value["execution"]
        if set(execution) != {"process_id", "uid", "pid", "start_ticks", "exit_code",
                              "cleanup_verified", "started_monotonic", "finished_monotonic",
                              "kernel_limits"} or not isinstance(execution["kernel_limits"], dict):
            raise AuthorityDenied("build.attestation", "stored process evidence is invalid")
        if not isinstance(value["outputs"], list) or not 1 <= len(value["outputs"]) <= MAX_OUTPUT_FILES:
            raise AuthorityDenied("build.attestation", "stored output manifest is invalid")
        outputs = []
        for raw in value["outputs"]:
            if not isinstance(raw, dict) or set(raw) != {"name", "artifact_id", "sha256", "size_bytes", "executable"}:
                raise AuthorityDenied("build.attestation", "stored output entry is malformed")
            try:
                output = BuildOutput(**raw)
                _safe_output_name(output.name)
                _sha(output.sha256, "output")
                if (type(output.size_bytes) is not int or output.size_bytes < 1
                        or type(output.executable) is not bool):
                    raise ValueError("output values")
            except (TypeError, ValueError, AuthorityDenied):
                raise AuthorityDenied("build.attestation", "stored output entry is invalid") from None
            outputs.append(output)
        if len({item.name for item in outputs}) != len(outputs):
            raise AuthorityDenied("build.attestation", "stored output names are duplicated")
        try:
            return BuildAttestation(
                schema=value["schema"], attestation_id=value["attestation_id"],
                attestation_sha256=value["attestation_sha256"], target_id=value["target_id"],
                enrollment_id=value["enrollment_id"], generation=value["generation"],
                operation_id=value["operation_id"], source_artifact_id=value["source_artifact_id"],
                source_sha256=value["source_sha256"], toolchain_artifact_id=value["toolchain_artifact_id"],
                toolchain_sha256=value["toolchain_sha256"], builder_artifact_id=value["builder_artifact_id"],
                builder_sha256=value["builder_sha256"], recipe_sha256=value["recipe_sha256"],
                outputs=tuple(outputs), process_id=execution["process_id"], process_uid=execution["uid"],
                process_pid=execution["pid"], process_start_ticks=execution["start_ticks"],
                exit_code=execution["exit_code"], cleanup_verified=execution["cleanup_verified"],
                started_monotonic=execution["started_monotonic"],
                finished_monotonic=execution["finished_monotonic"],
                kernel_limits=execution["kernel_limits"], signature=value["signature"],
            )
        except (TypeError, ValueError):
            raise AuthorityDenied("build.attestation", "stored build attestation values are invalid") from None

    def _verify_attestation(self, record: BuildAttestation, profile: Any) -> None:
        digest = hashlib.sha256(_canonical(record.unsigned_wire())).hexdigest()
        signature = hmac.new(self._key, _canonical(record.to_wire() | {"signature": ""}),
                             hashlib.sha256).hexdigest()
        expected = dict(profile.output_specs)
        actual = {item.name: item for item in record.outputs}
        expected_outputs = {
            name: (spec.sha256, spec.size_bytes, spec.executable)
            for name, spec in expected.items()
        }
        actual_outputs = {
            name: (item.sha256, item.size_bytes, item.executable)
            for name, item in actual.items()
        }
        if (record.schema != 1 or digest != record.attestation_sha256
                or not hmac.compare_digest(signature, record.signature)
                or record.target_id != profile.target_id or record.generation != profile.generation
                or OPERATION_TARGETS.get(record.operation_id) != profile.target_id
                or record.exit_code != 0 or not record.cleanup_verified
                or record.process_uid != profile.output_owner_uid or record.process_pid <= 1
                or record.process_start_ticks <= 0
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
                or actual_outputs != expected_outputs):
            raise AuthorityDenied("build.attestation", "stored receipt does not match current root enrollment")
        for item in record.outputs:
            self.resolve_output_object(item)

    def resolve_output_object(self, output: BuildOutput) -> Path:
        role = "x" if output.executable else "d"
        if output.artifact_id != f"build-output:{output.sha256}:{role}":
            raise AuthorityDenied("build.output_id", "build output ID is malformed")
        path = self.root / "objects" / (output.sha256 + "-" + role) / "payload"
        info = path.lstat()
        mode = 0o555 if output.executable else 0o444
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
                 authority_key: bytes,
                 store: ContentAddressedBuildStore | None = None, expected_uid: int = 0,
                 monotonic: Callable[[], float] = time.monotonic):
        if type(expected_uid) is not int or os.geteuid() != expected_uid:
            raise AuthorityDenied("build.privilege", "fixed build execution requires enrolled root identity")
        if not artifact_staging_root.is_absolute():
            raise AuthorityDenied("build.artifacts", "artifact staging root must be absolute")
        self.catalog = build_catalog
        self.artifacts = artifact_catalog
        self.artifact_staging_root = artifact_staging_root
        self.launcher = launcher
        self.store = store or ContentAddressedBuildStore.root_store(authority_key=authority_key)
        if self.store.owner_uid != expected_uid:
            raise AuthorityDenied("build.store_custody", "build store owner differs from the root executor identity")
        self.expected_uid = expected_uid
        self.monotonic = monotonic

    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float, peer_pid: int, peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                or not isinstance(payload, bytes) or len(payload) > 4096
                or type(peer_pid) is not int or peer_pid <= 0 or peer_pidfd is None
                or not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0
                or authorization.request_digest != canonical_digest(payload)):
            raise AuthorityDenied("build.request", "fixed build request is malformed")
        request = self._request(payload)
        target = OPERATION_TARGETS[request["operation_id"]]
        if (authorization.operation != "process.start" or authorization.target != target
                or context.operation != "process.start"
                or context.enrollment_id != request["enrollment_id"]
                or authorization.enrollment_id != request["enrollment_id"]
                or context.generation != request["generation"]
                or authorization.generation != request["generation"]):
            raise AuthorityDenied("build.binding", "grant does not bind this fixed build operation")
        profile = self.catalog.resolve(target, request["generation"])
        if profile.target_id != target or profile.generation != request["generation"]:
            raise AuthorityDenied("build.binding", "root catalog selected another build profile")
        deadline = self.monotonic() + timeout
        self._require_live(cancelled, deadline)
        inputs = self._resolve_inputs(profile)
        self._require_live(cancelled, deadline)
        started = self.monotonic()
        job_deadline = min(deadline, started + profile.max_lifetime_seconds)
        process = self.launcher.run(
            inputs, timeout=max(0.0, job_deadline - self.monotonic()),
            cancelled=lambda: cancelled() or self.monotonic() >= job_deadline,
        )
        self._require_live(cancelled, deadline)
        attestation = self.store.publish(profile, enrollment_id=request["enrollment_id"],
                                         operation_id=request["operation_id"], process=process,
                                         cancelled=lambda: cancelled() or self.monotonic() >= deadline)
        if cancelled():
            raise AuthorityDenied("build.expired", "build authority expired before result receipt")
        return {"status": 200, "body": _canonical(attestation.to_wire()),
                "headers": {"content-type": "application/json"}, "receipt_id": attestation.attestation_id}

    def _resolve_inputs(self, profile: Any) -> ResolvedBuildInputs:
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
        output = Path(profile.output_root)
        ContentAddressedBuildStore._check_owned_directory(output, profile.output_owner_uid, mode=0o700)
        return ResolvedBuildInputs(
            profile.target_id, profile.generation, source.artifact_id, source.sha256, source.path,
            toolchain.artifact_id, toolchain.sha256, toolchain.path, builder.artifact_id,
            builder.sha256, builder.path, tuple(profile.argv_recipe), dict(profile.environment),
            output, profile.output_owner_uid, profile.max_lifetime_seconds,
        )

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
