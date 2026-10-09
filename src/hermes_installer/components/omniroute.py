"""Pinned, isolated OmniRoute build profile and fail-closed route policy.

The upstream app contains broad provider, fallback, compression, plugin, and
account features. This adapter therefore never copies credentials into its data
directory and never starts the app unless the host has enrolled a loopback-only
service process with provider egress forced through the authority broker.
Source/build preparation is separate from service admission and route proof.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol

from hermes_installer.components.application_handlers import ComponentInvocation
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.state import OwnedRoot, OwnershipError


OMNIROUTE_COMPONENT = "omniroute"
OMNIROUTE_SOURCE_IDENTITY = "diegosouzapw/OmniRoute"
OMNIROUTE_SOURCE_REVISION = "4ea24a2f8e1faf8a606c8b8dce45e5b1ab6c9bb0"
OMNIROUTE_VERSION = "3.8.52"
NODE_VERSION = "26.7.0"
NODE_ARTIFACT_SHA256 = "afc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d"
NODE_ENGINE = ">=22.22.2 <23 || >=24.0.0 <27"
_MAX_SOURCE_FILES = 50_000
_MAX_SOURCE_BYTES = 512 * 1024 * 1024


class OmniRouteError(RuntimeError):
    """Safe unavailable or invalid pinned OmniRoute operation."""


@dataclass(frozen=True, slots=True)
class OmniRouteSource:
    revision: str
    version: str
    node_engine: str
    package_lock_sha256: str
    source_tree_sha: str
    source_content_sha256: str
    redistribution_review_required: bool


@dataclass(frozen=True, slots=True)
class OmniRouteNodeRuntime:
    """Root-resolved exact component-owned Node runtime evidence."""

    root: str
    node_executable: str
    npm_executable: str
    version: str
    architecture: str
    artifact_sha256: str
    executable_sha256: str
    generation_id: str

    def validate(self) -> None:
        root = _absolute(self.root, "Node runtime root")
        node = _absolute(self.node_executable, "Node executable")
        npm = _absolute(self.npm_executable, "npm executable")
        if (self.version != NODE_VERSION or self.architecture != "aarch64"
                or self.artifact_sha256 != NODE_ARTIFACT_SHA256
                or not _inside(node, root) or not _inside(npm, root)
                or not node.endswith("/bin/node") or not npm.endswith("/bin/npm")
                or not re.fullmatch(r"[0-9a-f]{64}", self.executable_sha256)
                or not self.generation_id or len(self.generation_id) > 128):
            raise OmniRouteError("OmniRoute requires the protected Node 26.7.0 linux-arm64 catalog runtime")


def _absolute(value: str, name: str) -> str:
    path = PurePosixPath(value)
    if not isinstance(value, str) or not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise OmniRouteError(f"{name} must be a normalized absolute protected path")
    return path.as_posix()


def _inside(child: str, parent: str) -> bool:
    return child.startswith(parent.rstrip("/") + "/")


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def validate_omniroute_source(source: VerifiedComponentSource) -> OmniRouteSource:
    """Check the pinned source identity and package/lock declarations offline."""
    if (not isinstance(source, VerifiedComponentSource)
            or source.component_id != OMNIROUTE_COMPONENT
            or source.source_identity != OMNIROUTE_SOURCE_IDENTITY
            or source.revision != OMNIROUTE_SOURCE_REVISION):
        raise OmniRouteError("selected OmniRoute source does not match the reviewed immutable pin")
    try:
        package_bytes = source.files["package.json"]
        lock_bytes = source.files["package-lock.json"]
        package = json.loads(package_bytes)
        lock = json.loads(lock_bytes)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise OmniRouteError("pinned OmniRoute package manifest or lock is missing or malformed") from None
    engines = package.get("engines") if isinstance(package, dict) else None
    root_lock = lock.get("packages", {}).get("") if isinstance(lock, dict) else None
    if (not isinstance(package, dict) or package.get("name") != "omniroute"
            or package.get("version") != OMNIROUTE_VERSION
            or engines != {"node": NODE_ENGINE}
            or package.get("license") != "MIT"
            or not isinstance(lock, dict) or lock.get("lockfileVersion") not in {2, 3}
            or not isinstance(root_lock, dict) or root_lock.get("version") != OMNIROUTE_VERSION
            or not isinstance(source.source_tree_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40}", source.source_tree_sha)
            or not isinstance(source.content_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source.content_sha256)):
        raise OmniRouteError("OmniRoute manifest, Node engine, lock root, or source pin differs from review")
    return OmniRouteSource(
        source.revision, package["version"], engines["node"], _sha256(lock_bytes),
        source.source_tree_sha, source.content_sha256,
        bool(source.redistribution_license_review_required),
    )


def stage_omniroute_build_workspace(
    source: VerifiedComponentSource, root: OwnedRoot, relative: str = "work/omniroute-build",
) -> str:
    """Copy verified pinned files to a new private writable build workspace.

    GenerationStore source trees remain immutable; npm and the app build write
    generated files only into this new installer-owned directory.
    """
    validate_omniroute_source(source)
    if not isinstance(root, OwnedRoot):
        raise TypeError("OmniRoute build workspaces require an OwnedRoot")
    try:
        root.ensure()
        destination = root.path(relative)
    except OwnershipError as exc:
        raise OmniRouteError("OmniRoute build workspace root is not installer-owned") from exc
    destination = _absolute(destination.as_posix(), "OmniRoute build workspace")
    workspace = Path(destination)
    if len(source.files) > _MAX_SOURCE_FILES or sum(map(len, source.files.values())) > _MAX_SOURCE_BYTES:
        raise OmniRouteError("verified OmniRoute source exceeds build workspace bounds")
    try:
        workspace.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name in sorted(source.files):
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise OmniRouteError("pinned OmniRoute source contains an unsafe path")
            parent = workspace
            for segment in relative.parts[:-1]:
                parent = parent / segment
                try:
                    parent.mkdir(mode=0o700)
                except FileExistsError:
                    info = parent.lstat()
                    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        raise OmniRouteError("OmniRoute source path collides with a non-directory")
            target = parent / relative.name
            mode = source.file_modes.get(name)
            if mode not in {0o100644, 0o100755, 0o644, 0o755}:
                raise OmniRouteError("pinned OmniRoute source contains an unsupported file mode")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(target, flags, 0o700 if mode in {0o100755, 0o755} else 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(source.files[name])
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(target, 0o700 if mode in {0o100755, 0o755} else 0o600)
    except OmniRouteError:
        try:
            if workspace.is_dir() and not workspace.is_symlink():
                import shutil
                shutil.rmtree(workspace)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            if workspace.is_dir() and not workspace.is_symlink():
                import shutil
                shutil.rmtree(workspace)
        except OSError:
            pass
        raise OmniRouteError("could not stage the pinned OmniRoute source workspace") from exc
    return workspace.as_posix()


def build_omniroute_install_invocations(
    *, source: OmniRouteSource, runtime: OmniRouteNodeRuntime,
    source_workspace: str,
) -> tuple[ComponentInvocation, ComponentInvocation]:
    """Describe offline dependency install and fixed backend build stages."""
    runtime.validate()
    workspace = _absolute(source_workspace, "OmniRoute source workspace")
    if (source.revision != OMNIROUTE_SOURCE_REVISION or source.version != OMNIROUTE_VERSION
            or not re.fullmatch(r"[0-9a-f]{64}", source.package_lock_sha256)):
        raise OmniRouteError("OmniRoute build inputs are not pinned")
    base_env = (
        ("PATH", runtime.root.rstrip("/") + "/bin:/usr/bin:/bin"),
        ("npm_config_offline", "true"),
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("NPM_CONFIG_USERCONFIG", "/dev/null"),
        ("NPM_CONFIG_GLOBALCONFIG", "/dev/null"),
        ("NPM_CONFIG_CACHE", workspace.rstrip("/") + "/.installer-npm-cache"),
    )
    install = ComponentInvocation(
        OMNIROUTE_COMPONENT, runtime.npm_executable,
        (runtime.npm_executable, "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"),
        workspace, base_env, (), ("component.omniroute.install",), "PRIVATE", "deny", 1800, 6144,
    )
    build = ComponentInvocation(
        OMNIROUTE_COMPONENT, runtime.npm_executable,
        (runtime.npm_executable, "run", "build:backend"), workspace,
        base_env + (("NODE_ENV", "production"), ("NEXT_TELEMETRY_DISABLED", "1")),
        (), ("component.omniroute.build",), "PRIVATE", "deny", 2400, 6144,
    )
    return install, build


@dataclass(frozen=True, slots=True)
class OmniRoutePolicy:
    """Single-route policy that the protected host must enforce at egress."""

    alias: str
    target: str
    recipient: str
    model: str
    additional_metered_fee_usd: int = 0
    allowed_sensitivities: frozenset[str] = frozenset({"public"})
    fallback_models: tuple[str, ...] = ()
    retry_limit: int = 0
    compression_enabled: bool = False
    plugin_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        from hermes_installer.provider_effect_handlers import (
            OPENROUTER_MODEL, PROVIDER_RECIPIENT, canonical_provider_target,
        )
        if (not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", self.alias)
                or self.target != canonical_provider_target(OPENROUTER_MODEL)
                or self.recipient != PROVIDER_RECIPIENT or self.model != OPENROUTER_MODEL
                or self.additional_metered_fee_usd != 0
                or self.allowed_sensitivities != frozenset({"public"})
                or self.fallback_models or self.retry_limit != 0
                or self.compression_enabled or self.plugin_ids):
            raise OmniRouteError("OmniRoute route is not the exact public-only zero-budget mediated route")


class NativeProviderBridge(Protocol):
    def dispatch_native_request(
        self, handle: object, normalized_payload: bytes, *, retry_index: int,
        timeout: float, cancelled: Callable[[], bool] | None = None,
    ) -> object: ...


class OmniRouteGatewayAdapter:
    """Translate one selected OmniRoute request into the atomic HI11 bridge.

    The opaque event handle is only a lookup reference. AuthorityService must
    authenticate this gateway peer and verify/consume the complete native event
    before any provider effect. This adapter never retries; callers must obtain a
    fresh event handle for every retry and send its original retry index.
    """

    _FORBIDDEN_FIELDS = frozenset({
        "fallback", "fallbacks", "providers", "provider", "provider_options",
        "compression", "transforms", "route",
    })

    def __init__(self, *, policy: OmniRoutePolicy,
                 root_selected_enrollments: Callable[[], Mapping[tuple[str, str], object]],
                 authority: NativeProviderBridge):
        policy.validate()
        if not callable(root_selected_enrollments) or not callable(
            getattr(authority, "dispatch_native_request", None)
        ):
            raise OmniRouteError("OmniRoute requires the host native-event broker adapter")
        self.policy = policy
        self._root_routes = root_selected_enrollments
        self._authority = authority

    def dispatch(self, *, native_event_handle: object, payload: bytes,
                 retry_index: int = 0, timeout: float = 30.0,
                 cancelled: Callable[[], bool] | None = None) -> object:
        from hermes_installer.provider_effect_handlers import canonical_provider_request

        self.policy.validate()
        if (not isinstance(native_event_handle, str) or not native_event_handle
                or len(native_event_handle) > 512 or isinstance(retry_index, bool)
                or not isinstance(retry_index, int) or retry_index < 0
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 30.0 or cancelled is not None and not callable(cancelled)):
            raise OmniRouteError("OmniRoute event handle, retry index, or timeout is invalid")
        if cancelled and cancelled():
            raise TimeoutError("OmniRoute request was cancelled")
        try:
            value = json.loads(payload, object_pairs_hook=_unique_json_pairs,
                               parse_constant=lambda _item: (_ for _ in ()).throw(ValueError("constant")))
        except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
            raise OmniRouteError("OmniRoute request must be bounded valid JSON") from None
        if not isinstance(value, dict) or self._FORBIDDEN_FIELDS.intersection(value):
            raise OmniRouteError("OmniRoute route overrides, compression, and fallbacks are disabled")
        if value.get("model") not in {self.policy.alias, self.policy.model}:
            raise OmniRouteError("OmniRoute model is outside the single enrolled route")
        value["model"] = self.policy.model
        try:
            normalized_input = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False, allow_nan=False).encode("utf-8")
            root_routes = self._root_routes()
            body, target, recipient, _capability, model = canonical_provider_request(
                root_routes, normalized_input
            )
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
            raise OmniRouteError("OmniRoute request could not be normalized safely") from exc
        if (target, recipient, model) != (self.policy.target, self.policy.recipient, self.policy.model):
            raise OmniRouteError("OmniRoute request does not match the enrolled route")
        if cancelled and cancelled():
            raise TimeoutError("OmniRoute request was cancelled")
        return self._authority.dispatch_native_request(
            native_event_handle, body, retry_index=retry_index,
            timeout=float(timeout), cancelled=cancelled,
        )


def deduplicate_omniroute_aliases(names: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve the selected seed aliases to one adapter registration."""
    normalized = {item.strip().casefold() for item in names if isinstance(item, str) and item.strip()}
    if not normalized <= {"omniroute", "omniroute; omniroute"}:
        raise OmniRouteError("unknown OmniRoute alias")
    return (OMNIROUTE_COMPONENT,) if normalized else ()


def build_omniroute_service_invocation(
    *, source_root: str, node_runtime: OmniRouteNodeRuntime,
    data_root: str, policy: OmniRoutePolicy | None,
    host_network_profile_id: str | None,
) -> ComponentInvocation:
    """Create a root-reviewable loopback service invocation or stay unavailable.

    `host_network_profile_id` names an enrollment enforced by host custody; it
    must route provider effects only through the fixed authority broker. This
    adapter does not start OmniRoute or treat a caller-provided config as proof.
    """
    if policy is None or not host_network_profile_id:
        raise OmniRouteError("OmniRoute service is unavailable until host broker and route enrollment are installed")
    policy.validate()
    node_runtime.validate()
    source = _absolute(source_root, "OmniRoute runtime root")
    data = _absolute(data_root, "OmniRoute data root")
    if len(host_network_profile_id) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host_network_profile_id):
        raise OmniRouteError("OmniRoute host egress profile reference is invalid")
    return ComponentInvocation(
        OMNIROUTE_COMPONENT, node_runtime.npm_executable,
        (node_runtime.npm_executable, "run", "start"), source,
        (
            ("PATH", node_runtime.root.rstrip("/") + "/bin:/usr/bin:/bin"),
            ("NODE_ENV", "production"),
            ("HOSTNAME", "127.0.0.1"),
            ("PORT", "20128"),
            ("DATA_DIR", data),
            ("NEXT_PUBLIC_BASE_URL", "http://127.0.0.1:20128"),
            ("NEXT_PUBLIC_CLOUD_URL", ""),
            ("REQUIRE_API_KEY", "true"),
            ("ALLOW_API_KEY_REVEAL", "false"),
            ("APP_LOG_TO_FILE", "false"),
            ("NEXT_TELEMETRY_DISABLED", "1"),
        ),
        (),
        ("component.omniroute.run", "provider-dispatch", "host-profile:" + host_network_profile_id),
        "PRIVATE", "provider-dispatch", 86_400, 4096,
    )
