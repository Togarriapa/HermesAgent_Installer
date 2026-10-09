"""Packaged, provenance-checked isolated-runtime lock material."""
from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from importlib.resources import files as package_files

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.isolated_locks import lockfile_errors
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree


SOURCE_REVISION = "c75e8476e26d18b7617643bc2ae082fae8eae431"
UPSTREAM_PYPROJECT_SHA256 = "5a61c6cc0b66c5e51972c7deeabefe00cf9a8127d7408bdbf3e573bdaf582f87"
OVERLAY_PYPROJECT_SHA256 = "7364254e748c9b74824d9b8de04dfcfabe5bcc0593e64b1610df686a27909435"
UV_LOCK_SHA256 = "d6798e0a02810515973a6fabd87ec9db7d9bcf77ac6a54a78cc15f04112c9b38"
_SOURCE_ID = "browser-use/browser-use"


class LockedRuntimeError(ValueError):
    """Packaged isolated-runtime evidence is missing or does not match its pin."""


@dataclass(frozen=True, slots=True)
class BrowserUseLockBundle:
    upstream_pyproject: bytes
    overlay_pyproject: bytes
    uv_lock: bytes
    provenance: bytes


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def load_browser_use_lock_bundle(*, source_pyproject: bytes | None = None) -> BrowserUseLockBundle:
    """Load committed lock inputs and verify every source/overlay/lock digest."""
    root = package_files("hermes_installer.components").joinpath("runtime_locks").joinpath("browser-use")
    try:
        upstream = root.joinpath("upstream-pyproject.toml").read_bytes()
        overlay = root.joinpath("pyproject.toml").read_bytes()
        lock = root.joinpath("uv.lock").read_bytes()
        provenance = root.joinpath("provenance.json").read_bytes()
        record = json.loads(provenance)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise LockedRuntimeError(f"packaged Browser Use lock bundle is incomplete: {exc}") from None
    expected = {
        "source_revision": SOURCE_REVISION,
        "source_url": "https://github.com/browser-use/browser-use",
        "python": "3.14",
        "platform": "aarch64-unknown-linux-gnu",
        "runner_architecture": "aarch64",
        "generated_in_ci": True,
        "installed_dependencies": True,
        "functional_browser_fixture": True,
        "pyproject_sha256": UPSTREAM_PYPROJECT_SHA256,
        "overlay_pyproject_sha256": OVERLAY_PYPROJECT_SHA256,
        "uv_lock_sha256": UV_LOCK_SHA256,
    }
    if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
        raise LockedRuntimeError("Browser Use lock provenance does not match the reviewed ARM64/Python 3.14 pin")
    if (_sha256(upstream) != UPSTREAM_PYPROJECT_SHA256
        or _sha256(overlay) != OVERLAY_PYPROJECT_SHA256
        or _sha256(lock) != UV_LOCK_SHA256):
        raise LockedRuntimeError("Browser Use lock bundle content digest mismatch")
    if source_pyproject is not None and source_pyproject != upstream:
        raise LockedRuntimeError("selected Browser Use source manifest differs from the lock provenance")
    if lockfile_errors("uv.lock", lock):
        raise LockedRuntimeError("Browser Use uv.lock fails structural validation")
    try:
        parsed = tomllib.loads(lock.decode("utf-8"))
        markers = " ".join(parsed.get("resolution-markers", []))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise LockedRuntimeError("Browser Use uv.lock is not valid TOML") from None
    if "linux" not in markers or "aarch64" not in markers or "3.14" not in markers:
        raise LockedRuntimeError("Browser Use uv.lock lacks its Linux ARM64/Python 3.14 resolution")
    if not parsed.get("package"):
        raise LockedRuntimeError("Browser Use uv.lock contains no resolved packages")
    return BrowserUseLockBundle(upstream, overlay, lock, provenance)


def stage_browser_use_runtime(source: VerifiedComponentSource, store: GenerationStore):
    """Stage the complete pinned source with the reviewed overlay and uv lock.

    The upstream manifest is preserved at a dedicated evidence path; the root
    pyproject is replaced only in this distinct installer-owned runtime
    generation so `uv sync --locked` consumes the exact reviewed lock.
    """
    contract = resolve_component_adapter("browser-use")
    if (source.component_id != contract.component_id or source.source_identity != _SOURCE_ID
        or source.revision != SOURCE_REVISION or contract.revision != SOURCE_REVISION):
        raise LockedRuntimeError("selected Browser Use tree does not match the immutable runtime pin")
    original = source.files.get("pyproject.toml")
    if not isinstance(original, bytes):
        raise LockedRuntimeError("pinned Browser Use source is missing pyproject.toml")
    upstream_files = {
        name: body for name, body in source.files.items()
        if name != "INSTALLER-SOURCE-PROVENANCE.json"
    }
    upstream_modes = {name: mode for name, mode in source.file_modes.items() if name in upstream_files}
    source_provenance = source.files.get("INSTALLER-SOURCE-PROVENANCE.json")
    try:
        provenance_record = json.loads(source_provenance)
        source_tree, _ = _git_tree(upstream_files, upstream_modes)
        content_digest = hashlib.sha256()
        for name in sorted(upstream_files):
            content_digest.update(name.encode("utf-8") + b"\0")
            content_digest.update(f"{upstream_modes[name]:o}".encode("ascii") + b"\0")
            content_digest.update(hashlib.sha256(upstream_files[name]).digest())
    except Exception as exc:
        raise LockedRuntimeError(f"pinned Browser Use source provenance is invalid: {exc}") from None
    if (source_tree != source.source_tree_sha
        or provenance_record.get("component_id") != source.component_id
        or provenance_record.get("source_identity") != source.source_identity
        or provenance_record.get("revision") != source.revision
        or provenance_record.get("source_tree_sha") != source.source_tree_sha
        or provenance_record.get("source_content_sha256") != source.content_sha256
        or content_digest.hexdigest() != source.content_sha256):
        raise LockedRuntimeError("pinned Browser Use source tree and provenance do not agree")
    bundle = load_browser_use_lock_bundle(source_pyproject=original)
    files = dict(source.files)
    if "INSTALLER-UPSTREAM-PYPROJECT.toml" in files or "uv.lock" in files:
        raise LockedRuntimeError("upstream Browser Use tree conflicts with runtime lock evidence paths")
    files["INSTALLER-UPSTREAM-PYPROJECT.toml"] = bundle.upstream_pyproject
    files["pyproject.toml"] = bundle.overlay_pyproject
    files["uv.lock"] = bundle.uv_lock
    files["INSTALLER-RUNTIME-LOCK-PROVENANCE.json"] = bundle.provenance
    modes = dict(source.file_modes)
    modes["INSTALLER-UPSTREAM-PYPROJECT.toml"] = 0o644
    modes["pyproject.toml"] = 0o644
    modes["uv.lock"] = 0o644
    modes["INSTALLER-RUNTIME-LOCK-PROVENANCE.json"] = 0o644
    generation_id = f"browser-use-runtime-{SOURCE_REVISION[:12]}"
    target = store.root / generation_id
    if target.exists() or target.is_symlink():
        try:
            existing, manifest, _ = store._verify(generation_id)
        except Exception as exc:
            raise LockedRuntimeError("existing Browser Use runtime generation is not verified") from exc
        expected_files = {
            name: {
                "sha256": _sha256(body),
                "mode": store._private_mode(modes[name]),
            }
            for name, body in files.items()
        }
        if manifest.get("files") != expected_files:
            raise LockedRuntimeError("existing Browser Use runtime generation conflicts with packaged lock inputs")
        return existing
    return store.stage(generation_id, files, file_modes=modes)
