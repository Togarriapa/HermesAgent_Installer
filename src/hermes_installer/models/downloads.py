"""Capacity-aware resumable download and atomic model-generation activation."""
from __future__ import annotations

import errno
import json
import os
import shutil
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .artifacts import ArtifactError, ArtifactManifest, ArtifactFile

CHUNK_SIZE = 1024 * 1024


class DownloadCancelled(RuntimeError):
    pass


class InsufficientSpace(OSError):
    pass


@dataclass(frozen=True, slots=True)
class StorageReserve:
    os_bytes: int
    hermes_bytes: int
    user_data_bytes: int
    cache_bytes: int
    log_bytes: int
    recovery_bytes: int
    conversion_temporary_bytes: int = 0
    rollback_bytes: int = 0

    def __post_init__(self) -> None:
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in asdict(self).values()):
            raise ValueError("all storage reserves must be non-negative byte counts")


@dataclass(frozen=True, slots=True)
class StoragePlan:
    model_download_bytes: int
    model_final_bytes: int
    conversion_temporary_bytes: int
    rollback_bytes: int
    system_reserve_bytes: int
    peak_required_bytes: int
    free_bytes: int
    sufficient: bool
    generic_backup_model_copy_bytes: int = 0


def estimate_storage(manifest: ArtifactManifest, path: Path, reserve: StorageReserve, *, free_bytes: int | None = None) -> StoragePlan:
    """Report the peak in-progress footprint, retaining the old generation for rollback.

    Download staging is renamed into place, so it is not counted twice as both a
    download and a final copy. The existing generation remains charged separately.
    """
    if free_bytes is None:
        free_bytes = shutil.disk_usage(path).free
    if isinstance(free_bytes, bool) or not isinstance(free_bytes, int) or free_bytes < 0:
        raise ValueError("free_bytes must be a non-negative integer")
    system = sum((reserve.os_bytes, reserve.hermes_bytes, reserve.user_data_bytes,
                  reserve.cache_bytes, reserve.log_bytes, reserve.recovery_bytes))
    model_peak = max(manifest.total_bytes, manifest.total_bytes + reserve.conversion_temporary_bytes)
    peak = system + model_peak + reserve.rollback_bytes
    return StoragePlan(manifest.total_bytes, manifest.total_bytes, reserve.conversion_temporary_bytes,
                       reserve.rollback_bytes, system, peak, free_bytes, free_bytes >= peak)


def _cancelled(cancel: threading.Event | Callable[[], bool] | None) -> bool:
    if cancel is None:
        return False
    return cancel.is_set() if isinstance(cancel, threading.Event) else bool(cancel())


def _check_expected_digest(item: ArtifactFile, path: Path) -> None:
    item.verify(path)


def download_file(item: ArtifactFile, destination: Path, *, cancel: threading.Event | Callable[[], bool] | None = None,
                  timeout: float = 30.0, opener: Callable[..., object] | None = None,
                  progress: Callable[[int, int], None] | None = None) -> Path:
    """Download one pinned object via HTTP Range and publish only after full verification."""
    if timeout <= 0 or timeout > 120:
        raise ValueError("download timeout must be between 0 and 120 seconds")
    if not item.digest or not item.digest_algorithm:
        raise ArtifactError(f"no verified digest is available for {item.name}; download activation is blocked")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise PermissionError("model download parent must not be a symlink")
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise PermissionError("model destination is not a regular file")
        _check_expected_digest(item, destination)
        return destination
    part = destination.with_name(destination.name + ".part")
    if part.is_symlink() or (part.exists() and not part.is_file()):
        raise PermissionError("model partial path is not a regular file")
    offset = part.stat().st_size if part.exists() else 0
    if offset > item.size:
        raise ArtifactError(f"partial file exceeds the pinned size for {item.name}")
    headers = {"User-Agent": "HermesInstaller/1.0", "Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    if offset == item.size:
        _check_expected_digest(item, part)
        os.replace(part, destination)
        return destination
    request = urllib.request.Request(item.url, headers=headers)
    open_url = opener or urllib.request.urlopen
    try:
        response = open_url(request, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OSError(f"model download failed for {item.name}: {exc}") from exc
    try:
        status = getattr(response, "status", None) or getattr(response, "code", None) or 200
        response_headers = getattr(response, "headers", {})
        append = offset > 0 and status == 206
        if append:
            expected_range = f"bytes {offset}-{item.size - 1}/{item.size}"
            if response_headers.get("Content-Range") != expected_range:
                raise ArtifactError(f"server returned an invalid Content-Range for {item.name}")
        elif status == 200:
            # Server ignored Range: restart safely instead of appending duplicate bytes.
            offset = 0
        else:
            raise ArtifactError(f"server did not provide a resumable/full response for {item.name}: HTTP {status}")
        remaining = item.size - offset
        mode = "ab" if append else "wb"
        received = offset
        try:
            with part.open(mode) as stream:
                while True:
                    if _cancelled(cancel):
                        raise DownloadCancelled(f"download cancelled for {item.name}; verified prefix retained for resume")
                    block = response.read(min(CHUNK_SIZE, remaining + 1))
                    if not block:
                        break
                    if len(block) > remaining:
                        part.unlink(missing_ok=True)
                        raise ArtifactError(f"server sent more than the pinned size for {item.name}")
                    stream.write(block)
                    received += len(block)
                    remaining -= len(block)
                    if progress:
                        progress(received, item.size)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise InsufficientSpace(f"disk filled while downloading {item.name}; the previous model remains untouched") from exc
            raise
    finally:
        close = getattr(response, "close", None)
        if close:
            close()
    if received != item.size:
        raise OSError(f"incomplete download for {item.name}: received {received} of {item.size} bytes; rerun to resume")
    try:
        _check_expected_digest(item, part)
    except ArtifactError:
        part.unlink(missing_ok=True)
        raise
    os.replace(part, destination)
    fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return destination


def verify_existing_model(manifest: ArtifactManifest, path: Path) -> Path:
    """Verify an existing user-selected model directory without copying it."""
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_dir() or path.is_symlink():
        raise ArtifactError("existing model path must be a real directory, not a symlink")
    manifest.verify_directory(resolved)
    return resolved


def download_generation(manifest: ArtifactManifest, model_root: Path, *, selected: bool,
                        reserve: StorageReserve, cancel: threading.Event | Callable[[], bool] | None = None,
                        opener: Callable[..., object] | None = None,
                        progress: Callable[[str, int, int], None] | None = None) -> Path:
    """Download into a resumable owned staging directory and publish a complete generation."""
    if not selected:
        raise PermissionError("the 429 GB GLM-5.2 download requires an explicit model selection")
    if not manifest.fully_verifiable:
        missing = next(f.name for f in manifest.files if not f.digest or not f.digest_algorithm)
        raise ArtifactError(f"no verified digest is available for {missing}; activation is blocked")
    model_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if model_root.is_symlink() or not model_root.is_dir():
        raise PermissionError("model root must be an owned real directory")
    plan = estimate_storage(manifest, model_root, reserve)
    if not plan.sufficient:
        raise InsufficientSpace(f"GLM-5.2 requires {plan.peak_required_bytes} bytes including configured reserves; only {plan.free_bytes} bytes are free")
    final = model_root / manifest.fingerprint
    stage = model_root / (".stage-" + manifest.fingerprint)
    if final.exists() or final.is_symlink():
        if final.is_symlink() or not final.is_dir():
            raise PermissionError("existing model generation path is not a real directory")
        manifest.verify_directory(final)
        return final
    if stage.is_symlink() or (stage.exists() and not stage.is_dir()):
        raise PermissionError("existing model staging path is not a real directory")
    stage.mkdir(mode=0o700, exist_ok=True)
    for item in manifest.files:
        if _cancelled(cancel):
            raise DownloadCancelled("GLM-5.2 selection cancelled; verified shard prefixes are retained")
        result_path = stage.joinpath(*item.name.split("/"))
        result_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if result_path.exists():
            if result_path.is_symlink():
                raise PermissionError(f"staged model path is a symlink: {item.name}")
            _check_expected_digest(item, result_path)
            continue
        download_file(item, result_path, cancel=cancel, opener=opener,
            progress=(lambda got, total, name=item.name: progress(name, got, total)) if progress else None)
    manifest.verify_directory(stage)
    marker = stage / ".hermes-model-generation.json"
    data = {"schema": 1, "model_id": manifest.model_id, "revision": manifest.revision,
            "manifest_sha256": manifest.fingerprint, "bytes": manifest.total_bytes,
            "verified_at": int(time.time()), "activation": "pending"}
    marker.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    marker.chmod(0o400)
    marker_fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(marker_fd)
    finally:
        os.close(marker_fd)
    stage_fd = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(stage_fd)
    finally:
        os.close(stage_fd)
    os.replace(stage, final)
    fd = os.open(model_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return final


def activate_generation(model_root: Path, generation: Path, manifest: ArtifactManifest) -> Path:
    """Atomically swap the managed `current` pointer after complete manifest verification."""
    if model_root.is_symlink() or generation.is_symlink():
        raise PermissionError("model root and generation paths must not be symlinks")
    root = model_root.resolve(strict=True)
    candidate = generation.resolve(strict=True)
    if candidate.parent != root or candidate.name != manifest.fingerprint:
        raise ArtifactError("generation is outside the model root or does not match this manifest")
    manifest.verify_directory(candidate)
    pointer = root / "current"
    if pointer.exists() and not pointer.is_symlink():
        raise PermissionError("refusing to replace an unowned non-symlink current path")
    if pointer.is_symlink():
        prior_name = os.readlink(pointer)
        prior_rel = Path(prior_name)
        if prior_rel.is_absolute() or len(prior_rel.parts) != 1 or prior_rel.name in {".", ".."}:
            raise PermissionError("refusing to replace a current pointer outside the model root")
        prior = root / prior_rel
        marker = prior / ".hermes-model-generation.json"
        if prior.is_symlink() or not prior.is_dir() or marker.is_symlink() or not marker.is_file():
            raise PermissionError("refusing to replace a current pointer to an unowned generation")
        try:
            prior_data = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PermissionError("current pointer does not identify a valid managed generation") from exc
        if prior_data.get("schema") != 1 or prior_data.get("model_id") != manifest.model_id:
            raise PermissionError("current pointer belongs to a different or unowned model")
    marker = candidate / ".hermes-model-generation.json"
    if marker.is_symlink() or not marker.is_file():
        raise ArtifactError("generation is missing its immutable ownership marker")
    try:
        marker_data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError("generation ownership marker is invalid") from exc
    if (marker_data.get("schema") != 1 or marker_data.get("model_id") != manifest.model_id
            or marker_data.get("revision") != manifest.revision
            or marker_data.get("manifest_sha256") != manifest.fingerprint):
        raise ArtifactError("generation ownership marker does not match the pinned GLM-5.2 manifest")
    temporary = root / (".current-" + uuid.uuid4().hex)
    os.symlink(candidate.name, temporary)
    try:
        os.replace(temporary, pointer)
        fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    return candidate
