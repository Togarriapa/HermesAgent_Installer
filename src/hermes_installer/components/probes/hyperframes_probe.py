"""Fixed offline Hyperframes render probe asset and strict result contract."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Mapping, Sequence

from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    RuntimeProfileError,
    _absolute_path,
)

HYPERFRAMES_SOURCE_REVISION = "46f6cb356785bed79e1ce7b79d7e7accc697786a"
HYPERFRAMES_SOURCE_IDENTITY = "heygen-com/hyperframes"
HYPERFRAMES_FIXTURE_RELATIVE_PATH = "composition.html"
HYPERFRAMES_FIXTURE_SOURCE_PATH = "src/hermes_installer/components/probes/hyperframes_fixture/composition.html"
HYPERFRAMES_FIXTURE_ROOT = Path(__file__).with_name("hyperframes_fixture")
HYPERFRAMES_OUTPUT_NAME = "rendered.mp4"
HYPERFRAMES_SAMPLE_FRAME_INDICES = (12, 36)
HYPERFRAMES_EXPECTED_FRAME_COUNT = 48
HYPERFRAMES_EXPECTED_DURATION_SECONDS = 2.0
_MAX_RENDER_BYTES = 10 * 1024 * 1024
_MAX_PROBE_STDOUT_BYTES = 32 * 1024
_MAX_PROBE_STDERR_BYTES = 8 * 1024
_MAX_FRAMEHASH_STDOUT_BYTES = 8 * 1024
_MAX_FRAMEHASH_STDERR_BYTES = 8 * 1024


@dataclass(frozen=True, slots=True)
class HyperframesProbeAsset:
    source_identity: str
    source_revision: str
    source_path: str
    sha256: str
    size_bytes: int
    role: str


def hyperframes_probe_asset() -> HyperframesProbeAsset:
    """Return fixed package asset provenance, derived from the shipped bytes."""
    try:
        data = HYPERFRAMES_FIXTURE_ROOT.joinpath(HYPERFRAMES_FIXTURE_RELATIVE_PATH).read_bytes()
    except OSError as exc:
        raise RuntimeError("Hyperframes fixture source asset is unavailable") from exc
    return HyperframesProbeAsset(
        HYPERFRAMES_SOURCE_IDENTITY,
        HYPERFRAMES_SOURCE_REVISION,
        HYPERFRAMES_FIXTURE_SOURCE_PATH,
        hashlib.sha256(data).hexdigest(),
        len(data),
        "root-owned local HTML render fixture; inline CSS, no remote resources",
    )


def stage_hyperframes_fixture(fixture_root: str) -> HyperframesProbeAsset:
    """Stage the exact packaged HTML in a private, owned fixture directory."""
    root = Path(_absolute_path(fixture_root, "fixture root"))
    asset = hyperframes_probe_asset()
    source = HYPERFRAMES_FIXTURE_ROOT.joinpath(HYPERFRAMES_FIXTURE_RELATIVE_PATH)
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != asset.sha256 or len(content) != asset.size_bytes:
        raise RuntimeError("Hyperframes fixture source changed during staging")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                or root_info.st_mode & 0o077 or root.resolve(strict=True) != root):
            raise RuntimeError("Hyperframes fixture directory is not private and owned")
        destination = root / HYPERFRAMES_FIXTURE_RELATIVE_PATH
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(destination, flags, 0o400)
        except FileExistsError:
            existing_info = destination.lstat()
            if (not stat.S_ISREG(existing_info.st_mode) or existing_info.st_uid != os.geteuid()
                    or existing_info.st_nlink != 1 or existing_info.st_mode & 0o222
                    or destination.read_bytes() != content):
                raise RuntimeError("Hyperframes fixture contains conflicting or mutable data")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        raise RuntimeError("Hyperframes fixture cannot be safely staged") from exc
    return asset


def build_hyperframes_framehash_invocation(ffmpeg_executable: str, work_root: str) -> ComponentInvocation:
    """Hash two fixed frames on either side of the authored scene transition."""
    ffmpeg = _absolute_path(ffmpeg_executable, "ffmpeg executable")
    work = _absolute_path(work_root, "work root")
    output = work.rstrip("/") + "/" + HYPERFRAMES_OUTPUT_NAME
    selection = "select=eq(n\\,12)+eq(n\\,36)"
    return ComponentInvocation(
        "hyperframes", ffmpeg,
        ("-v", "error", "-i", output, "-vf", selection, "-fps_mode", "passthrough",
         "-frames:v", "2", "-f", "framemd5", "pipe:1"),
        work, (), (), ("component.hyperframes.read-private-work",),
        "PRIVATE", "deny", 30, 256,
    )


def _bounded_process_text(result: object, key: str, maximum: int) -> str:
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise RuntimeError("Hyperframes fixture evidence stage did not exit successfully")
    value = result.get(key)
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise RuntimeError("Hyperframes fixture evidence exceeds its output bound")
    return value


def _private_output_digest(work_root: str) -> tuple[str, int]:
    root = Path(_absolute_path(work_root, "work root"))
    path = root / HYPERFRAMES_OUTPUT_NAME
    try:
        root_info = root.lstat()
        info = path.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                or root_info.st_mode & 0o077 or root.resolve(strict=True) != root
                or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o022
                or not 1 <= info.st_size <= _MAX_RENDER_BYTES):
            raise RuntimeError("Hyperframes render output is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_ino != info.st_ino or opened.st_dev != info.st_dev
                    or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_size != info.st_size or opened.st_size > _MAX_RENDER_BYTES):
                raise RuntimeError("Hyperframes render output changed during verification")
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "rb", closefd=False) as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    size += len(block)
                    digest.update(block)
        finally:
            os.close(fd)
        if size != info.st_size:
            raise RuntimeError("Hyperframes render output changed while being hashed")
    except OSError as exc:
        raise RuntimeError("Hyperframes render output cannot be safely read") from exc
    return digest.hexdigest(), size


def _parse_ffprobe(result: object) -> dict[str, object]:
    raw = _bounded_process_text(result, "stdout", _MAX_PROBE_STDOUT_BYTES)
    stderr = _bounded_process_text(result, "stderr", _MAX_PROBE_STDERR_BYTES)
    if stderr:
        raise RuntimeError("Hyperframes ffprobe emitted unexpected diagnostics")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("Hyperframes ffprobe returned invalid JSON") from exc
    if (not isinstance(document, dict)
            or not {"streams", "format"}.issubset(document)
            or set(document) - {"streams", "format", "programs", "stream_groups"}
            or any(document.get(key) != [] for key in ("programs", "stream_groups") if key in document)):
        raise RuntimeError("Hyperframes ffprobe result has an unexpected schema")
    streams, fmt = document.get("streams"), document.get("format")
    if not isinstance(streams, list) or len(streams) != 1 or not isinstance(fmt, dict):
        raise RuntimeError("Hyperframes output must contain exactly one video stream")
    stream = streams[0]
    if not isinstance(stream, dict) or set(stream) != {
        "index", "codec_name", "codec_type", "width", "height", "pix_fmt",
        "avg_frame_rate", "nb_read_frames",
    }:
        raise RuntimeError("Hyperframes video stream has an unexpected schema")
    if set(fmt) != {"duration", "size"}:
        raise RuntimeError("Hyperframes media format has an unexpected schema")
    frames_text = stream.get("nb_read_frames")
    size_text = fmt.get("size")
    duration_text = fmt.get("duration")
    fps = stream.get("avg_frame_rate")
    if (type(stream.get("index")) is not int or stream.get("index") != 0
            or stream.get("codec_type") != "video"
            or stream.get("codec_name") != "h264" or stream.get("pix_fmt") != "yuv420p"
            or stream.get("width") != 320 or stream.get("height") != 180
            or fps != "24/1" or frames_text != str(HYPERFRAMES_EXPECTED_FRAME_COUNT)
            or not isinstance(size_text, str) or not re.fullmatch(r"[1-9][0-9]{0,7}", size_text)
            or not isinstance(duration_text, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", duration_text)):
        raise RuntimeError("Hyperframes output media facts do not match the fixed fixture")
    duration = float(duration_text)
    file_size = int(size_text)
    if (not math.isfinite(duration) or abs(duration - HYPERFRAMES_EXPECTED_DURATION_SECONDS) > 1 / 24
            or not 1 <= file_size <= _MAX_RENDER_BYTES):
        raise RuntimeError("Hyperframes output duration or size is outside fixture bounds")
    return {
        "codec": "h264", "pixel_format": "yuv420p", "width": 320, "height": 180,
        "frame_rate": "24/1", "frame_count": HYPERFRAMES_EXPECTED_FRAME_COUNT,
        "duration_seconds": duration, "container_bytes": file_size,
        "audio_streams": 0,
    }


def _parse_framehash(result: object) -> tuple[str, int]:
    raw = _bounded_process_text(result, "stdout", _MAX_FRAMEHASH_STDOUT_BYTES)
    stderr = _bounded_process_text(result, "stderr", _MAX_FRAMEHASH_STDERR_BYTES)
    if stderr:
        raise RuntimeError("Hyperframes frame sampler emitted unexpected diagnostics")
    headers = [line.strip() for line in raw.splitlines()]
    if ("#tb 0: 1/24" not in headers or "#dimensions 0: 320x180" not in headers
            or not any(re.fullmatch(r"#stream#,\s*dts,\s*pts,\s*duration,\s*size,\s*hash", line)
                       for line in headers)):
        raise RuntimeError("Hyperframes frame sampler returned an unexpected header")
    hashes: list[str] = []
    sampled_indices: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [part.strip() for part in line.split(",")]
        if (len(fields) != 6 or fields[0] != "0" or fields[1] not in {"12", "36"}
                or fields[2] != fields[1] or fields[3] != "1" or fields[4] != "86400"
                or not re.fullmatch(r"[0-9a-f]{32}", fields[5])):
            raise RuntimeError("Hyperframes frame sampler returned an unexpected frame record")
        hashes.append(fields[5])
        sampled_indices.append(fields[1])
    if (sampled_indices != ["12", "36"] or len(hashes) != 2 or hashes[0] == hashes[1]):
        raise RuntimeError("Hyperframes render did not produce two visually distinct fixture scenes")
    evidence = "\n".join(hashes).encode("ascii")
    return hashlib.sha256(evidence).hexdigest(), len(hashes)


def verify_hyperframes_probe_results(results: object, work_roots: Mapping[str, str]) -> dict[str, object]:
    """Validate every fixed stage and return bounded semantic evidence."""
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)) or len(results) != 3:
        raise RuntimeError("Hyperframes fixture requires render, ffprobe, and framehash evidence")
    render, probe, framehash = results
    _bounded_process_text(render, "stdout", _MAX_PROBE_STDOUT_BYTES)
    _bounded_process_text(render, "stderr", _MAX_PROBE_STDERR_BYTES)
    media = _parse_ffprobe(probe)
    frame_digest, sample_count = _parse_framehash(framehash)
    output_digest, output_bytes = _private_output_digest(work_roots["hyperframes"])
    asset = hyperframes_probe_asset()
    return {
        "source_identity": asset.source_identity,
        "source_revision": asset.source_revision,
        "source_asset_path": asset.source_path,
        "source_asset_sha256": asset.sha256,
        "source_asset_bytes": asset.size_bytes,
        "render_output_sha256": output_digest,
        "render_output_bytes": output_bytes,
        "media": media,
        "frame_change_sha256": frame_digest,
        "distinct_sampled_frames": sample_count,
        "fixture_state": "functional_local_render_passed",
        "metered_cost_usd": "0",
        "network": "deny",
    }
