"""Fixed, offline builder for selected pre-active Python applications.

This is a standalone source-owned driver.  The managed build recipe invokes it
with the held PM Python in isolated mode; it accepts no command-line input and
reads only the fixed mounts below.  Selection facts are written by the root
adapter to a root-owned, read-only JSON file whose digest is part of the
selected recipe.  This module is not a general package installer.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
import configparser
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path("/run/hermes-installer/build")
SOURCE = ROOT / "source"
TOOLCHAIN = ROOT / "toolchain"
WORK = ROOT / "work"
OUTPUT = ROOT / "output"
PACKAGES = ROOT / "packages"
BACKEND = ROOT / "backend"
PYTHON_RUNTIME = ROOT / "python-runtime"
UV = ROOT / "uv" / "uv"
CONFIG = ROOT / "recipe" / "application-build-input.json"
ARCHIVE_NAME = "runtime-environment.tar"
MANIFEST_NAME = "HERMES-RUNTIME-MANIFEST.json"
RUNTIME_ENTRYPOINT = "bin/python3.14"
MAX_ARCHIVE = 2 * 1024**3
MAX_EXPANDED = 2 * 1024**3
MAX_MEMBERS = 131_072
MAX_CAPTURE = 1024 * 1024
MAX_CONFIG = 16 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z", re.ASCII)
PYTHON_APPS = {
    "graphify": ("graphifyy", "setuptools.build_meta", ("setuptools>=83.0.0",),
                 {"graphify": "graphify.__main__:main", "graphify-mcp": "graphify.serve:_main"}),
    "browser-use": ("browser-use", "hatchling.build", ("hatchling==1.32.0",),
                    {"browser-use": "browser_use.cli:main", "browseruse": "browser_use.cli:main",
                     "bu": "browser_use.cli:main", "browser": "browser_use.cli:main",
                     "browser-use-tui": "browser_use.cli:browser_use_tui_main"}),
    # The pinned ScrapeGraphAI source has no [project.scripts] table. Sol must
    # choose a reviewed executable archive entrypoint before it can run.
    "scrapegraph-ai": ("scrapegraphai", "hatchling.build", ("hatchling==1.26.3",),
                       {}),
}
ALIASES = ("bin/python", "bin/python3")
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class BuildDenied(RuntimeError):
    """A selected build input or a real build step failed closed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path, limit: int) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BuildDenied("a fixed build input could not be opened without following links") from exc
    digest, size = hashlib.sha256(), 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BuildDenied("a fixed build input is not a single-link regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise BuildDenied("a fixed build input exceeds its enrolled size ceiling")
                digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def _read_regular(path: Path, limit: int, *, root_owned_readonly: bool = False) -> bytes:
    _digest, size = _sha_file(path, limit)
    if size > limit:
        raise BuildDenied("fixed build input exceeds its size ceiling")
    # Open a second time only after the no-follow check; use the descriptor for
    # bytes and verify its identity/digest again to close replacement races.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size
                or root_owned_readonly and (info.st_uid != 0 or info.st_mode & 0o022)):
            raise BuildDenied("fixed build input changed while being read")
        chunks, count = [], 0
        while True:
            part = os.read(fd, min(1024 * 1024, limit + 1 - count))
            if not part:
                break
            count += len(part)
            if count > limit:
                raise BuildDenied("fixed build input exceeds its size ceiling")
            chunks.append(part)
        result = b"".join(chunks)
    finally:
        os.close(fd)
    if len(result) != size or _sha_bytes(result) != _digest:
        raise BuildDenied("fixed build input changed while being read")
    return result


def _verify_selected_executable(path: Path, expected_sha256: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BuildDenied("a selected executable could not be opened without following links") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or not info.st_mode & 0o111
                or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)):
            raise BuildDenied("a selected executable lacks root-owned immutable executable custody")
        digest = hashlib.sha256()
        size = 0
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            size += len(part)
            if size > 128 * 1024**2:
                raise BuildDenied("selected executable exceeds its fixed size ceiling")
            digest.update(part)
        if digest.hexdigest() != expected_sha256:
            raise BuildDenied("selected executable bytes differ from the root-held receipt")
    finally:
        os.close(fd)


def _required_object(value: Any, keys: set[str], message: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise BuildDenied(message)
    return value


def _validate_pin(row: Any, *, backend: bool = False) -> dict[str, Any]:
    keys = {"name", "version", "filename", "sha256", "size_bytes"}
    if type(row) is not dict or set(row) != keys:
        raise BuildDenied("selected package pin fields are not exact")
    if (not all(isinstance(row[k], str) for k in ("name", "version", "filename", "sha256"))
            or not NAME.fullmatch(row["name"]) or not NAME.fullmatch(row["version"])
            or not SHA.fullmatch(row["sha256"])
            or type(row["size_bytes"]) is not int or not 1 <= row["size_bytes"] <= MAX_EXPANDED
            or PurePosixPath(row["filename"]).name != row["filename"]
            or not row["filename"].endswith(".whl")):
        raise BuildDenied("selected package pin is malformed")
    if backend and row["name"].casefold().replace("_", "-") == "pip":
        raise BuildDenied("ambient pip is not part of the fixed build backend")
    return row


def _load_input() -> dict[str, Any]:
    raw = _read_regular(CONFIG, MAX_CONFIG, root_owned_readonly=True)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BuildDenied("root-selected build input is malformed") from None
    top = _required_object(value, {
        "schema", "application_id", "source_manifest_sha256", "lock_sha256",
        "package_closure_sha256", "backend_closure_sha256", "packages",
        "backend_packages", "recipe_sha256", "uv_executable_sha256",
        "python_executable_sha256", "python_runtime_closure_sha256",
        "python_runtime_executable_relative_path",
    }, "root-selected build input fields are not exact")
    if (top["schema"] != 1 or type(top["schema"]) is not int
            or top["application_id"] not in PYTHON_APPS
            or any(not isinstance(top[k], str) or not SHA.fullmatch(top[k]) for k in (
                "source_manifest_sha256", "lock_sha256", "package_closure_sha256",
                "backend_closure_sha256", "recipe_sha256", "uv_executable_sha256",
                "python_executable_sha256", "python_runtime_closure_sha256"))):
        raise BuildDenied("root-selected build identity is malformed")
    if not _safe_relative(top["python_runtime_executable_relative_path"]):
        raise BuildDenied("selected PM executable member path is not canonical")
    for key, backend in (("packages", False), ("backend_packages", True)):
        rows = top[key]
        if type(rows) is not list or not rows or len(rows) > 8192:
            raise BuildDenied("selected wheel closure is empty or exceeds its fixed limit")
        normalized = [_validate_pin(item, backend=backend) for item in rows]
        names = [item["name"].casefold().replace("_", "-") for item in normalized]
        if len(set(names)) != len(names):
            raise BuildDenied("selected wheel closure contains duplicate package names")
        top[key] = normalized
    expected_dist, expected_backend, expected_requires, _expected_scripts = PYTHON_APPS[
        top["application_id"]]
    top["expected_distribution"] = expected_dist
    top["expected_backend"] = expected_backend
    top["expected_build_requirements"] = expected_requires
    return top


def _safe_relative(value: str) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and path.as_posix() == value
            and all(part not in {"", ".", ".."} for part in path.parts))


def _ensure_mount(path: Path, *, writable: bool = False, root_readonly: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BuildDenied("a fixed build mount is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BuildDenied("a fixed build mount is not a real directory")
    if writable and not (info.st_mode & 0o200):
        raise BuildDenied("a fixed build work mount is not writable by the selected service")
    if root_readonly:
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise BuildDenied("root-selected build mount is not root-owned and protected")
        readonly_flag = getattr(os, "ST_RDONLY", 1)
        if not os.statvfs(path).f_flag & readonly_flag:
            raise BuildDenied("root-selected build mount is not mounted read-only")


def _runtime_closure_sha256(root: Path, *, expected_uid: int = 0) -> str:
    """Rehash the held PM runtime tree using the PM receipt's tree algorithm."""
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise BuildDenied("held PM runtime root is unavailable") from exc
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != expected_uid or root_info.st_mode & 0o022):
        raise BuildDenied("held PM runtime root is not an immutable selected directory")
    digest = hashlib.sha256()
    paths: list[Path] = []
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(base)
        paths.extend(parent / name for name in dirs)
        paths.extend(parent / name for name in files)
        if len(paths) > MAX_MEMBERS:
            raise BuildDenied("held PM runtime exceeds its fixed member-count ceiling")
        dirs[:] = [name for name in dirs if not (parent / name).is_symlink()]
    if len(paths) > MAX_MEMBERS:
        raise BuildDenied("held PM runtime exceeds its fixed member-count ceiling")
    total_bytes = 0
    for item in sorted(paths, key=lambda path: path.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        if (info.st_uid != expected_uid or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID
                                                            | stat.S_ISVTX)):
            raise BuildDenied("held PM runtime member is not root-owned immutable input")
        digest.update(relative.encode("utf-8") + b"\0")
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(item)
            if not target or target.startswith("/") or "\\" in target or "\x00" in target:
                raise BuildDenied("held PM runtime contains an unsafe symbolic link")
            parts = list(PurePosixPath(relative).parent.parts)
            for part in PurePosixPath(target).parts:
                if part == "..":
                    if not parts:
                        raise BuildDenied("held PM runtime symbolic link escapes its tree")
                    parts.pop()
                elif part not in {"", "."}:
                    parts.append(part)
            digest.update(b"link\0" + target.encode("utf-8"))
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            file_sha, file_size = _sha_file(item, MAX_EXPANDED)
            if file_size != info.st_size:
                raise BuildDenied("held PM runtime file changed while being measured")
            total_bytes += file_size
            if total_bytes > MAX_EXPANDED:
                raise BuildDenied("held PM runtime exceeds its fixed expanded-size ceiling")
            digest.update(b"file\0" + bytes.fromhex(file_sha))
        elif stat.S_ISDIR(info.st_mode) and info.st_nlink >= 2:
            digest.update(b"dir\0")
        else:
            raise BuildDenied("held PM runtime contains a special or multiply-linked member")
    return digest.hexdigest()


def _check_source(config: dict[str, Any]) -> tuple[bytes, bytes, str, str]:
    # Only the exact source manifest roots from the root-selected receipt are
    # accepted; the immutable source mount is re-opened before and after work.
    pyproject = _read_regular(SOURCE / "pyproject.toml", 2 * 1024 * 1024,
                              root_owned_readonly=True)
    lock = _read_regular(SOURCE / "uv.lock", 16 * 1024 * 1024,
                         root_owned_readonly=True)
    lock_sha = _sha_bytes(lock)
    if lock_sha != config["lock_sha256"]:
        raise BuildDenied("selected application lock bytes changed")
    try:
        project = tomllib.loads(pyproject.decode("utf-8"))
        build = project["build-system"]
        dist = project["project"]["name"]
        version = project["project"]["version"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        raise BuildDenied("selected project metadata is malformed") from None
    if (not isinstance(dist, str) or dist.casefold().replace("_", "-")
            != config["expected_distribution"].casefold().replace("_", "-")
            or not isinstance(version, str)
            or build.get("build-backend") != config["expected_backend"]
            or tuple(build.get("requires", ())) != config["expected_build_requirements"]):
        raise BuildDenied("selected source project or build backend differs from its finite profile")
    return pyproject, lock, version, dist


def _verify_wheelhouse(root: Path, pins: list[dict[str, Any]], *, expected_uid: int = 0) -> None:
    _ensure_mount(root)
    entries = list(root.iterdir())
    if len(entries) != len(pins):
        raise BuildDenied("held wheelhouse membership differs from the selected package closure")
    expected = {row["filename"]: row for row in pins}
    if len(expected) != len(pins) or {item.name for item in entries} != set(expected):
        raise BuildDenied("held wheelhouse names differ from selected wheel pins")
    for item in entries:
        row = expected[item.name]
        info = item.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != expected_uid
                or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)):
            raise BuildDenied("a selected wheel is not a root-owned immutable regular file")
        digest, size = _sha_file(item, row["size_bytes"])
        if digest != row["sha256"] or size != row["size_bytes"]:
            raise BuildDenied("a held wheel differs from its selected digest or size")
        _verify_wheel_identity(item, row)


def _verify_wheel_identity(path: Path, row: dict[str, Any]) -> None:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 16_384:
                raise ValueError
            names: set[str] = set()
            total = 0
            metadata = None
            for info in infos:
                name = info.filename
                mode = (info.external_attr >> 16) & 0xFFFF
                kind = mode & 0o170000
                if (not _safe_relative(name.rstrip("/")) or name in names
                        or info.flag_bits & 1 or info.file_size < 0
                        or info.file_size > MAX_EXPANDED
                        or kind not in {0, 0o100000, 0o040000}
                        or info.is_dir() and kind not in {0, 0o040000}):
                    raise ValueError
                names.add(name)
                total += info.file_size
                if total > MAX_EXPANDED:
                    raise ValueError
                if name.endswith(".dist-info/METADATA"):
                    if metadata is not None or info.file_size > 2 * 1024 * 1024:
                        raise ValueError
                    metadata = archive.read(info)
            if metadata is None:
                raise ValueError
        from email.parser import BytesParser
        from email.policy import compat32
        parsed = BytesParser(policy=compat32).parsebytes(metadata)
        package_name = parsed.get("Name")
        package_version = parsed.get("Version")
        if (not isinstance(package_name, str) or not isinstance(package_version, str)
                or package_name.casefold().replace("_", "-")
                   != row["name"].casefold().replace("_", "-")
                or package_version != row["version"]):
            raise ValueError
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, RuntimeError):
        raise BuildDenied("a selected wheel has invalid ZIP structure or package metadata") from None


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 240) -> bytes:
    if (not argv or argv[0] != str(UV) or any(not isinstance(arg, str) for arg in argv)
            or timeout < 1 or timeout > 600):
        raise BuildDenied("fixed offline build command is malformed")
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   close_fds=True)
    except OSError:
        raise BuildDenied("fixed offline build step could not complete within its deadline") from None
    if process.stdout is None:
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise BuildDenied("fixed offline build output pipe was not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    captured = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BuildDenied("fixed offline build step exceeded its deadline")
            events = selector.select(min(remaining, 0.2))
            for key, _mask in events:
                chunk = os.read(key.fd, min(64 * 1024, MAX_CAPTURE + 1 - len(captured)))
                if chunk:
                    captured.extend(chunk)
                    if len(captured) > MAX_CAPTURE:
                        raise BuildDenied("fixed offline build step exceeded its bounded output")
                else:
                    selector.unregister(key.fileobj)
            if process.poll() is not None and not selector.get_map():
                break
        return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired, BuildDenied):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise
    finally:
        selector.close()
        process.stdout.close()
    if return_code != 0:
        raise BuildDenied("fixed offline build step failed")
    return bytes(captured)


def _base_env(env_home: Path, uv_cache: Path) -> dict[str, str]:
    return {
        "HOME": str(env_home), "TMPDIR": str(WORK / "tmp"),
        # Every child is launched by an enrolled absolute executable path.
        # Hooks get only their private environment's bin directory below.
        "PATH": str(WORK / "empty-path"),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1", "PIP_CONFIG_FILE": os.devnull,
        "UV_NO_CONFIG": "1", "UV_OFFLINE": "1", "UV_NO_PROGRESS": "1",
        "UV_PYTHON_DOWNLOADS": "never", "UV_CACHE_DIR": str(uv_cache),
        "UV_INDEX_URL": "https://invalid.invalid/disabled",
        "UV_DEFAULT_INDEX": "https://invalid.invalid/disabled",
        "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
        "http_proxy": "", "https_proxy": "", "all_proxy": "",
        "NO_PROXY": "*", "no_proxy": "*", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _parse_export(data: bytes) -> dict[str, tuple[str, frozenset[str]]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise BuildDenied("uv export output is not UTF-8") from None
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # uv export may include the selected project's ordinary registry
        # declaration. The builder never uses it: installs use --no-index and
        # resolve only to held, hash-verified local wheel files.
        if line in {"--index-url https://pypi.org/simple",
                    "--index-url https://pypi.org/simple/"}:
            continue
        if pending:
            line = pending + " " + line
            pending = ""
        if line.endswith("\\"):
            pending = line[:-1].strip()
            continue
        logical.append(line)
    if pending:
        raise BuildDenied("uv export contains a truncated continued row")
    rows: dict[str, tuple[str, frozenset[str]]] = {}
    req_re = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)(.*)$")
    hash_re = re.compile(r"--hash=sha256:([0-9a-f]{64})")
    for line in logical:
        match = req_re.match(line)
        if not match:
            # Editable/local/path/direct-URL and option rows are never accepted.
            raise BuildDenied("uv export contains a non-pinned or unsupported requirement row")
        name, version, tail = match.groups()
        normalized = name.casefold().replace("_", "-").replace(".", "-")
        hashes = frozenset(hash_re.findall(tail))
        if not hashes:
            raise BuildDenied("uv export requirement has no SHA-256 integrity hashes")
        if normalized in rows and rows[normalized][0] != version:
            raise BuildDenied("uv export contains conflicting versions for a package")
        if normalized in rows:
            old_version, old_hashes = rows[normalized]
            rows[normalized] = (old_version, old_hashes | hashes)
        else:
            rows[normalized] = (version, hashes)
    if not rows:
        raise BuildDenied("uv export has no hash-pinned package rows")
    return rows


def _requirements_bytes(pins: list[dict[str, Any]], export_rows: dict[str, tuple[str, frozenset[str]]]) -> bytes:
    expected_names: set[str] = set()
    lines: list[str] = []
    for row in sorted(pins, key=lambda item: item["name"].casefold()):
        name = row["name"].casefold().replace("_", "-").replace(".", "-")
        expected_names.add(name)
        exported = export_rows.get(name)
        if exported is None or exported[0] != row["version"] or row["sha256"] not in exported[1]:
            raise BuildDenied("selected root wheel is not in the active hash-pinned lock export")
        lines.append(f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}")
    if expected_names != set(export_rows):
        raise BuildDenied("selected root wheel set is not the complete active hash-pinned lock export")
    return ("\n".join(lines) + "\n").encode("ascii")


def _write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _copy_selected_python(source: Path, destination: Path, expected_sha256: str) -> tuple[str, int]:
    """Copy only the receipt-selected PM executable into the runtime tree."""
    _verify_selected_executable(source, expected_sha256)
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0))
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o755)
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or not before.st_mode & 0o111 or before.st_mode & 0o022):
            raise BuildDenied("selected PM executable changed before runtime copy")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > 128 * 1024**2:
                raise BuildDenied("selected PM executable exceeds its fixed size ceiling")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        after = os.fstat(source_fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or digest.hexdigest() != expected_sha256 or count != before.st_size):
            raise BuildDenied("selected PM executable changed while being copied")
        os.fchmod(destination_fd, 0o755)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    return digest.hexdigest(), count


def _runtime_members(root: Path, aliases: tuple[str, ...]) -> tuple[list[dict[str, Any]], int]:
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise BuildDenied("isolated runtime output is not a real directory")
    alias_set = set(aliases)
    members: list[dict[str, Any]] = []
    total = 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        kept: list[str] = []
        for name in sorted(dirs):
            item = base_path / name
            info = item.lstat()
            rel = item.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                if rel in alias_set:
                    continue
                raise BuildDenied("runtime environment contains an unselected directory symlink")
            if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 2 or info.st_uid != root_info.st_uid:
                raise BuildDenied("runtime environment contains an unsafe directory")
            members.append({"path": rel, "kind": "directory", "mode": 0o755,
                            "size_bytes": 0, "sha256": EMPTY_SHA})
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            item = base_path / name
            info = item.lstat()
            rel = item.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                if rel in alias_set:
                    continue
                raise BuildDenied("runtime environment contains an unselected symlink")
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != root_info.st_uid or info.st_mode & 0o022):
                raise BuildDenied("runtime environment contains an unsafe or writable file")
            digest, size = _sha_file(item, MAX_EXPANDED)
            total += size
            if total > MAX_EXPANDED:
                raise BuildDenied("runtime environment exceeds the expanded-size ceiling")
            mode = 0o755 if info.st_mode & 0o111 else 0o644
            members.append({"path": rel, "kind": "file", "mode": mode,
                            "size_bytes": size, "sha256": digest})
            if len(members) > MAX_MEMBERS:
                raise BuildDenied("runtime environment exceeds its member-count ceiling")
    members.sort(key=lambda item: item["path"].encode("utf-8"))
    if len({item["path"] for item in members}) != len(members):
        raise BuildDenied("runtime environment contains duplicate member paths")
    return members, total


def _write_archive(env_root: Path, destination: Path, app: str, entrypoint: str) -> tuple[str, int, str]:
    if not _safe_relative(entrypoint):
        raise BuildDenied("selected runtime entrypoint is not a canonical relative path")
    aliases = ALIASES
    members, expanded = _runtime_members(env_root, aliases)
    if not any(row["path"] == entrypoint and row["kind"] == "file" and row["mode"] & 0o111
               for row in members):
        raise BuildDenied("selected runtime entrypoint is not an observed executable file")
    manifest = _canonical({
        "schema": 1, "application_id": app, "runtime_kind": "python",
        "entrypoint": entrypoint, "interpreter_aliases": list(aliases), "members": members,
    })
    if len(manifest) > 16 * 1024 * 1024:
        raise BuildDenied("runtime manifest exceeds its fixed size ceiling")
    temp = destination.with_name(".runtime-environment.tmp")
    try:
        with temp.open("xb") as raw, tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            manifest_info = tarfile.TarInfo(MANIFEST_NAME)
            manifest_info.size, manifest_info.mode = len(manifest), 0o444
            manifest_info.uid = manifest_info.gid = manifest_info.mtime = 0
            manifest_info.uname = manifest_info.gname = ""
            archive.addfile(manifest_info, io.BytesIO(manifest))
            for row in members:
                info = tarfile.TarInfo(row["path"] + ("/" if row["kind"] == "directory" else ""))
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = row["mode"]
                if row["kind"] == "directory":
                    info.type, info.size = tarfile.DIRTYPE, 0
                    archive.addfile(info)
                else:
                    info.type, info.size = tarfile.REGTYPE, row["size_bytes"]
                    with (env_root / row["path"]).open("rb") as stream:
                        archive.addfile(info, stream)
        size = temp.stat().st_size
        if size > MAX_ARCHIVE:
            raise BuildDenied("runtime archive exceeds its fixed size ceiling")
        fd = os.open(temp, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temp, destination, follow_symlinks=False)
        temp.unlink()
        parent_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        digest, size = _sha_file(destination, MAX_ARCHIVE)
        return digest, size, _sha_bytes(manifest)
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _project_info(pyproject: bytes, app: str) -> tuple[str, str]:
    try:
        value = tomllib.loads(pyproject.decode("utf-8"))["project"]
        name, version = value["name"], value["version"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        raise BuildDenied("project wheel metadata is not statically declared") from None
    if not isinstance(name, str) or not isinstance(version, str):
        raise BuildDenied("project wheel name or version is malformed")
    if name.casefold().replace("_", "-") != PYTHON_APPS[app][0].casefold().replace("_", "-"):
        raise BuildDenied("project wheel distribution differs from the fixed profile")
    return name, version


def _inspect_project_wheel(path: Path, name: str, version: str,
                           expected_scripts: dict[str, str]) -> tuple[str, int]:
    digest, size = _sha_file(path, MAX_ARCHIVE)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if not 1 <= len(entries) <= 16_384:
                raise ValueError
            metadata: bytes | None = None
            entry_points: bytes | None = None
            seen: set[str] = set()
            expanded = 0
            for info in entries:
                if (not _safe_relative(info.filename) or info.filename in seen
                        or info.flag_bits & 1 or info.file_size < 0):
                    raise ValueError
                seen.add(info.filename)
                expanded += info.file_size
                if expanded > MAX_EXPANDED:
                    raise ValueError
                if info.filename.endswith(".dist-info/METADATA"):
                    if metadata is not None or info.file_size > 2 * 1024 * 1024:
                        raise ValueError
                    metadata = archive.read(info)
                elif info.filename.endswith(".dist-info/entry_points.txt"):
                    if entry_points is not None or info.file_size > 1024 * 1024:
                        raise ValueError
                    entry_points = archive.read(info)
            if metadata is None:
                raise ValueError
        from email.parser import BytesParser
        from email.policy import compat32
        parsed = BytesParser(policy=compat32).parsebytes(metadata)
        if (parsed.get("Name", "").casefold().replace("_", "-") != name.casefold().replace("_", "-")
                or parsed.get("Version") != version):
            raise ValueError
        if entry_points is not None:
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(entry_points.decode("utf-8"))
            if parser.defaults() or any(section != "console_scripts" for section in parser.sections()):
                raise ValueError
            actual_scripts = (dict(parser.items("console_scripts"))
                              if "console_scripts" in parser else {})
        else:
            actual_scripts = {}
        if actual_scripts != expected_scripts:
            raise ValueError
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError):
        raise BuildDenied("built project wheel has malformed archive or unexpected identity") from None
    return digest, size


def build() -> dict[str, Any]:
    for mount in (SOURCE, TOOLCHAIN, PACKAGES, BACKEND, PYTHON_RUNTIME, ROOT / "uv"):
        _ensure_mount(mount, root_readonly=True)
    _ensure_mount(CONFIG.parent, root_readonly=True)
    _ensure_mount(WORK, writable=True)
    _ensure_mount(OUTPUT, writable=True)
    config = _load_input()
    app = config["application_id"]
    if app == "hyperframes":
        raise BuildDenied("Hyperframes requires its separate reviewed Node/Bun build route")
    _verify_wheelhouse(PACKAGES, config["packages"])
    _verify_wheelhouse(BACKEND, config["backend_packages"])
    if _runtime_closure_sha256(PYTHON_RUNTIME) != config["python_runtime_closure_sha256"]:
        raise BuildDenied("held PM runtime closure differs from its current root receipt")
    selected_python = PYTHON_RUNTIME / config["python_runtime_executable_relative_path"]
    _verify_selected_executable(selected_python, config["python_executable_sha256"])
    pyproject, original_lock, project_version, _project_name = _check_source(config)
    initial_lock_sha = _sha_bytes(original_lock)
    _verify_selected_executable(UV, config["uv_executable_sha256"])
    builder_info = Path(ROOT / "builder").lstat()
    if (not stat.S_ISREG(builder_info.st_mode) or stat.S_ISLNK(builder_info.st_mode)
            or builder_info.st_uid != 0 or not builder_info.st_mode & 0o111
            or builder_info.st_mode & 0o022):
        raise BuildDenied("selected PM Python executable lacks root-held executable custody")
    work = WORK / "application"
    if work.exists():
        raise BuildDenied("selected application work root is not fresh")
    work.mkdir(mode=0o700)
    for name in ("tmp", "home", "cache", "empty-path", "backend-env", "runtime-env", "backend-wheelhouse",
                 "project-wheelhouse", "project-wheel-output"):
        (work / name).mkdir(mode=0o700)
    env = _base_env(work / "home", work / "cache")
    env["UV_PYTHON"] = str(selected_python)
    env["VIRTUAL_ENV"] = ""
    env["PATH"] = str(work / "empty-path")
    lock_before = _sha_file(SOURCE / "uv.lock", 16 * 1024 * 1024)[0]
    _run([str(UV), "lock", "--check", "--offline", "--no-progress"], cwd=SOURCE, env=env)
    export_path = work / "requirements-export.txt"
    _run([str(UV), "export", "--locked", "--offline", "--no-dev", "--no-default-groups",
          "--no-editable", "--no-emit-project", "--format", "requirements-txt",
          "--output-file", str(export_path)], cwd=SOURCE, env=env)
    exported = _read_regular(export_path, 16 * 1024 * 1024)
    export_sha = _sha_bytes(exported)
    package_projection = _requirements_bytes(config["packages"], _parse_export(exported))
    if _sha_file(SOURCE / "uv.lock", 16 * 1024 * 1024)[0] != lock_before or lock_before != initial_lock_sha:
        raise BuildDenied("fixed uv validation/export modified the selected lock")
    _write_exclusive(work / "runtime-requirements.txt", package_projection)
    backend_requirements = ("\n".join(
        f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}"
        for row in sorted(config["backend_packages"], key=lambda item: item["name"].casefold())
    ) + "\n").encode("ascii")
    _write_exclusive(work / "backend-requirements.txt", backend_requirements)
    for row in config["backend_packages"]:
        shutil.copyfile(BACKEND / row["filename"], work / "backend-wheelhouse" / row["filename"])
    for row in config["packages"]:
        shutil.copyfile(PACKAGES / row["filename"], work / "project-wheelhouse" / row["filename"])
    py = str(selected_python)
    backend_python = str(work / "backend-env" / "bin" / "python")
    runtime_python = str(work / "runtime-env" / "bin" / "python")
    common_uv = [str(UV)]
    _run(common_uv + ["venv", "--offline", "--no-project", "--no-seed", "--python", py,
                      str(work / "backend-env")], cwd=work, env=env)
    _run(common_uv + ["pip", "sync", "--require-hashes", "--offline", "--no-index",
                      "--find-links", str(work / "backend-wheelhouse"), "--python", backend_python,
                      str(work / "backend-requirements.txt")], cwd=work, env=env)
    backend_env = dict(env)
    backend_env["PATH"] = str(work / "backend-env" / "bin")
    backend_env["VIRTUAL_ENV"] = str(work / "backend-env")
    wheel_out = work / "project-wheel-output"
    _run(common_uv + ["build", "--wheel", "--offline", "--no-build-isolation", "--python",
                      backend_python, "--out-dir", str(wheel_out), str(SOURCE)],
         cwd=work, env=backend_env, timeout=600)
    wheel_files = list(wheel_out.iterdir())
    if len(wheel_files) != 1 or not wheel_files[0].name.endswith(".whl"):
        raise BuildDenied("fixed project build did not produce exactly one wheel")
    project_name, source_version = _project_info(pyproject, app)
    if source_version != project_version:
        raise BuildDenied("source project metadata changed during build")
    project_sha, project_size = _inspect_project_wheel(
        wheel_files[0], project_name, source_version, PYTHON_APPS[app][3])
    project_copy = work / "project-wheelhouse" / wheel_files[0].name
    shutil.copyfile(wheel_files[0], project_copy)
    _run(common_uv + ["venv", "--offline", "--no-project", "--no-seed", "--python", py,
                      str(work / "runtime-env")], cwd=work, env=env)
    _run(common_uv + ["pip", "sync", "--require-hashes", "--offline", "--no-index",
                      "--find-links", str(work / "project-wheelhouse"), "--python", runtime_python,
                      str(work / "runtime-requirements.txt")], cwd=work, env=env, timeout=600)
    project_req = work / "project-requirement.txt"
    _write_exclusive(project_req,
                     f"{project_name}=={source_version} --hash=sha256:{project_sha}\n".encode("ascii"))
    _run(common_uv + ["pip", "install", "--no-deps", "--require-hashes", "--offline", "--no-index",
                      "--find-links", str(work / "project-wheelhouse"), "--python", runtime_python,
                      "-r", str(project_req)], cwd=work, env=env, timeout=600)
    # The root-selected PM interpreter and its exact alias are materialized in
    # a clean output tree as a measured regular file. The root materializer
    # later binds this exact member to its separately held base-runtime receipt
    # and rewrites only source-verified console-script shebangs to that final
    # interpreter location, retaining both original and rewritten hashes.
    env_root = work / "runtime-env"
    runtime_bin = env_root / "bin"
    runtime_bin.mkdir(mode=0o755, parents=True, exist_ok=True)
    _copy_selected_python(ROOT / "builder", runtime_bin / "python3.14",
                          config["python_executable_sha256"])
    for alias in ALIASES:
        if alias == "bin/python3.14":
            continue
        link = env_root / alias
        link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if link.exists() or link.is_symlink():
            link.unlink()
        # The root archive extractor discards these fixed aliases and binds
        # them to the independently verified copied runtime executable.
        os.symlink("python3.14" if alias.startswith("bin/") else "bin/python3.14", link)
    archive_path = OUTPUT / ARCHIVE_NAME
    digest, size, manifest_sha = _write_archive(
        env_root, archive_path, app, RUNTIME_ENTRYPOINT)
    # Lock/source are revalidated after all hooks have executed.  A source
    # mutation inside the managed unit invalidates the whole result.
    if (_sha_file(SOURCE / "uv.lock", 16 * 1024 * 1024)[0] != initial_lock_sha
            or _sha_bytes(_read_regular(SOURCE / "pyproject.toml", 2 * 1024 * 1024,
                                        root_owned_readonly=True)) != _sha_bytes(pyproject)):
        try:
            archive_path.unlink()
        except OSError:
            pass
        raise BuildDenied("selected source or lock changed while the builder was running")
    return {
        "schema": 1, "application_id": app, "source_manifest_sha256": config["source_manifest_sha256"],
        "lock_sha256": initial_lock_sha, "export_sha256": export_sha,
        "package_closure_sha256": config["package_closure_sha256"],
        "backend_closure_sha256": config["backend_closure_sha256"],
        "python_executable_sha256": config["python_executable_sha256"],
        "python_runtime_closure_sha256": config["python_runtime_closure_sha256"],
        "python_runtime_executable_relative_path": config[
            "python_runtime_executable_relative_path"],
        "runtime_entrypoint": RUNTIME_ENTRYPOINT,
        "project_wheel_sha256": project_sha, "project_wheel_size_bytes": project_size,
        "runtime_archive_sha256": digest, "runtime_archive_size_bytes": size,
        "runtime_manifest_sha256": manifest_sha,
    }


def main() -> int:
    if len(sys.argv) != 1:
        raise BuildDenied("the fixed application builder accepts no arguments")
    result = build()
    # A single bounded, secret-free result line.  Root independently measures
    # the output and does not treat this line as a build attestation.
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildDenied as exc:
        message = str(exc).replace("\n", " ")[:240]
        sys.stderr.write("application environment build denied: " + message + "\n")
        raise SystemExit(2)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError):
        sys.stderr.write("application environment build denied: fixed input or output validation failed\n")
        raise SystemExit(2)
