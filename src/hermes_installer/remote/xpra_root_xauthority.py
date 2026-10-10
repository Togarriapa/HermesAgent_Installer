"""Source-pinned Xpra overlay for the root-owned Xauthority credential.

The overlay is intentionally tied to the exact Xpra tree reviewed in the
remote-desktop plan.  It does not claim to install or launch Xpra; it creates
an immutable patched source tree whose digest can be enrolled as an artifact.
The runtime must still verify the artifact receipt and Xauthority mount before
using this tree.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


XPRA_SOURCE_COMMIT = "521b0d2e762c770b2641d258b93d23575fa9cbea"
ROOT_XAUTHORITY = "/run/hermes-installer/display/Xauthority"
_PINNED_INPUTS = {
    "xpra/scripts/server.py": "40e9ced39617ce7ba26ce26a320e86d3c20944f3cf9ff9e47e459d3180372ead",
    "xpra/server/subsystem/xvfb.py": "fd1718ad7fb3b905547b86116df241694c9a6c59c4c40e954a38764689201de6",
    "xpra/x11/vfb_util.py": "9285e8a124384270c92df6338d8e2d0f30da20a47616a4f33f6b79bff6c185d6",
}
OVERLAY_ARTIFACT_ID = "installer-xpra-root-xauthority-overlay-v1"
OVERLAY_MANIFEST = "hermes-installer-xpra-root-xauthority-overlay-v1.json"
XPRA_SOURCE_ARTIFACT_ID = f"xpra-source-{XPRA_SOURCE_COMMIT}"
XPRA_SOURCE_ARCHIVE_SHA256 = "20b55586457df5aed8453b0d1b446e4dd954f2027d814f1eb7c0a96227ef1c80"
XPRA_SOURCE_REGULAR_TREE_SHA256 = "f52b4ce760b86c24a4d6d930f47e58357442a984d9ff2478d7abf338ff48e467"
XPRA_SOURCE_MANIFEST_SHA256 = "108ab4e20dc62160fa3617f1622054b8b1ff3784ec2916f4a0e051aa961cec63"
XPRA_BUILD_TARGET_ID = "xpra-root-xauthority-transform:start"
XPRA_BUILD_OUTPUT_PATH = "xpra-overlay.tar"
MAX_XPRA_OUTPUT_BYTES = 128 * 1024 * 1024
_SOURCE_LINKS = {
    "debian": ("packaging/debian/xpra", "a1aef4be57bc54eefaab320b3728f3c0e0f463bc3c7307b1ac4528e2b3f00d4b", 21),
    "fs/etc/default": ("sysconfig", "ed85312a196268e2240f401f7d8711c4edaad4d43bcfd76ec5f4e19ec8916ee0", 9),
    "fs/libexec/xpra/gnome-open": ("xdg-open", "cdb8bb17173e1db8bf5dad2247fbe8be8d8c82e076cb465a471482387f521a29", 8),
    "fs/libexec/xpra/gvfs-open": ("xdg-open", "cdb8bb17173e1db8bf5dad2247fbe8be8d8c82e076cb465a471482387f521a29", 8),
    "fs/share/doc/xpra": ("../../../docs", "bdc7f46fbdfe68781df25dec18962c3ac2aa93d35c3e04185ecc9ac201c73b35", 13),
}


class XpraOverlayDenied(PermissionError):
    """Pinned source or expected patch anchors differ."""


@dataclass(frozen=True, slots=True)
class XpraOverlayReceipt:
    schema: int
    source_commit: str
    source_tree_sha256: str
    source_sha256: Mapping[str, str]
    output_sha256: Mapping[str, str]
    transformed_tree_sha256: str
    overlay_sha256: str
    manifest_sha256: str
    output_artifact_sha256: str
    patched_root: Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_sha256(root: Path) -> str:
    root = root.resolve(strict=True)
    rows: list[dict[str, object]] = []
    entries: list[tuple[str, Path]] = []
    directories: set[str] = set()
    links: dict[str, str] = {}
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in names + files:
            path = base / name
            rel = path.relative_to(root).as_posix()
            if rel == OVERLAY_MANIFEST:
                continue
            if path.is_symlink():
                links[rel] = os.readlink(path)
            elif path.is_dir():
                directories.add(rel)
            entries.append((rel, path))
    for rel, path in sorted(entries):
        st = path.lstat()
        if stat.S_ISREG(st.st_mode):
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    raise XpraOverlayDenied("Xpra tree file changed during hashing")
                content = hashlib.sha256()
                while chunk := os.read(fd, 131072):
                    content.update(chunk)
            finally:
                os.close(fd)
            rows.append({"path": rel, "sha256": content.hexdigest(),
                         "size_bytes": st.st_size, "executable": bool(st.st_mode & 0o111)})
        elif stat.S_ISDIR(st.st_mode):
            continue
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            resolved = (path.parent / target).resolve(strict=False)
            if not resolved.is_relative_to(root):
                raise XpraOverlayDenied("Xpra tree contains an escaping symlink")
        else:
            raise XpraOverlayDenied("Xpra tree contains a special file")
    expected_directories = set()
    for rel, _path in entries:
        parts = rel.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    for rel in _SOURCE_LINKS:
        parts = rel.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    if directories != expected_directories:
        raise XpraOverlayDenied("Xpra tree contains an empty or unlisted directory")
    expected_links = {path: value[0] for path, value in _SOURCE_LINKS.items()}
    if links != expected_links:
        raise XpraOverlayDenied("Xpra tree symlinks differ from the five measured source links")
    for target, target_sha256, size_bytes in _SOURCE_LINKS.values():
        encoded = target.encode("utf-8")
        if len(encoded) != size_bytes or _sha256(encoded) != target_sha256:
            raise XpraOverlayDenied("Xpra link target bytes differ from the committed source manifest")
    body = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _sha256(body)


def _regular_tree_sha256(root: Path) -> str:
    """Hash the pinned regular-file source projection before link expansion."""
    root = root.resolve(strict=True)
    rows: list[dict[str, object]] = []
    directories: set[str] = set()
    entries: list[tuple[str, Path]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in names + files:
            path = base / name
            rel = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise XpraOverlayDenied("regular-only Xpra source contains an unapproved link")
            if stat.S_ISDIR(info.st_mode):
                directories.add(rel)
            elif stat.S_ISREG(info.st_mode):
                entries.append((rel, path))
            else:
                raise XpraOverlayDenied("regular-only Xpra source contains a special member")
    for rel, path in sorted(entries):
        st = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                raise XpraOverlayDenied("Xpra source changed while hashing")
            digest = hashlib.sha256()
            while block := os.read(fd, 131072):
                digest.update(block)
        finally:
            os.close(fd)
        rows.append({"path": rel, "sha256": digest.hexdigest(),
                     "size_bytes": st.st_size, "executable": bool(st.st_mode & 0o111)})
    expected_directories = set()
    for rel, _path in entries:
        parts = rel.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    for rel in _SOURCE_LINKS:
        parts = rel.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:index]))
    if directories != expected_directories:
        raise XpraOverlayDenied("regular-only Xpra source has an empty or unlisted directory")
    body = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _sha256(body)


def deterministic_xpra_overlay_archive(root: Path) -> bytes:
    """Return the exact bounded deterministic archive bytes for root CAS publication."""
    root = root.resolve(strict=True)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            base = Path(directory)
            names.sort()
            files.sort()
            for name in names + files:
                path = base / name
                rel = path.relative_to(root).as_posix()
                info = path.lstat()
                item = tarfile.TarInfo(rel + ("/" if stat.S_ISDIR(info.st_mode) else ""))
                item.uid = item.gid = 0
                item.uname = item.gname = ""
                item.mtime = 0
                item.mode = stat.S_IMODE(info.st_mode)
                item.size = info.st_size if stat.S_ISREG(info.st_mode) else 0
                if stat.S_ISDIR(info.st_mode):
                    item.type = tarfile.DIRTYPE
                elif stat.S_ISREG(info.st_mode):
                    item.type = tarfile.REGTYPE
                elif stat.S_ISLNK(info.st_mode):
                    item.type = tarfile.SYMTYPE
                    item.linkname = os.readlink(path)
                else:
                    raise XpraOverlayDenied("Xpra tree contains a special artifact member")
                with path.open("rb") if stat.S_ISREG(info.st_mode) else _null_context() as source:
                    archive.addfile(item, source if stat.S_ISREG(info.st_mode) else None)
                if stream.tell() > 128 * 1024 * 1024:
                    raise XpraOverlayDenied("transformed Xpra archive exceeds its bound")
    return stream.getvalue()


def _deterministic_archive_sha256(root: Path) -> str:
    return _sha256(deterministic_xpra_overlay_archive(root))


class _null_context:
    def __enter__(self):
        return None

    def __exit__(self, *_exc):
        return False


def _replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise XpraOverlayDenied(f"pinned Xpra patch anchor mismatch: {label}")
    return data.replace(old, new, 1)


def _replace_method_region(data: bytes, start: bytes, end: bytes,
                           replacement: bytes, label: str) -> bytes:
    if data.count(start) != 1 or data.count(end) != 1:
        raise XpraOverlayDenied(f"pinned Xpra method boundary mismatch: {label}")
    begin = data.index(start)
    finish = data.index(end)
    if finish <= begin:
        raise XpraOverlayDenied(f"pinned Xpra method order mismatch: {label}")
    return data[:begin] + replacement + data[finish:]


def _patch_sources(root: Path) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    for relative, expected in _PINNED_INPUTS.items():
        path = root / relative
        try:
            raw = path.read_bytes()
        except OSError:
            raise XpraOverlayDenied("pinned Xpra source file is unavailable") from None
        if _sha256(raw) != expected:
            raise XpraOverlayDenied("pinned Xpra source file digest differs")
        sources[relative] = raw

    server = sources["xpra/scripts/server.py"]
    server = _replace_once(
        server,
        b"    xauth_data: str = get_hex_uuid() if start_vfb else \"\"\n",
        b"    # Dedicated installer overlay: never mint a second display cookie.\n"
        b"    xauth_data: str = \"\"\n",
        "server-cookie-generation",
    )
    sources["xpra/scripts/server.py"] = server

    xvfb = sources["xpra/server/subsystem/xvfb.py"]
    xvfb = _replace_once(
        xvfb,
        b"import os\nimport sys\n",
        b"import os\nimport stat\nimport sys\n",
        "xvfb-stat-import",
    )
    xvfb = _replace_once(
        xvfb,
        b"        self.xvfb_cmd = xvfb_command(opts.xvfb, self.pixel_depth, opts.dpi)\n",
        b"        self.xvfb_cmd = xvfb_command(opts.xvfb, self.pixel_depth, opts.dpi)\n"
        b"        if os.environ.get(\"XAUTHORITY\") != \"/run/hermes-installer/display/Xauthority\":\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is required\")\n"
        b"        if self.displayfd:\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected Xvfb must use the enrolled fixed display name\")\n"
        b"        if \"-auth\" in self.xvfb_cmd:\n"
        b"            _hermes_auth_index = self.xvfb_cmd.index(\"-auth\")\n"
        b"            if (_hermes_auth_index + 1 >= len(self.xvfb_cmd)\n"
        b"                    or self.xvfb_cmd[_hermes_auth_index + 1] != \"/run/hermes-installer/display/Xauthority\"\n"
        b"                    or self.xvfb_cmd.count(\"-auth\") != 1):\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"selected Xvfb auth path differs\")\n"
        b"        else:\n"
        b"            self.xvfb_cmd.extend((\"-auth\", \"/run/hermes-installer/display/Xauthority\"))\n",
        "xvfb-fixed-auth-argument",
    )
    xvfb = _replace_once(
        xvfb,
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n"
        b"        from xpra.x11.vfb_util import get_xauthority_path, valid_xauth\n",
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n"
        b"        from xpra.x11.vfb_util import get_xauthority_path, valid_xauth\n"
        b"        if os.environ.get(\"XAUTHORITY\") != \"/run/hermes-installer/display/Xauthority\":\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is required\")\n"
        b"        _hermes_path = \"/run/hermes-installer/display/Xauthority\"\n"
        b"        _hermes_fd = os.open(_hermes_path, os.O_RDONLY | getattr(os, \"O_NOFOLLOW\", 0))\n"
        b"        try:\n"
        b"            _hermes_stat = os.fstat(_hermes_fd)\n"
        b"            if (not stat.S_ISREG(_hermes_stat.st_mode) or _hermes_stat.st_uid != 0\n"
        b"                    or stat.S_IMODE(_hermes_stat.st_mode) != 0o640):\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is not protected\")\n"
        b"        finally:\n"
        b"            os.close(_hermes_fd)\n"
        b"        session_files = self.get_subsystem(\"session-files\")\n"
        b"        assert session_files\n"
        b"        session_files.write_session_file(\"xauthority\", _hermes_path)\n"
        b"        return _hermes_path\n",
        "xvfb-root-xauthority-selection",
    )
    xvfb = _replace_once(
        xvfb,
        b"        if (use_display is not None and not upgrading) or proxying or encoder:\n"
        b"            return start_vfb, xauth_data, use_display\n",
        b"        if os.environ.get(\"XAUTHORITY\") != \"/run/hermes-installer/display/Xauthority\":\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is required\")\n"
        b"        if not display_name.startswith(\":\"):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root-selected display name is invalid\")\n"
        b"        if verify_display(None, display_name, log_errors=False, timeout=1):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected display is already active\")\n"
        b"        _hermes_socket = os.path.join(X11_SOCKET_DIR, \"X\" + display_name[1:])\n"
        b"        if stat_display_socket(_hermes_socket):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected display socket already exists\")\n"
        b"        # Never repair, replace, or add credentials to a selected readonly authority file.\n"
        b"        return start_vfb, \"\", use_display\n",
        "xvfb-no-cookie-repair",
    )
    xvfb = _replace_once(
        xvfb,
        b"            assert not proxying and self.xauth_data\n",
        b"            assert not proxying and not self.xauth_data and xauthority == \"/run/hermes-installer/display/Xauthority\"\n",
        "xvfb-root-cookie-validity",
    )
    xvfb = _replace_once(
        xvfb,
        b"            assert xauthority\n"
        b"            xauth_add(xauthority, display_name, self.xauth_data, self.uid, self.gid)\n",
        b"            assert xauthority == \"/run/hermes-installer/display/Xauthority\"\n",
        "xvfb-no-xauth-add",
    )
    xvfb = _replace_once(
        xvfb,
        b"            from xpra.x11.vfb_util import start_Xvfb, xauth_add\n",
        b"            from xpra.x11.vfb_util import start_Xvfb\n",
        "xvfb-no-xauth-writer-import",
    )
    sources["xpra/server/subsystem/xvfb.py"] = xvfb

    vfb = sources["xpra/x11/vfb_util.py"]
    vfb = _replace_once(
        vfb,
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n"
        b"    xauth_args = [\"-f\", filename, \"add\", display_name, \"MIT-MAGIC-COOKIE-1\", xauth_data]\n",
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n"
        b"    raise PermissionError(\"Xauthority writes are disabled in the installer selected-display overlay\")\n"
        b"    xauth_args = [\"-f\", filename, \"add\", display_name, \"MIT-MAGIC-COOKIE-1\", xauth_data]\n",
        "vfb-no-xauth-add-root-file",
    )
    sources["xpra/x11/vfb_util.py"] = vfb

    xvfb = _replace_method_region(
        xvfb,
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n",
        b"    def get_info(self, _proto) -> dict[str, Any]:\n",
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n"
        b"        if os.environ.get(\"XAUTHORITY\") != \"/run/hermes-installer/display/Xauthority\":\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is required\")\n"
        b"        path = \"/run/hermes-installer/display/Xauthority\"\n"
        b"        fd = os.open(path, os.O_RDONLY | getattr(os, \"O_NOFOLLOW\", 0))\n"
        b"        try:\n"
        b"            info = os.fstat(fd)\n"
        b"            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o640:\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is not protected\")\n"
        b"        finally:\n"
        b"            os.close(fd)\n"
        b"        session_files = self.get_subsystem(\"session-files\")\n"
        b"        assert session_files\n"
        b"        session_files.write_session_file(\"xauthority\", path)\n"
        b"        return path\n\n",
        "xvfb-root-xauthority-method",
    )
    xvfb = _replace_method_region(
        xvfb,
        b"    def resolve_x11_display(self, display_name: str, xauthority: str, xauth_data: str,\n",
        b"    def start_server_vfb(self, display_name: str, old_display_name: str, xauthority: str | None,\n",
        b"    def resolve_x11_display(self, display_name: str, xauthority: str, xauth_data: str,\n"
        b"                            start_vfb: bool, use_display: bool | None, upgrading: bool,\n"
        b"                            shadowing: bool, proxying: bool, encoder: bool, pam,\n"
        b"                            progress: Callable) -> tuple[bool, str, bool | None]:\n"
        b"        if os.environ.get(\"XAUTHORITY\") != \"/run/hermes-installer/display/Xauthority\":\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is required\")\n"
        b"        if (not display_name.startswith(\":\") or not start_vfb or use_display is not False\n"
        b"                or upgrading or shadowing or proxying or encoder):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected display startup mode is not permitted\")\n"
        b"        if verify_display(None, display_name, log_errors=False, timeout=1):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected display is already active\")\n"
        b"        socket_path = os.path.join(X11_SOCKET_DIR, \"X\" + display_name[1:])\n"
        b"        if stat_display_socket(socket_path):\n"
        b"            raise InitExit(ExitCode.NO_DISPLAY, \"selected display socket already exists\")\n"
        b"        return True, \"\", False\n\n",
        "xvfb-fixed-display-method",
    )
    sources["xpra/server/subsystem/xvfb.py"] = xvfb

    vfb = _replace_method_region(
        vfb,
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n",
        b"def check_xvfb_process(xvfb=None, cmd: str = \"Xvfb\", timeout: int = 0, command=()) -> bool:\n",
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n"
        b"    raise PermissionError(\"Xauthority writes are disabled in the installer selected-display overlay\")\n\n",
        "vfb-disabled-xauth-writer",
    )
    sources["xpra/x11/vfb_util.py"] = vfb
    return sources


def build_pinned_xpra_root_xauthority_overlay(source_root: Path,
                                               output_root: Path) -> XpraOverlayReceipt:
    """Build a private patched copy of exactly the reviewed Xpra source tree.

    The output must be separately pinned in the protected artifact catalog.
    This function refuses a pre-existing destination and never edits source.
    """
    source_root = Path(source_root).resolve(strict=True)
    output_root = Path(output_root)
    try:
        output_root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise XpraOverlayDenied("overlay destination already exists")
    try:
        commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5,
            env={"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"},
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise XpraOverlayDenied("cannot verify pinned Xpra source revision") from None
    if commit != XPRA_SOURCE_COMMIT:
        raise XpraOverlayDenied("Xpra source revision differs from reviewed pin")
    try:
        archive = subprocess.run(
            ["git", "-C", str(source_root), "archive", "--format=tar", commit],
            check=True, capture_output=True, timeout=20,
            env={"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"},
        ).stdout
        if len(archive) > 128 * 1024 * 1024:
            raise XpraOverlayDenied("pinned Xpra source archive exceeds its bound")
        output_root.mkdir(mode=0o700, parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_archive:
            source_archive.extractall(output_root, filter="data")
        source_tree_sha256 = _tree_sha256(output_root)
        return _finish_overlay(output_root, output_root, commit, source_tree_sha256)
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _finish_overlay(source_root: Path, output_root: Path, commit: str,
                    source_tree_sha256: str) -> XpraOverlayReceipt:
    """Patch an already materialized, verified source tree in a fresh output."""
    if source_root != output_root:
        shutil.copytree(source_root, output_root, symlinks=True, copy_function=shutil.copy2)
    try:
        patched = _patch_sources(output_root)
        output_hashes: dict[str, str] = {}
        for relative, data in patched.items():
            target = output_root / relative
            st = target.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise XpraOverlayDenied("Xpra patch target is not a regular file")
            fd = os.open(target, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            output_hashes[relative] = _sha256(data)
        transformed_tree_sha256 = _tree_sha256(output_root)
        overlay_sha256 = _sha256(Path(__file__).read_bytes())
        manifest = {
            "schema": 1, "overlay": OVERLAY_ARTIFACT_ID,
            "source_commit": commit, "source_tree_sha256": source_tree_sha256,
            "source_sha256": _PINNED_INPUTS,
            "output_sha256": output_hashes,
            "transformed_tree_sha256": transformed_tree_sha256,
            "overlay_sha256": overlay_sha256,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")).encode()
        manifest_sha256 = _sha256(manifest_bytes)
        manifest_path = output_root / OVERLAY_MANIFEST
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            view = memoryview(manifest_bytes)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        output_artifact_sha256 = _deterministic_archive_sha256(output_root)
        return XpraOverlayReceipt(1, commit, source_tree_sha256,
                                  dict(_PINNED_INPUTS), output_hashes,
                                  transformed_tree_sha256, overlay_sha256,
                                  manifest_sha256, output_artifact_sha256, output_root)
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def materialize_observed_xpra_source(observation, observer, destination: Path) -> str:
    """Materialize only the exact sealed source-tree observation, no archive paths.

    Every regular file is reopened through the root catalog observer and copied
    from its held no-follow descriptor. Symlinks are recreated only from the
    catalog's exact finite link rows after the observer has revalidated them.
    """
    from hermes_installer.authority.source_artifact_receipts import (
        RootCatalogArtifactObserver, VerifiedCatalogArtifactObservation,
    )
    if (type(observation) is not VerifiedCatalogArtifactObservation
            or type(observer) is not RootCatalogArtifactObserver
            or observation.artifact_id != f"xpra-source-{XPRA_SOURCE_COMMIT}"
            or not observation.is_tree or not observer.verify_current(observation)):
        raise XpraOverlayDenied("Xpra source is not the current pinned root catalog observation")
    spec = observer.runtime_bindings.artifact_catalog._artifact(
        observation.artifact_id, observation.sha256,
    )
    if (spec.version != XPRA_SOURCE_COMMIT or observation.tree_manifest_sha256 is None
            or observation.tree_manifest_sha256 != spec.tree_manifest_sha256
            or spec.sha256 != XPRA_SOURCE_ARCHIVE_SHA256 or spec.size_bytes != 13_962_693
            or len(spec.tree_files) != 2_474
            or sum(row.size_bytes for row in spec.tree_files) != 28_215_129):
        raise XpraOverlayDenied("Xpra source catalog manifest does not match the reviewed commit")
    measured_rows = []
    for row in sorted(spec.tree_files, key=lambda item: item.path):
        entry = {"path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes,
                 "executable": row.executable, "kind": row.kind}
        if row.kind == "symlink":
            entry["link_target"] = row.link_target
        measured_rows.append(entry)
    if _sha256(json.dumps(measured_rows, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii")) != XPRA_SOURCE_MANIFEST_SHA256:
        raise XpraOverlayDenied("Xpra catalog rows differ from the committed full source manifest")
    destination = Path(destination)
    try:
        destination.mkdir(mode=0o755, parents=False, exist_ok=False)
        for row in sorted(spec.tree_files, key=lambda item: item.path):
            parts = row.path.split("/")
            if any(part in {"", ".", ".."} for part in parts):
                raise XpraOverlayDenied("Xpra source manifest contains an unsafe member")
            parent = destination
            for component in parts[:-1]:
                parent = parent / component
                try:
                    parent.mkdir(mode=0o755)
                except FileExistsError:
                    if not stat.S_ISDIR(parent.lstat().st_mode):
                        raise XpraOverlayDenied("Xpra source parent is not a directory")
            target = parent / parts[-1]
            if row.kind == "symlink":
                link = row.link_target
                if not isinstance(link, str) or Path(link).is_absolute():
                    raise XpraOverlayDenied("Xpra source link is not a finite relative target")
                resolved = (target.parent / link).resolve(strict=False)
                if not resolved.is_relative_to(destination.resolve(strict=True)):
                    raise XpraOverlayDenied("Xpra source link escapes its pinned tree")
                os.symlink(link, target)
                continue
            if row.kind != "file":
                raise XpraOverlayDenied("Xpra source contains an unsupported member kind")
            source_fd = observation.open_member(row.path, observer=observer)
            output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0),
                                0o700 if row.executable else 0o600)
            try:
                digest = hashlib.sha256()
                total = 0
                while True:
                    block = os.pread(source_fd, 131072, total)
                    if not block:
                        break
                    total += len(block)
                    if total > row.size_bytes:
                        raise XpraOverlayDenied("Xpra source member exceeded its pinned size")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        view = view[os.write(output_fd, view):]
                if total != row.size_bytes or digest.hexdigest() != row.sha256:
                    raise XpraOverlayDenied("Xpra source member changed while materializing")
                os.fchmod(output_fd, 0o755 if row.executable else 0o644)
                os.fsync(output_fd)
            finally:
                os.close(source_fd)
                os.close(output_fd)
        tree_digest = _tree_sha256(destination)
        expected = "f52b4ce760b86c24a4d6d930f47e58357442a984d9ff2478d7abf338ff48e467"
        if tree_digest != expected:
            raise XpraOverlayDenied("materialized Xpra regular tree differs from its measured source pin")
        return tree_digest
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def build_observed_pinned_xpra_overlay(source_observation, overlay_observation,
                                       observer, output_root: Path) -> XpraOverlayReceipt:
    """Build the reviewed overlay only from held root-catalog observations."""
    from hermes_installer.authority.source_artifact_receipts import VerifiedCatalogArtifactObservation
    if (type(source_observation) is not VerifiedCatalogArtifactObservation
            or type(overlay_observation) is not VerifiedCatalogArtifactObservation
            or not observer.verify_current(source_observation)
            or not observer.verify_current(overlay_observation)
            or overlay_observation.artifact_id != OVERLAY_ARTIFACT_ID):
        raise XpraOverlayDenied("Xpra source or selected overlay code observation is stale")
    overlay_fd = overlay_observation.open_blob()
    try:
        overlay_hash = hashlib.sha256()
        offset = 0
        while block := os.pread(overlay_fd, 65536, offset):
            overlay_hash.update(block)
            offset += len(block)
        if overlay_hash.hexdigest() != _sha256(Path(__file__).read_bytes()):
            raise XpraOverlayDenied("selected overlay code differs from the running reviewed module")
    finally:
        os.close(overlay_fd)
    parent = Path(output_root).parent
    if not parent.is_absolute() or parent.is_symlink():
        raise XpraOverlayDenied("Xpra overlay workspace root is unsafe")
    source_tree = parent / (".xpra-source-" + os.urandom(8).hex())
    try:
        source_digest = materialize_observed_xpra_source(source_observation, observer, source_tree)
        output_root = Path(output_root)
        try:
            output_root.lstat()
        except FileNotFoundError:
            pass
        else:
            raise XpraOverlayDenied("Xpra overlay destination already exists")
        return _finish_overlay(source_tree, output_root, XPRA_SOURCE_COMMIT, source_digest)
    finally:
        shutil.rmtree(source_tree, ignore_errors=True)


def build_materialized_xpra_overlay() -> str:
    """Fixed child entrypoint for the enrolled isolated transform profile.

    It accepts no argv paths or options. Root custody mounts the verified
    source at ``/run/hermes-installer/build/source`` and a fresh empty work and
    output directory at the corresponding fixed mount IDs. The actual output
    is one bounded non-executable tar file for ContentAddressedBuildStore.
    """
    source_root = Path("/run/hermes-installer/build/source")
    work_root = Path("/run/hermes-installer/build/work")
    output_root = Path("/run/hermes-installer/build/output")
    for directory in (source_root, work_root, output_root):
        info = directory.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()):
            raise XpraOverlayDenied("fixed Xpra build mount identity is invalid")
    try:
        source_digest = _tree_sha256(source_root)
        has_links = True
    except XpraOverlayDenied:
        source_digest = _regular_tree_sha256(source_root)
        has_links = False
    if source_digest != XPRA_SOURCE_REGULAR_TREE_SHA256:
        raise XpraOverlayDenied("fixed Xpra source mount differs from its complete measured tree")
    if (source_root / OVERLAY_MANIFEST).exists():
        raise XpraOverlayDenied("Xpra source mount contains an unreviewed overlay receipt")
    output_path = output_root / XPRA_BUILD_OUTPUT_PATH
    try:
        output_path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise XpraOverlayDenied("fixed Xpra output already exists")
    scratch = Path(tempfile.mkdtemp(prefix="xpra-overlay-", dir=work_root))
    transformed = scratch / "tree"
    try:
        selected_source = source_root
        if not has_links:
            selected_source = scratch / "source"
            _copy_and_expand_source_links(source_root, selected_source)
        receipt = _finish_overlay(selected_source, transformed, XPRA_SOURCE_COMMIT,
                                  XPRA_SOURCE_REGULAR_TREE_SHA256)
        archive = deterministic_xpra_overlay_archive(transformed)
        if (len(archive) > MAX_XPRA_OUTPUT_BYTES
                or _sha256(archive) != receipt.output_artifact_sha256):
            raise XpraOverlayDenied("deterministic Xpra output archive failed its bound or digest")
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            view = memoryview(archive)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        except Exception:
            os.close(fd)
            output_path.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)
        return receipt.output_artifact_sha256
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _copy_and_expand_source_links(source_root: Path, destination: Path) -> str:
    """Expand only the five reviewed aliases from a regular-only staged tree."""
    source_root = Path(source_root).resolve(strict=True)
    destination = Path(destination)
    if _regular_tree_sha256(source_root) != XPRA_SOURCE_REGULAR_TREE_SHA256:
        raise XpraOverlayDenied("regular-only Xpra source projection differs from the pin")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        raise XpraOverlayDenied("Xpra private work destination already exists")
    try:
        shutil.copytree(source_root, destination, symlinks=True,
                        copy_function=shutil.copy2)
        for relative, (target, target_sha256, size_bytes) in _SOURCE_LINKS.items():
            encoded = target.encode("utf-8")
            if len(encoded) != size_bytes or _sha256(encoded) != target_sha256:
                raise XpraOverlayDenied("Xpra link target bytes differ from the committed source manifest")
            link_path = destination / relative
            if link_path.exists() or link_path.is_symlink():
                raise XpraOverlayDenied("Xpra link destination already exists")
            link_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if not (link_path.parent / target).resolve(strict=True).is_relative_to(
                    destination.resolve(strict=True)):
                raise XpraOverlayDenied("Xpra source link target escapes the reviewed tree")
            os.symlink(target, link_path)
        if _tree_sha256(destination) != XPRA_SOURCE_REGULAR_TREE_SHA256:
            raise XpraOverlayDenied("expanded Xpra source aliases differ from the full manifest")
        return XPRA_SOURCE_REGULAR_TREE_SHA256
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


if __name__ == "__main__":
    build_materialized_xpra_overlay()


def verify_pinned_xpra_overlay(receipt: XpraOverlayReceipt, *, artifact_id: str,
                               expected_overlay_sha256: str) -> bool:
    """Revalidate the enrolled patch manifest and all patched source bytes.

    The enclosing root artifact catalog remains responsible for the complete
    Xpra artifact tree and executable pins. This function validates only the
    source-overlay receipt joined by its protected artifact ID and digest.
    """
    if (not isinstance(receipt, XpraOverlayReceipt) or receipt.schema != 1
            or artifact_id != OVERLAY_ARTIFACT_ID
            or receipt.source_commit != XPRA_SOURCE_COMMIT
            or receipt.overlay_sha256 != expected_overlay_sha256
            or not isinstance(expected_overlay_sha256, str)
            or len(expected_overlay_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_overlay_sha256)):
        raise XpraOverlayDenied("selected Xpra source overlay is not enrolled")
    root = Path(receipt.patched_root)
    if not root.is_absolute() or root.is_symlink():
        raise XpraOverlayDenied("selected Xpra source overlay root is unsafe")
    manifest_path = root / OVERLAY_MANIFEST
    try:
        manifest_st = manifest_path.lstat()
        if not stat.S_ISREG(manifest_st.st_mode) or stat.S_IMODE(manifest_st.st_mode) & 0o222:
            raise XpraOverlayDenied("Xpra patch receipt is not immutable")
        manifest_fd = os.open(manifest_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            manifest_opened = os.fstat(manifest_fd)
            if (manifest_opened.st_dev, manifest_opened.st_ino) != (manifest_st.st_dev, manifest_st.st_ino):
                raise XpraOverlayDenied("Xpra patch receipt changed during verification")
            manifest_chunks = []
            while chunk := os.read(manifest_fd, 65536):
                manifest_chunks.append(chunk)
                if sum(map(len, manifest_chunks)) > 65536:
                    raise XpraOverlayDenied("Xpra patch receipt exceeds its bound")
            manifest_bytes = b"".join(manifest_chunks)
        finally:
            os.close(manifest_fd)
        if (_sha256(manifest_bytes) != receipt.manifest_sha256
                or _sha256(Path(__file__).read_bytes()) != receipt.overlay_sha256):
            raise XpraOverlayDenied("Xpra patch receipt digest changed")
        manifest = json.loads(manifest_bytes)
    except (OSError, ValueError, json.JSONDecodeError):
        raise XpraOverlayDenied("Xpra patch receipt is unavailable") from None
    if (manifest != {
            "schema": 1, "overlay": OVERLAY_ARTIFACT_ID,
            "source_commit": XPRA_SOURCE_COMMIT,
            "source_tree_sha256": receipt.source_tree_sha256,
            "source_sha256": dict(_PINNED_INPUTS),
            "output_sha256": dict(receipt.output_sha256),
            "transformed_tree_sha256": receipt.transformed_tree_sha256,
            "overlay_sha256": receipt.overlay_sha256,
    }):
        raise XpraOverlayDenied("Xpra patch receipt fields differ")
    for relative, expected in receipt.output_sha256.items():
        if relative not in _PINNED_INPUTS or len(expected) != 64:
            raise XpraOverlayDenied("Xpra patch receipt contains an unknown source")
        path = root / relative
        try:
            parent = root
            for component in Path(relative).parts[:-1]:
                parent = parent / component
                if stat.S_ISLNK(parent.lstat().st_mode) or not stat.S_ISDIR(parent.lstat().st_mode):
                    raise XpraOverlayDenied("patched Xpra source path is unsafe")
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise XpraOverlayDenied("patched Xpra source is not a regular file")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    raise XpraOverlayDenied("patched Xpra source changed during verification")
                digest = hashlib.sha256()
                while chunk := os.read(fd, 65536):
                    digest.update(chunk)
            finally:
                os.close(fd)
        except OSError:
            raise XpraOverlayDenied("patched Xpra source is unavailable") from None
        if digest.hexdigest() != expected:
            raise XpraOverlayDenied("patched Xpra source digest changed")
    if set(receipt.output_sha256) != set(_PINNED_INPUTS):
        raise XpraOverlayDenied("Xpra patch receipt is incomplete")
    if _tree_sha256(root) != receipt.transformed_tree_sha256:
        raise XpraOverlayDenied("transformed Xpra source tree digest changed")
    if _deterministic_archive_sha256(root) != receipt.output_artifact_sha256:
        raise XpraOverlayDenied("transformed Xpra output artifact digest changed")
    return True


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


@dataclass(frozen=True, slots=True, repr=False)
class RootXpraOverlayPatchReceipt:
    schema: int
    receipt_handle: str
    source_commit: str
    source_tree_digest: str
    overlay_artifact_id: str
    overlay_sha256: str
    transformed_tree_sha256: str
    output_artifact_id: str
    output_artifact_sha256: str
    selected_enrollment_id: str
    process_generation: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes

    def payload(self) -> bytes:
        return _canonical({
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "source_commit": self.source_commit,
            "source_tree_digest": self.source_tree_digest,
            "overlay_artifact_id": self.overlay_artifact_id,
            "overlay_sha256": self.overlay_sha256,
            "transformed_tree_sha256": self.transformed_tree_sha256,
            "output_artifact_id": self.output_artifact_id,
            "output_artifact_sha256": self.output_artifact_sha256,
            "selected_enrollment_id": self.selected_enrollment_id,
            "process_generation": self.process_generation,
            "service_generation_digest": self.service_generation_digest,
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        })

    def __repr__(self) -> str:
        return "RootXpraOverlayPatchReceipt(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class _OverlayEntry:
    receipt: RootXpraOverlayPatchReceipt
    selection: Any
    build_profile: Any
    output: Any


class RootXpraOverlayReceiptRegistry:
    """Root registry joining the selected source transform to a real CAS output.

    The producer accepts only broker-held source/code observations and an
    attestation which is reloaded from the currently enrolled managed build
    profile. Output identity is always taken from the verified BuildOutput in
    that attestation; callers cannot supply an output ID, path, or digest.
    """

    def __init__(self, active_bindings, artifact_catalog, owned_store, journal,
                 signer, *, monotonic=time.monotonic):
        from hermes_installer.authority.source_artifact_receipts import RootCatalogArtifactObserver
        if (type(artifact_catalog) is not RootCatalogArtifactObserver
                or artifact_catalog.runtime_bindings is not active_bindings
                or getattr(active_bindings, "artifact_catalog", None)
                    is not artifact_catalog.runtime_bindings.artifact_catalog
                or not callable(getattr(owned_store, "resolve", None))
                or not callable(getattr(owned_store, "resolve_output_object", None))
                or not all(callable(getattr(journal, name, None))
                           for name in ("lookup", "prepare", "record"))
                or not callable(getattr(signer, "sign", None))
                or not callable(getattr(signer, "verify", None))
                or not callable(monotonic)):
            raise XpraOverlayDenied("root Xpra overlay registry dependencies are unavailable")
        self.active_bindings = active_bindings
        self.artifact_catalog = artifact_catalog
        self.owned_store = owned_store
        self.journal = journal
        self.signer = signer
        self.monotonic = monotonic
        self._entries: dict[str, _OverlayEntry] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, active_bindings, artifact_catalog, owned_store,
                          journal, signer, *, monotonic=time.monotonic):
        if os.name != "posix" or not sys.platform.startswith("linux") or os.geteuid() != 0:
            raise XpraOverlayDenied("selected Xpra overlay registry requires the Linux root authority")
        return cls(active_bindings, artifact_catalog, owned_store, journal,
                   signer, monotonic=monotonic)

    def record_selected_transformation(self, selected_startup, input_tree_observation,
                                       overlay_artifact_observation,
                                       actual_output_observation) -> str:
        from hermes_installer.authority.build_execution import BuildAttestation
        from hermes_installer.authority.selected_startup_authority import SelectedStartupSelection
        from hermes_installer.authority.source_artifact_receipts import VerifiedCatalogArtifactObservation

        if (type(selected_startup) is not SelectedStartupSelection
                or type(input_tree_observation) is not VerifiedCatalogArtifactObservation
                or type(overlay_artifact_observation) is not VerifiedCatalogArtifactObservation
                or type(actual_output_observation) is not BuildAttestation):
            raise XpraOverlayDenied("Xpra patch producer requires sealed root selections and observations")
        if not self._selection_current(selected_startup):
            raise XpraOverlayDenied("Xpra patch selection is stale or no longer active")
        observer = self.artifact_catalog
        if (not observer.verify_current(input_tree_observation)
                or input_tree_observation.artifact_id != XPRA_SOURCE_ARTIFACT_ID
                or input_tree_observation.sha256 != XPRA_SOURCE_ARCHIVE_SHA256
                or input_tree_observation.version != XPRA_SOURCE_COMMIT
                or not input_tree_observation.is_tree
                or input_tree_observation.size_bytes != 28_215_129
                or not observer.verify_current(overlay_artifact_observation)
                or overlay_artifact_observation.artifact_id != OVERLAY_ARTIFACT_ID
                or overlay_artifact_observation.sha256 != selected_startup.overlay_sha256
                or selected_startup.overlay_artifact_id != OVERLAY_ARTIFACT_ID):
            raise XpraOverlayDenied("Xpra source or selected overlay bytes do not match the active pin")
        profile = self._resolve_build_profile(actual_output_observation)
        current = self.owned_store.resolve(profile)
        if (current.attestation_id != actual_output_observation.attestation_id
                or current.attestation_sha256 != actual_output_observation.attestation_sha256
                or current.signature != actual_output_observation.signature
                or current != actual_output_observation):
            raise XpraOverlayDenied("Xpra transform output attestation is stale or not current")
        output = next((item for item in current.outputs
                       if item.relative_path == XPRA_BUILD_OUTPUT_PATH), None)
        if (output is None or output.kind != "file" or output.executable_role != "data"
                or output.size_bytes <= 0 or output.size_bytes > MAX_XPRA_OUTPUT_BYTES):
            raise XpraOverlayDenied("current Xpra transform receipt has no finite data archive")
        output_path = self.owned_store.resolve_output_object(output)
        output_stat = output_path.lstat()
        if (not stat.S_ISREG(output_stat.st_mode) or stat.S_ISLNK(output_stat.st_mode)
                or output_stat.st_uid != self.owned_store.owner_uid
                or output_stat.st_size != output.size_bytes):
            raise XpraOverlayDenied("Xpra build output is not held in the selected CAS")
        handle = selected_startup.patch_receipt_handle
        now = self.monotonic()
        expiry = min(now + 600.0, selected_startup.expires_monotonic,
                     current.expires_monotonic)
        if expiry <= now:
            raise XpraOverlayDenied("Xpra startup or build receipt lease is expired")

        with tempfile.TemporaryDirectory(
                prefix="hermes-xpra-verify-",
                dir=self.artifact_catalog.protected_enrollment.artifact_staging_directory) as temp:
            transformed_root = Path(temp) / "transformed"
            result = build_observed_pinned_xpra_overlay(
                input_tree_observation, overlay_artifact_observation,
                observer, transformed_root,
            )
            if (result.source_tree_sha256 != XPRA_SOURCE_REGULAR_TREE_SHA256
                    or result.overlay_sha256 != selected_startup.overlay_sha256
                    or result.output_artifact_sha256 != output.sha256
                    or result.transformed_tree_sha256 == result.output_artifact_sha256):
                raise XpraOverlayDenied("held Xpra output bytes do not equal the selected reviewed transform")

        provisional = RootXpraOverlayPatchReceipt(
            schema=1, receipt_handle=handle,
            source_commit=XPRA_SOURCE_COMMIT,
            source_tree_digest=XPRA_SOURCE_REGULAR_TREE_SHA256,
            overlay_artifact_id=OVERLAY_ARTIFACT_ID,
            overlay_sha256=selected_startup.overlay_sha256,
            transformed_tree_sha256=result.transformed_tree_sha256,
            output_artifact_id=output.artifact_id,
            output_artifact_sha256=output.sha256,
            selected_enrollment_id=selected_startup.selected_startup_enrollment_id,
            process_generation=selected_startup.process_generation,
            service_generation_digest=selected_startup.service_generation_digest,
            issued_monotonic=now, expires_monotonic=expiry, signature=b"",
        )
        receipt = RootXpraOverlayPatchReceipt(
            schema=provisional.schema, receipt_handle=provisional.receipt_handle,
            source_commit=provisional.source_commit,
            source_tree_digest=provisional.source_tree_digest,
            overlay_artifact_id=provisional.overlay_artifact_id,
            overlay_sha256=provisional.overlay_sha256,
            transformed_tree_sha256=provisional.transformed_tree_sha256,
            output_artifact_id=provisional.output_artifact_id,
            output_artifact_sha256=provisional.output_artifact_sha256,
            selected_enrollment_id=provisional.selected_enrollment_id,
            process_generation=provisional.process_generation,
            service_generation_digest=provisional.service_generation_digest,
            issued_monotonic=provisional.issued_monotonic,
            expires_monotonic=provisional.expires_monotonic,
            signature=self.signer.sign(provisional.payload()),
        )
        journal_key = "xpra-overlay:" + selected_startup.selected_startup_enrollment_id
        journal_entry = self._receipt_wire(receipt)
        self.journal.prepare(journal_key, {"state": "prepared", **journal_entry})
        with self._lock:
            if handle in self._entries:
                raise XpraOverlayDenied("Xpra overlay receipt handle collision")
            self._entries[handle] = _OverlayEntry(receipt, selected_startup, profile, output)
        self.journal.record(journal_key, {"state": "committed", **journal_entry})
        return handle

    def resolve_selected_patch(self, patch_receipt_handle: str, selected_startup
                               ) -> RootXpraOverlayPatchReceipt:
        from hermes_installer.authority.selected_startup_authority import SelectedStartupSelection
        if (not isinstance(patch_receipt_handle, str)
                or type(selected_startup) is not SelectedStartupSelection
                or patch_receipt_handle != selected_startup.patch_receipt_handle
                or not self._selection_current(selected_startup)):
            raise XpraOverlayDenied("selected Xpra patch handle or active startup row differs")
        with self._lock:
            entry = self._entries.get(patch_receipt_handle)
        if entry is None or entry.selection != selected_startup:
            raise XpraOverlayDenied("selected Xpra patch receipt is absent from the root registry")
        receipt = entry.receipt
        journal = self.journal.lookup("xpra-overlay:" + selected_startup.selected_startup_enrollment_id)
        if (not isinstance(journal, Mapping) or journal.get("state") != "committed"
                or journal.get("receipt_handle") != receipt.receipt_handle
                or not self.signer.verify(receipt.payload(), receipt.signature)
                or receipt.expires_monotonic <= self.monotonic()
                or receipt.overlay_sha256 != selected_startup.overlay_sha256
                or receipt.overlay_artifact_id != selected_startup.overlay_artifact_id
                or receipt.selected_enrollment_id != selected_startup.selected_startup_enrollment_id
                or receipt.process_generation != selected_startup.process_generation
                or receipt.service_generation_digest != selected_startup.service_generation_digest):
            raise XpraOverlayDenied("Xpra patch receipt is invalid, expired or no longer selected")
        if not self.artifact_catalog.verify_current(
                self.artifact_catalog.observe(receipt.overlay_artifact_id,
                                              receipt.overlay_sha256)):
            raise XpraOverlayDenied("selected Xpra overlay code pin is stale")
        current = self.owned_store.resolve(entry.build_profile)
        actual = next((item for item in current.outputs
                       if item.relative_path == XPRA_BUILD_OUTPUT_PATH), None)
        if actual is None:
            raise XpraOverlayDenied("selected Xpra output receipt is no longer available")
        if (actual is None or actual.artifact_id != receipt.output_artifact_id
                or actual.sha256 != receipt.output_artifact_sha256
                or self.owned_store.resolve_output_object(actual).lstat().st_size != actual.size_bytes):
            raise XpraOverlayDenied("selected Xpra source transform output changed")
        return receipt

    def _resolve_build_profile(self, attestation):
        if (attestation.target_id != XPRA_BUILD_TARGET_ID
                or not attestation.generation):
            raise XpraOverlayDenied("Xpra output came from an unselected build operation")
        try:
            profile = self.active_bindings.resolve_build_process_profile(
                attestation.target_id, attestation.generation,
            )
        except Exception:
            raise XpraOverlayDenied("root-enrolled Xpra transform build profile is unavailable") from None
        if (profile.target_id != XPRA_BUILD_TARGET_ID
                or profile.source_artifact_id != XPRA_SOURCE_ARTIFACT_ID
                or profile.source_sha256 != XPRA_SOURCE_ARCHIVE_SHA256):
            raise XpraOverlayDenied("Xpra build profile does not bind the exact reviewed source archive")
        return profile

    def _selection_current(self, selection) -> bool:
        try:
            current = self.active_bindings.resolve_remote_startup(selection.remote_enrollment_id)
            return (current.id == selection.selected_startup_enrollment_id
                    and current.xpra_xauthority_overlay_artifact_id == selection.overlay_artifact_id
                    and current.xpra_xauthority_overlay_sha256 == selection.overlay_sha256
                    and current.xpra_xauthority_patch_receipt_handle == selection.patch_receipt_handle
                    and self.active_bindings.enrollment_catalog.digest
                        == selection.service_generation_digest)
        except Exception:
            return False

    @staticmethod
    def _receipt_wire(receipt: RootXpraOverlayPatchReceipt) -> dict[str, Any]:
        import base64
        return {
            "schema": receipt.schema, "receipt_handle": receipt.receipt_handle,
            "source_commit": receipt.source_commit,
            "source_tree_digest": receipt.source_tree_digest,
            "overlay_artifact_id": receipt.overlay_artifact_id,
            "overlay_sha256": receipt.overlay_sha256,
            "transformed_tree_sha256": receipt.transformed_tree_sha256,
            "output_artifact_id": receipt.output_artifact_id,
            "output_artifact_sha256": receipt.output_artifact_sha256,
            "selected_enrollment_id": receipt.selected_enrollment_id,
            "process_generation": receipt.process_generation,
            "service_generation_digest": receipt.service_generation_digest,
            "issued_monotonic": receipt.issued_monotonic,
            "expires_monotonic": receipt.expires_monotonic,
            "signature_b64": base64.b64encode(receipt.signature).decode("ascii"),
        }
