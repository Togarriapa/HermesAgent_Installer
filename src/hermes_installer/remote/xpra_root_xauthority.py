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
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


XPRA_SOURCE_COMMIT = "521b0d2e762c770b2641d258b93d23575fa9cbea"
ROOT_XAUTHORITY = "/run/hermes-installer/display/Xauthority"
_PINNED_INPUTS = {
    "xpra/scripts/server.py": "40e9ced39617ce7ba26ce26a320e86d3c20944f3cf9ff9e47e459d3180372ead",
    "xpra/server/subsystem/xvfb.py": "fd1718ad7fb3b905547b86116df241694c9a6c59c4c40e954a38764689201de6",
    "xpra/x11/vfb_util.py": "9285e8a124384270c92df6338d8e2d0f30da20a47616a4f33f6b79bff6c185d6",
}
OVERLAY_ARTIFACT_ID = "installer-xpra-root-xauthority-overlay-v1"
OVERLAY_MANIFEST = "hermes-installer-xpra-root-xauthority-overlay-v1.json"


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
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in names + files:
            path = base / name
            rel = path.relative_to(root).as_posix()
            if rel == OVERLAY_MANIFEST:
                continue
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
