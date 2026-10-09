"""Source-pinned Xpra overlay for the root-owned Xauthority credential.

The overlay is intentionally tied to the exact Xpra tree reviewed in the
remote-desktop plan.  It does not claim to install or launch Xpra; it creates
an immutable patched source tree whose digest can be enrolled as an artifact.
The runtime must still verify the artifact receipt and Xauthority mount before
using this tree.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
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


class XpraOverlayDenied(PermissionError):
    """Pinned source or expected patch anchors differ."""


@dataclass(frozen=True, slots=True)
class XpraOverlayReceipt:
    schema: int
    source_commit: str
    source_sha256: Mapping[str, str]
    output_sha256: Mapping[str, str]
    overlay_sha256: str
    patched_root: Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    count = data.count(old)
    if count != 1:
        raise XpraOverlayDenied(f"pinned Xpra patch anchor mismatch: {label}")
    return data.replace(old, new, 1)


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
        b"    # Root-selected remote display supplies its Xauthority file; never mint a second cookie.\n"
        b"    _hermes_root_xauth = os.environ.get(\"XAUTHORITY\") == \"/run/hermes-installer/display/Xauthority\"\n"
        b"    xauth_data: str = \"\" if _hermes_root_xauth else (get_hex_uuid() if start_vfb else \"\")\n",
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
        b"        if os.environ.get(\"XAUTHORITY\") == \"/run/hermes-installer/display/Xauthority\":\n"
        b"            if \"-auth\" in self.xvfb_cmd:\n"
        b"                _hermes_auth_index = self.xvfb_cmd.index(\"-auth\")\n"
        b"                if (_hermes_auth_index + 1 >= len(self.xvfb_cmd)\n"
        b"                        or self.xvfb_cmd[_hermes_auth_index + 1] != \"/run/hermes-installer/display/Xauthority\"\n"
        b"                        or self.xvfb_cmd.count(\"-auth\") != 1):\n"
        b"                    raise InitExit(ExitCode.NO_DISPLAY, \"selected Xvfb auth path differs\")\n"
        b"            else:\n"
        b"                self.xvfb_cmd.extend((\"-auth\", \"/run/hermes-installer/display/Xauthority\"))\n",
        "xvfb-fixed-auth-argument",
    )
    xvfb = _replace_once(
        xvfb,
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n"
        b"        from xpra.x11.vfb_util import get_xauthority_path, valid_xauth\n",
        b"    def setup_xauthority(self, display_name: str, shadowing: bool, writable: bool = True) -> str:\n"
        b"        from xpra.x11.vfb_util import get_xauthority_path, valid_xauth\n"
        b"        if os.environ.get(\"XAUTHORITY\") == \"/run/hermes-installer/display/Xauthority\":\n"
        b"            _hermes_path = \"/run/hermes-installer/display/Xauthority\"\n"
        b"            _hermes_fd = os.open(_hermes_path, os.O_RDONLY | getattr(os, \"O_NOFOLLOW\", 0))\n"
        b"            try:\n"
        b"                _hermes_stat = os.fstat(_hermes_fd)\n"
        b"                if (not stat.S_ISREG(_hermes_stat.st_mode) or _hermes_stat.st_uid != 0\n"
        b"                        or stat.S_IMODE(_hermes_stat.st_mode) != 0o640):\n"
        b"                    raise InitExit(ExitCode.NO_DISPLAY, \"root Xauthority mount is not protected\")\n"
        b"            finally:\n"
        b"                os.close(_hermes_fd)\n"
        b"            session_files = self.get_subsystem(\"session-files\")\n"
        b"            assert session_files\n"
        b"            session_files.write_session_file(\"xauthority\", _hermes_path)\n"
        b"            return _hermes_path\n",
        "xvfb-root-xauthority-selection",
    )
    xvfb = _replace_once(
        xvfb,
        b"        if (use_display is not None and not upgrading) or proxying or encoder:\n",
        b"        if os.environ.get(\"XAUTHORITY\") == \"/run/hermes-installer/display/Xauthority\":\n"
        b"            if not display_name.startswith(\":\"):\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"root-selected display name is invalid\")\n"
        b"            if verify_display(None, display_name, log_errors=False, timeout=1):\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"selected display is already active\")\n"
        b"            _hermes_socket = os.path.join(X11_SOCKET_DIR, \"X\" + display_name[1:])\n"
        b"            if stat_display_socket(_hermes_socket):\n"
        b"                raise InitExit(ExitCode.NO_DISPLAY, \"selected display socket already exists\")\n"
        b"            # Never repair, replace, or add credentials to a selected readonly authority file.\n"
        b"            return start_vfb, \"\", use_display\n"
        b"        if (use_display is not None and not upgrading) or proxying or encoder:\n",
        "xvfb-no-cookie-repair",
    )
    xvfb = _replace_once(
        xvfb,
        b"            assert not proxying and self.xauth_data\n",
        b"            assert not proxying and (self.xauth_data or xauthority == \"/run/hermes-installer/display/Xauthority\")\n",
        "xvfb-root-cookie-validity",
    )
    xvfb = _replace_once(
        xvfb,
        b"            assert xauthority\n"
        b"            xauth_add(xauthority, display_name, self.xauth_data, self.uid, self.gid)\n",
        b"            assert xauthority\n"
        b"            if xauthority != \"/run/hermes-installer/display/Xauthority\":\n"
        b"                xauth_add(xauthority, display_name, self.xauth_data, self.uid, self.gid)\n",
        "xvfb-no-xauth-add",
    )
    sources["xpra/server/subsystem/xvfb.py"] = xvfb

    vfb = sources["xpra/x11/vfb_util.py"]
    vfb = _replace_once(
        vfb,
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n"
        b"    xauth_args = [\"-f\", filename, \"add\", display_name, \"MIT-MAGIC-COOKIE-1\", xauth_data]\n",
        b"def xauth_add(filename: str, display_name: str, xauth_data: str, uid: int, gid: int) -> None:\n"
        b"    if filename == \"/run/hermes-installer/display/Xauthority\":\n"
        b"        raise PermissionError(\"root-selected Xauthority is readonly and cannot be modified\")\n"
        b"    xauth_args = [\"-f\", filename, \"add\", display_name, \"MIT-MAGIC-COOKIE-1\", xauth_data]\n",
        "vfb-no-xauth-add-root-file",
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
        dirty = subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all"],
            check=True, capture_output=True, text=True, timeout=5,
            env={"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"},
        ).stdout
    except (OSError, subprocess.SubprocessError):
        raise XpraOverlayDenied("cannot verify Xpra source worktree") from None
    if dirty:
        raise XpraOverlayDenied("Xpra source worktree is not pristine")
    patched = _patch_sources(source_root)
    try:
        shutil.copytree(source_root, output_root, symlinks=True,
                        ignore=shutil.ignore_patterns(".git"))
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
        manifest = {
            "schema": 1, "overlay": "installer-xpra-root-xauthority-overlay-v1",
            "source_commit": commit, "source_sha256": _PINNED_INPUTS,
            "output_sha256": output_hashes,
        }
        digest = _sha256(json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")).encode())
        return XpraOverlayReceipt(1, commit, dict(_PINNED_INPUTS), output_hashes,
                                  digest, output_root)
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
