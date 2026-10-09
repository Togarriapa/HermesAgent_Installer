"""Apply the pinned Xpra allowlist patch before enabling the HTML5 bridge."""
from __future__ import annotations
import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path
PINNED_WINDOW_SOURCE_GIT_BLOB="a67b72eb2faef9fc53d218633a9ea7c979d0827b"
def _git_blob_id(source:str)->str:
 raw=source.encode("utf-8")
 return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def patch_can_send_window(method_source:str)->str:
 needle="""                    filterslog("can_send_window(%s)=%s", window, v)
                    return v
        if self.window_enabled and self.system_tray:
"""
 replacement="""                    filterslog("can_send_window(%s)=%s", window, v)
                    return v
            # Installer patch: filters are a security allowlist, unmatched denies.
            return False
        if self.window_enabled and self.system_tray:
"""
 if method_source.count(needle)!=1:raise ValueError("Xpra can_send_window source does not match pinned patch context")
 return method_source.replace(needle,replacement,1)
def apply_pinned_window_patch(source:str,allowed_classes:Iterable[str])->str:
 from re import fullmatch
 classes=tuple(sorted(set(allowed_classes)))
 if not classes or any(not isinstance(c,str) or not fullmatch(r"[A-Za-z0-9_.-]{1,128}",c) for c in classes):raise ValueError("invalid Hermes Desktop window class allowlist")
 if _git_blob_id(source)!=PINNED_WINDOW_SOURCE_GIT_BLOB:raise ValueError("Xpra window source differs from reviewed pinned revision")
 anchor="""        self.window_filters = window.window_filters
        self.readonly = server.readonly
"""
 replacement="""        # Rebuild filters from the installer-owned finite class allowlist.
        self.window_filters = [
            (self.uuid, get_window_filter("window", "class-instance", "=", value))
            for value in {"""+", ".join(repr(c) for c in classes)+"""}
        ]
        if not self.window_filters:
            raise RuntimeError("Hermes Desktop window allowlist is empty")
        self.readonly = server.readonly
"""
 if source.count(anchor)!=1:raise ValueError("Xpra connection initialization differs from pinned patch context")
 result=source.replace(anchor,replacement,1)
 start=result.index("    def can_send_window(self, window) -> bool:")
 end=result.index("\n    ######################################################################",start)
 result=result[:start]+patch_can_send_window(result[start:end])+result[end:]
 result += "\n"+_PATCH_META_PREFIX+",".join(classes)+"\n"
 return result+_PATCH_HASH_PREFIX+hashlib.sha256(result.encode("utf-8")).hexdigest()+"\n"

_PATCH_META_PREFIX = "# HermesInstaller-Xpra-Allowed-Classes:"
_PATCH_HASH_PREFIX = "# HermesInstaller-Xpra-Patch-Content-SHA256:"

def _managed_patch_valid(source: str, classes: tuple[str, ...]) -> bool:
    meta = _PATCH_META_PREFIX + ",".join(classes)
    if source.count(meta + "\n") != 1:
        return False
    matches = re.findall(r"(?m)^# HermesInstaller-Xpra-Patch-Content-SHA256:([0-9a-f]{64})$", source)
    if len(matches) != 1:
        return False
    unhashed = re.sub(r"(?m)^# HermesInstaller-Xpra-Patch-Content-SHA256:[0-9a-f]{64}\n", "", source)
    return hashlib.sha256(unhashed.encode("utf-8")).hexdigest() == matches[0]

def install_pinned_window_patch(xpra_root: Path, allowed_classes: Iterable[str]) -> bool:
    """Atomically install a patch only into pinned xpra/server/window.py.

    True means the file changed; False means the exact managed patch is already
    present. Refuse symlinks, edited patches, unrecognized source revisions,
    non-regular files, and files beyond the small source-file bound.
    """
    root = Path(xpra_root)
    if not root.is_absolute():
        raise ValueError("Xpra package root must be absolute")
    root = root.resolve(strict=True)
    target = root
    for component in ("xpra", "server", "window.py"):
        target = target / component
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Xpra package path contains a symlink")
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
        raise ValueError("Xpra source is not a bounded regular file")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Xpra source changed during verification")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 2 * 1024 * 1024:
                break
        raw = b"".join(chunks)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Xpra source exceeds patch bound")
        source = raw.decode("utf-8", "strict")
    finally:
        os.close(fd)
    classes = tuple(sorted(set(allowed_classes)))
    if _PATCH_META_PREFIX in source or _PATCH_HASH_PREFIX in source:
        if not _managed_patch_valid(source, classes):
            raise ValueError("existing Xpra patch is modified or has a different allowlist")
        return False
    patched = apply_pinned_window_patch(source, classes)
    fd, temp_name = tempfile.mkstemp(prefix=".hermes-xpra-window-", dir=target.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(info.st_mode))
        if (opened.st_uid, opened.st_gid) != (os.geteuid(), os.getegid()):
            os.fchown(fd, opened.st_uid, opened.st_gid)
        view = memoryview(patched.encode("utf-8"))
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        current = target.lstat()
        if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Xpra source changed before atomic replacement")
        os.replace(temp_name, target)
        dirfd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return True
