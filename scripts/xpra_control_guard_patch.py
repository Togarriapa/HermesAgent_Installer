#!/usr/bin/env python3
"""Apply the single pinned Xpra 6.5.4 control-disabled startup fix."""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

SOURCE_SIZE = 4_978
SOURCE_SHA256 = "d0f4cf681095d90c3f1ab039c2932e7fb6b450d3c01ba48fa873e10ff1c95a4e"
PATCHED_SIZE = 5_071
PATCHED_SHA256 = "da12f27c1421dc71248b568791f186ee3d470d0969c4020da0d9d6d7a1a02279"
SOURCE_MD5 = "f2bf39a8a05eb972fb70c9da330154d2"
PATCHED_MD5 = "14fa7242a94bfcdceebee92ee13a33a9"

OLD = (
    b'    def args_control(self, name: str, descr: str, **kwargs) -> None:\n'
    b'        from xpra.net.control.common import add_args_control_command\n'
    b'        run = getattr(self, "control_command_%s" % name.replace("-", "_"), noop)\n'
)
NEW = (
    b'    def args_control(self, name: str, descr: str, **kwargs) -> None:\n'
    b'        from xpra.server import features\n'
    b'        if not features.control:\n'
    b'            return\n'
    b'        from xpra.net.control.common import add_args_control_command\n'
    b'        run = getattr(self, "control_command_%s" % name.replace("-", "_"), noop)\n'
)
STUB_RELATIVE = Path("usr/lib/python3/dist-packages/xpra/server/subsystem/stub.py")
LOCAL_VERSION = "6.5.4-r0-1+jarvis1"
PACKAGE = "xpra-server"
ARCHITECTURE = "arm64"


def patch_bytes(data: bytes) -> bytes:
    if len(data) != SOURCE_SIZE or hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("stub.py does not match the pinned official xpra-server 6.5.4 input")
    if data.count(OLD) != 1:
        raise ValueError("expected exactly one original args_control body")
    patched = data.replace(OLD, NEW, 1)
    if len(patched) != PATCHED_SIZE or hashlib.sha256(patched).hexdigest() != PATCHED_SHA256:
        raise ValueError("patched stub.py bytes do not match the reviewed patch")
    return patched


def patch_tree(root: Path) -> None:
    path = root / STUB_RELATIVE
    path.write_bytes(patch_bytes(path.read_bytes()))


def update_control_directory(directory: Path) -> None:
    control_path = directory / "control"
    control = control_path.read_text(encoding="utf-8")
    expected = {
        "Package": PACKAGE,
        "Version": "6.5.4-r0-1",
        "Architecture": ARCHITECTURE,
    }
    fields = {}
    for line in control.splitlines():
        if line and not line[0].isspace() and ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    for key, value in expected.items():
        if fields.get(key) != value:
            raise ValueError(f"unexpected source package {key}: {fields.get(key)!r}")
    old_version = "Version: 6.5.4-r0-1\n"
    if control.count(old_version) != 1:
        raise ValueError("expected one exact original Version control field")
    control_path.write_text(control.replace(old_version, f"Version: {LOCAL_VERSION}\n", 1), encoding="utf-8")

    md5_path = directory / "md5sums"
    lines = md5_path.read_text(encoding="ascii").splitlines(keepends=True)
    member = STUB_RELATIVE.as_posix()
    old_md5 = SOURCE_MD5
    new_md5 = PATCHED_MD5
    matches = [i for i, line in enumerate(lines) if line.rstrip("\n").split(maxsplit=1)[-1:] == [member]]
    if len(matches) != 1:
        raise ValueError("expected one md5sums entry for the exact patched module")
    index = matches[0]
    parts = lines[index].split(maxsplit=1)
    if len(parts) != 2 or parts[0] != old_md5:
        raise ValueError("original stub.py checksum in package md5sums differs")
    lines[index] = f"{new_md5}  {member}\n"
    md5_path.write_text("".join(lines), encoding="ascii")


def _tree_manifest(root: Path) -> dict[str, tuple]:
    manifest: dict[str, tuple] = {}
    def visit(directory: Path, rel: Path = Path()) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            child_rel = rel / entry.name
            child = Path(entry.path)
            info = child.lstat()
            mode = stat.S_IMODE(info.st_mode)
            key = child_rel.as_posix()
            if stat.S_ISDIR(info.st_mode):
                manifest[key] = ("dir", mode)
                visit(child, child_rel)
            elif stat.S_ISLNK(info.st_mode):
                manifest[key] = ("symlink", mode, os.readlink(child))
            elif stat.S_ISREG(info.st_mode):
                data = child.read_bytes()
                manifest[key] = ("file", mode, len(data), hashlib.sha256(data).hexdigest())
            else:
                raise ValueError(f"unsupported special package member {key}")
    visit(root)
    return manifest


def verify_payload_trees(original: Path, rebuilt: Path) -> None:
    before = _tree_manifest(original)
    after = _tree_manifest(rebuilt)
    key = STUB_RELATIVE.as_posix()
    if set(before) != set(after):
        raise ValueError("rebuilt data archive changed the package member set")
    for member in before:
        if member == key:
            if after[member] != ("file", before[member][1], PATCHED_SIZE, PATCHED_SHA256):
                raise ValueError("rebuilt stub.py does not match its reviewed mode/size/hash")
        elif before[member] != after[member]:
            raise ValueError(f"rebuilt package changed an unrelated payload member: {member}")


def verify_control_directories(original: Path, rebuilt: Path) -> None:
    before = _tree_manifest(original)
    after = _tree_manifest(rebuilt)
    if set(before) != set(after):
        raise ValueError("rebuilt package changed its control member set")
    for name in before:
        old_path, new_path = original / name, rebuilt / name
        old, new = before[name], after[name]
        if name in {"control", "md5sums"}:
            if old[0:2] != new[0:2] or old[0] != "file":
                raise ValueError(f"rebuilt control member changed type or mode: {name}")
            old_bytes, new_bytes = old_path.read_bytes(), new_path.read_bytes()
        else:
            if old != new:
                raise ValueError(f"rebuilt package changed unrelated control metadata: {name}")
            continue
        if name == "control":
            old_line = b"Version: 6.5.4-r0-1\n"
            if old_bytes.count(old_line) != 1 or old_bytes.replace(old_line, b"Version: 6.5.4-r0-1+jarvis1\n", 1) != new_bytes:
                raise ValueError("control metadata changed beyond the exact local package version")
        elif name == "md5sums":
            old_md5, new_md5 = SOURCE_MD5.encode(), PATCHED_MD5.encode()
            old_row = old_md5 + b"  " + STUB_RELATIVE.as_posix().encode() + b"\n"
            new_row = new_md5 + b"  " + STUB_RELATIVE.as_posix().encode() + b"\n"
            if old_bytes.count(old_row) != 1 or old_bytes.replace(old_row, new_row, 1) != new_bytes:
                raise ValueError("md5sums changed beyond the patched stub.py checksum")


def verify_repacked_package(original_root: Path, rebuilt_root: Path) -> None:
    """Compare independently unpacked data/control roots against the exact allowance."""
    verify_payload_trees(original_root / "data", rebuilt_root / "data")
    verify_control_directories(original_root / "DEBIAN", rebuilt_root / "DEBIAN")


OLD = (
    b'    def args_control(self, name: str, descr: str, **kwargs) -> None:\n'
    b'        from xpra.net.control.common import add_args_control_command\n'
    b'        run = getattr(self, "control_command_%s" % name.replace("-", "_"), noop)\n'
)
def main() -> int:
    valid = (len(sys.argv) == 3 and sys.argv[1] in {"patch", "metadata"}) or (len(sys.argv) == 4 and sys.argv[1] == "verify")
    if not valid:
        print("usage: xpra_control_guard_patch.py patch|metadata <directory> | verify <original-root> <rebuilt-root>", file=sys.stderr)
        return 2
    try:
        directory = Path(sys.argv[2])
        if sys.argv[1] == "patch":
            patch_tree(directory)
            print(f"patched size={PATCHED_SIZE} sha256={PATCHED_SHA256}")
        elif sys.argv[1] == "metadata":
            update_control_directory(directory)
        else:
            rebuilt = Path(sys.argv[3])
            verify_repacked_package(directory, rebuilt)
            print("package payload/control comparison passed")
    except (OSError, ValueError) as exc:
        print(f"refusing Xpra source patch: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
