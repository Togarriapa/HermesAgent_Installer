#!/usr/bin/env python3
"""Apply the pinned Xpra 6.5.4 disabled-control and no-client-command guards."""
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
CORE_SIZE = 75_650
CORE_SHA256 = "67bf4c1c903fedfd4bb9c7e040e5f4b2d1e9b41f7efcbf43c50a02306ca8000a"
WINDOW_SIZE = 42_383
WINDOW_SHA256 = "6f36f82a51d55b5302772e23f7f6e1317226184e0635b0f3f5954dacaca16a0f"
CORE_MD5 = "f27671cadfd5efe5a6f363b30da72fef"
WINDOW_MD5 = "991eb3b6866c1df49fa55b54e2fbad7b"
COMMAND_SIZE = 23_581
COMMAND_SHA256 = "804eca53b88e23996fb41c394318531548193a750f07e6846dbdaffe8db7126e"
COMMAND_MD5 = "53922da70a3214d9adc47a901313a487"

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
CORE_RELATIVE = Path("usr/lib/python3/dist-packages/xpra/server/core.py")
WINDOW_RELATIVE = Path("usr/lib/python3/dist-packages/xpra/server/subsystem/window.py")
COMMAND_RELATIVE = Path("usr/lib/python3/dist-packages/xpra/server/subsystem/command.py")
LOCAL_VERSION = "6.5.4-r0-1+jarvis3"
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


CORE_OLD = (
    b'    def add_core_control_commands(self) -> None:\n'
    b'        from xpra.net.control.common import parse_boolean_value\n'
)
CORE_NEW = (
    b'    def add_core_control_commands(self) -> None:\n'
    b'        from xpra.server import features\n'
    b'        if not features.control:\n'
    b'            return\n'
    b'        from xpra.net.control.common import parse_boolean_value\n'
)
WINDOW_OLD = (
    b'    def add_window_control_commands(self) -> None:\n'
    b'        from xpra.util.parsing import parse_scaling_value, from0to100\n'
    b'        from xpra.net.control.common import parse_boolean_value, parse_4intlist\n'
)
WINDOW_NEW = (
    b'    def add_window_control_commands(self) -> None:\n'
    b'        from xpra.server import features\n'
    b'        if not features.control:\n'
    b'            return\n'
    b'        from xpra.util.parsing import parse_scaling_value, from0to100\n'
    b'        from xpra.net.control.common import parse_boolean_value, parse_4intlist\n'
)
CORE_PATCHED_SIZE = 75_743
CORE_PATCHED_SHA256 = "95a8bb41304181555ac33482931ba1c2460b4a1b03e458c3c5e8825adcf34e77"
CORE_PATCHED_MD5 = "4be1d1a6c50413f074eaf7d316aa07b3"
WINDOW_PATCHED_SIZE = 42_476
WINDOW_PATCHED_SHA256 = "7fd74d70e6a50e2f02727e263bdbec34826d23871abf4feedb230741ef09264f"
WINDOW_PATCHED_MD5 = "1eb15f0297d3f5c84b0dce12f41d45d4"

COMMAND_OLD_NEW = (
    (b'        self.hello_request_handlers["run"] = self._handle_hello_request_run\n', b""),
    (b'        self.start_new_commands = opts.start_new_commands\n',
     b'        self.start_new_commands = opts.start_new_commands\n'
     b'        if self.start_new_commands:\n'
     b'            self.hello_request_handlers["run"] = self._handle_hello_request_run\n'
     b'        else:\n'
     b'            self.hello_request_handlers.pop("run", None)\n'),
    (b'    def _handle_hello_request_run(self, proto, caps: typedict) -> bool:\n',
     b'    def _handle_hello_request_run(self, proto, caps: typedict) -> bool:\n'
     b'        if not self.start_new_commands:\n'
     b'            response = {"code": ExitCode.UNSUPPORTED, "message": "command execution is disabled"}\n'
     b'            proto.send_now(Packet("hello", {"run_response": response}))\n'
     b'            return True\n'),
    (b'    def _process_command_signal(self, _proto, packet: Packet) -> None:\n',
     b'    def _process_command_signal(self, _proto, packet: Packet) -> None:\n'
     b'        if not self.start_new_commands:\n'
     b'            log.warn("Warning: received command-signal request, but the feature is currently disabled")\n'
     b'            return\n'),
    (b'        if COMMAND_SIGNALS:\n            self.add_packets("command-signal")\n',
     b'        if COMMAND_SIGNALS and self.start_new_commands:\n            self.add_packets("command-signal")\n'),
)
COMMAND_PATCHED_SIZE = 24_117
COMMAND_PATCHED_SHA256 = "09e90f7dcb8a76687c59ee8c538faef21ce2881bdaed4cafb760eb8fe141f2d3"
COMMAND_PATCHED_MD5 = "b5cbadc4d602785467178814cba3f1a2"


def patch_command_bytes(data: bytes) -> bytes:
    if len(data) != COMMAND_SIZE or hashlib.sha256(data).hexdigest() != COMMAND_SHA256:
        raise ValueError("server/subsystem/command.py does not match the pinned official Xpra 6.5.4 input")
    for old, _new in COMMAND_OLD_NEW:
        if data.count(old) != 1:
            raise ValueError("expected exactly one pinned command-subsystem guard anchor")
    patched = data
    for old, new in COMMAND_OLD_NEW:
        patched = patched.replace(old, new, 1)
    if len(patched) != COMMAND_PATCHED_SIZE or hashlib.sha256(patched).hexdigest() != COMMAND_PATCHED_SHA256:
        raise ValueError("patched command.py does not match the reviewed v262 patch")
    return patched


def _patch_guard_member(data: bytes, *, size: int, sha256: str, old: bytes, new: bytes, label: str) -> bytes:
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError(f"{label} does not match the pinned official Xpra 6.5.4 source")
    if data.count(old) != 1:
        raise ValueError(f"expected exactly one original {label} control-registration body")
    return data.replace(old, new, 1)


def patch_core_bytes(data: bytes) -> bytes:
    patched = _patch_guard_member(data, size=CORE_SIZE, sha256=CORE_SHA256,
                                  old=CORE_OLD, new=CORE_NEW, label="server/core.py")
    if len(patched) != CORE_PATCHED_SIZE or hashlib.sha256(patched).hexdigest() != CORE_PATCHED_SHA256:
        raise ValueError("patched server/core.py does not match the reviewed patch")
    return patched


def patch_window_bytes(data: bytes) -> bytes:
    patched = _patch_guard_member(data, size=WINDOW_SIZE, sha256=WINDOW_SHA256,
                                  old=WINDOW_OLD, new=WINDOW_NEW,
                                  label="server/subsystem/window.py")
    if len(patched) != WINDOW_PATCHED_SIZE or hashlib.sha256(patched).hexdigest() != WINDOW_PATCHED_SHA256:
        raise ValueError("patched server/subsystem/window.py does not match the reviewed patch")
    return patched


PATCHED_CONTROL_MD5S = (
    (STUB_RELATIVE.as_posix(), SOURCE_MD5, PATCHED_MD5),
    (CORE_RELATIVE.as_posix(), CORE_MD5, CORE_PATCHED_MD5),
    (WINDOW_RELATIVE.as_posix(), WINDOW_MD5, WINDOW_PATCHED_MD5),
    (COMMAND_RELATIVE.as_posix(), COMMAND_MD5, COMMAND_PATCHED_MD5),
)
PATCHED_MEMBER_FACTS = {
    STUB_RELATIVE.as_posix(): (PATCHED_SIZE, PATCHED_SHA256),
    CORE_RELATIVE.as_posix(): (CORE_PATCHED_SIZE, CORE_PATCHED_SHA256),
    WINDOW_RELATIVE.as_posix(): (WINDOW_PATCHED_SIZE, WINDOW_PATCHED_SHA256),
    COMMAND_RELATIVE.as_posix(): (COMMAND_PATCHED_SIZE, COMMAND_PATCHED_SHA256),
}


def patch_tree(root: Path) -> None:
    for member, patcher in (
        (STUB_RELATIVE, patch_bytes),
        (CORE_RELATIVE, patch_core_bytes),
        (WINDOW_RELATIVE, patch_window_bytes),
        (COMMAND_RELATIVE, patch_command_bytes),
    ):
        path = root / member
        path.write_bytes(patcher(path.read_bytes()))


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
    for member, old_md5, new_md5 in PATCHED_CONTROL_MD5S:
        matches = [i for i, line in enumerate(lines) if line.rstrip("\n").split(maxsplit=1)[-1:] == [member]]
        if len(matches) != 1:
            raise ValueError(f"expected one md5sums entry for {member}")
        index = matches[0]
        parts = lines[index].split(maxsplit=1)
        if len(parts) != 2 or parts[0] != old_md5:
            raise ValueError(f"original package checksum differs for {member}")
        lines[index] = f"{new_md5}  {member}\n"
    md5_path.write_text("".join(lines), encoding="ascii")


def _tree_manifest(root: Path, *, exclude_top: frozenset[str] = frozenset()) -> dict[str, tuple]:
    manifest: dict[str, tuple] = {}
    def visit(directory: Path, rel: Path = Path()) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            if rel == Path() and entry.name in exclude_top:
                continue
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


def verify_payload_trees(
    original: Path,
    rebuilt: Path,
    *,
    exclude_top: frozenset[str] = frozenset(),
) -> None:
    before = _tree_manifest(original, exclude_top=exclude_top)
    after = _tree_manifest(rebuilt, exclude_top=exclude_top)
    expected = PATCHED_MEMBER_FACTS
    if set(before) != set(after):
        raise ValueError("rebuilt data archive changed the package member set")
    if not set(expected).issubset(before):
        raise ValueError("package tree is missing one or more fixed patched Xpra modules")
    for member in before:
        if member in expected:
            size, sha256 = expected[member]
            if after[member] != ("file", before[member][1], size, sha256):
                raise ValueError(f"rebuilt member does not match reviewed mode/size/hash: {member}")
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
            if old_bytes.count(old_line) != 1 or old_bytes.replace(old_line, b"Version: 6.5.4-r0-1+jarvis3\n", 1) != new_bytes:
                raise ValueError("control metadata changed beyond the exact local package version")
        elif name == "md5sums":
            expected_bytes = old_bytes
            for member, old_md5, new_md5 in PATCHED_CONTROL_MD5S:
                old_row = old_md5.encode() + b"  " + member.encode() + b"\n"
                new_row = new_md5.encode() + b"  " + member.encode() + b"\n"
                if expected_bytes.count(old_row) != 1:
                    raise ValueError(f"md5sums does not contain the exact original row for {member}")
                expected_bytes = expected_bytes.replace(old_row, new_row, 1)
            if expected_bytes != new_bytes:
                raise ValueError("md5sums changed beyond the four reviewed source members")


def verify_repacked_package(original_root: Path, rebuilt_root: Path) -> None:
    """Compare dpkg-deb --raw-extract roots (payload plus DEBIAN metadata)."""
    verify_payload_trees(
        original_root,
        rebuilt_root,
        exclude_top=frozenset({"DEBIAN"}),
    )
    verify_control_directories(original_root / "DEBIAN", rebuilt_root / "DEBIAN")


def main() -> int:
    valid = (len(sys.argv) == 3 and sys.argv[1] in {"patch", "metadata"}) or (len(sys.argv) == 4 and sys.argv[1] == "verify")
    if not valid:
        print("usage: xpra_control_guard_patch.py patch|metadata <directory> | verify <original-root> <rebuilt-root>", file=sys.stderr)
        return 2
    try:
        directory = Path(sys.argv[2])
        if sys.argv[1] == "patch":
            patch_tree(directory)
            print("patched fixed source members:")
            for member, (size, digest) in PATCHED_MEMBER_FACTS.items():
                print(f"{member} size={size} sha256={digest}")
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
