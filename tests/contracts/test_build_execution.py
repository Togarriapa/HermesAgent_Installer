from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.build_execution import (
    BuildOutputSpec, ContentAddressedBuildStore, LinuxBuildOutputFactInspector,
    ManagedBuildResult, managed_process_identity_digest,
)
from hermes_installer.authority.types import AuthorityDenied


def constraints():
    return {
        "bin/colibri": BuildOutputSpec(
            "bin/colibri", "file", 1024 * 1024, "colibri-engine",
            {"elf_class": 64, "elf_machine": "EM_AARCH64", "required_runtime_dependencies": ["libgomp.so.1"]},
        ),
        "runtime/lib/python3.9": BuildOutputSpec(
            "runtime/lib/python3.9", "tree", 1024 * 1024, "cpython-stdlib-and-extension-closure",
            {"python_version": "3.9.25", "target": "linux-aarch64"},
        ),
    }


class Profile:
    target_id = "colibri-source-build:start"
    generation = "generation-1"
    service_generation_digest = "a" * 64
    source_artifact_id = "colibri-source"
    source_sha256 = "1" * 64
    toolchain_artifact_id = "aarch64-sysroot"
    toolchain_sha256 = "2" * 64
    builder_artifact_id = "fixed-builder"
    builder_sha256 = "3" * 64
    argv_recipe = ("/catalog/builder", "build", "--fixed")
    environment = {"LANG": "C"}
    max_lifetime_seconds = 600
    output_root_id = "build-output"
    output_owner_uid = os.getuid()
    output_specs = constraints()

    def __init__(self, output_root: Path):
        self.output_root = output_root


class FixtureInspector:
    def __init__(self, *, corrupt=False):
        self.corrupt = corrupt

    def inspect(self, profile, spec, path):
        if self.corrupt:
            return {"elf_class": 32}
        if spec.relative_path == "bin/colibri":
            return {"elf_class": 64, "elf_machine": "EM_AARCH64",
                    "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                    "resolved_dependency_closure": [{"name": "libgomp.so.1", "sha256": "f" * 64}]}
        return {"python_version": "3.9.25", "target": "linux-aarch64",
                "native_extension_manifest": []}


def completed(**changes):
    now = time.monotonic()
    row = {
        "process_id": "managed-build-1", "generation": "generation-1", "uid": os.getuid(),
        "pid": 12345, "start_ticks": 55, "exit_code": 0, "timed_out": False,
        "cancelled": False, "cleanup_verified": True, "started_monotonic": now - .25,
        "finished_monotonic": now - .05,
        "kernel_limits": {"PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
                          "NoNewPrivileges": "yes", "ProtectSystem": "strict"},
        "terminal_success_record_id": "terminal:success:1", "process_identity_digest": "",
        "cgroup_id": "cgroup:fixture", "mount_namespace_inode": 101,
        "network_namespace_inode": 102, "bounded_log_digest": "c" * 64, "log_bytes": 16,
    }
    row.update(changes)
    if "process_identity_digest" not in changes:
        row["process_identity_digest"] = managed_process_identity_digest(
            process_id=row["process_id"], generation=row["generation"], uid=row["uid"], pid=row["pid"],
            start_ticks=row["start_ticks"], cgroup_id=row["cgroup_id"],
            mount_namespace_inode=row["mount_namespace_inode"],
            network_namespace_inode=row["network_namespace_inode"])
    return ManagedBuildResult(**row)


def write_file(root: Path, name: str, data: bytes, executable=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700 if executable else 0o600)
    return path


def make_store(path: Path):
    return ContentAddressedBuildStore(path, signing_key=b"k" * 32, owner_uid=os.getuid())


def filled_output(root):
    root.mkdir(mode=0o700)
    write_file(root, "bin/colibri", b"fixture ARM64 executable", executable=True)
    write_file(root, "runtime/lib/python3.9/os.py", b"stdlib fixture")
    write_file(root, "runtime/lib/python3.9/lib-dynload/_test.so", b"extension fixture")


def test_dynamic_output_manifest_is_root_hashed_and_atomically_resolved():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        base = Path(temp)
        output_root = base / "outputs"
        filled_output(output_root)
        profile = Profile(output_root)
        store = make_store(base / "cas")
        receipt = store.publish(profile, enrollment_id="enrollment-1",
                                operation_id="colibri-source-build-v1", process=completed(),
                                fact_inspector=FixtureInspector())

        assert receipt.service_generation_digest == profile.service_generation_digest
        assert receipt.receipt_digest == hashlib.sha256(json.dumps(
            receipt.unsigned_wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")).hexdigest()
        assert {item.relative_path for item in receipt.outputs} == set(profile.output_specs)
        assert all(item.sha256 for item in receipt.outputs)
        tree = next(item for item in receipt.outputs if item.kind == "tree")
        assert tree.tree_file_manifest_sha256 == tree.sha256
        assert (store.resolve_output(profile, "bin/colibri")).read_bytes() == b"fixture ARM64 executable"
        assert (store.resolve_output(profile, "runtime/lib/python3.9") / "os.py").read_bytes() == b"stdlib fixture"
        assert store.resolve(profile).receipt_id == receipt.receipt_id


def test_root_fact_mismatch_or_inspector_error_never_publishes_receipt():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        profile = Profile(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector(corrupt=True))
        assert not (store.root / "attestations").exists()


@pytest.mark.parametrize("changes", [
    {"exit_code": 1}, {"exit_code": None}, {"timed_out": True}, {"cancelled": True},
    {"cleanup_verified": False}, {"terminal_success_record_id": ""},
    {"process_identity_digest": "bad"}, {"mount_namespace_inode": 0},
    {"kernel_limits": {"PrivateNetwork": "no"}},
])
def test_no_receipt_for_nonterminal_or_unproven_process(changes):
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(Profile(root), enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(**changes), fact_inspector=FixtureInspector())
        assert not (store.root / "attestations").exists()


@pytest.mark.parametrize("mutation", ["missing", "extra", "symlink", "oversize"])
def test_output_scanner_rejects_incomplete_or_unbounded_tree(mutation):
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        if mutation == "missing":
            (root / "bin/colibri").unlink()
        elif mutation == "extra":
            write_file(root, "unreviewed", b"extra")
        elif mutation == "symlink":
            (root / "runtime/lib/python3.9/link").symlink_to(root / "bin/colibri")
        else:
            write_file(root, "bin/colibri", b"x" * (1024 * 1024 + 1), executable=True)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(Profile(root), enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector())
        assert not (store.root / "attestations").exists()


def test_cancellation_and_tampered_receipt_or_cas_object_fail_closed():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        profile = Profile(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector(), cancelled=lambda: True)
        assert not store.root.exists()
        receipt = store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                                process=completed(), fact_inspector=FixtureInspector())
        path = store.resolve_output(profile, "bin/colibri")
        path.chmod(0o755)
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)
        path.chmod(0o555)
        record_path = store.root / "attestations" / f"{receipt.receipt_id}.json"
        record_path.chmod(0o600)
        raw = json.loads(record_path.read_text())
        raw["service_generation_digest"] = "d" * 64
        record_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")))
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)


def elf64_aarch64(needed=()):
    data = bytearray(512)
    data[:4] = b"\x7fELF"
    data[4:7] = b"\x02\x01\x01"
    data[7] = 0
    data[16:18] = (2).to_bytes(2, "little")
    data[18:20] = (183).to_bytes(2, "little")
    data[32:40] = (64).to_bytes(8, "little")
    data[52:54] = (64).to_bytes(2, "little")
    data[54:56] = (56).to_bytes(2, "little")
    if needed:
        data[56:58] = (2).to_bytes(2, "little")
        strings = b"\0" + b"\0".join(name.encode() for name in needed) + b"\0"
        load = 64
        data[load:load+4] = (1).to_bytes(4, "little")
        data[load+8:load+16] = (0).to_bytes(8, "little")
        data[load+16:load+24] = (0).to_bytes(8, "little")
        data[load+32:load+40] = len(data).to_bytes(8, "little")
        data[load+40:load+48] = len(data).to_bytes(8, "little")
        dynamic_header = 120
        data[dynamic_header:dynamic_header+4] = (2).to_bytes(4, "little")
        data[dynamic_header+8:dynamic_header+16] = (200).to_bytes(8, "little")
        data[dynamic_header+16:dynamic_header+24] = (200).to_bytes(8, "little")
        data[dynamic_header+32:dynamic_header+40] = (96).to_bytes(8, "little")
        data[dynamic_header+40:dynamic_header+48] = (96).to_bytes(8, "little")
        rows = [(5, 300), (10, len(strings))]
        rows.extend((1, offset) for offset in [] )
        cursor = 1
        for name in needed:
            rows.append((1, cursor))
            cursor += len(name) + 1
        rows.append((0, 0))
        for index, (tag, value) in enumerate(rows):
            offset = 200 + index * 16
            data[offset:offset+8] = tag.to_bytes(8, "little", signed=True)
            data[offset+8:offset+16] = value.to_bytes(8, "little")
        data[300:300+len(strings)] = strings
    return bytes(data)


def test_linux_fact_inspector_parses_aarch64_elf_dependencies_and_rejects_x86():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        root = Path(temp)
        path = root / "colibri"
        path.write_bytes(elf64_aarch64(("libgomp.so.1", "libm.so.6", "libc.so.6")))
        path.chmod(0o444)
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=lambda _profile: root,
            source_root_resolver=lambda _profile: root,
            runtime_probe=SimpleNamespace(inspect_cpython39=lambda _profile, _path: {}),
            owner_uid=os.getuid())
        facts, dependencies = inspector._elf(path)
        assert facts == {"elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux"}
        assert dependencies == ("libgomp.so.1", "libm.so.6", "libc.so.6")

        wrong = bytearray(elf64_aarch64())
        wrong[18:20] = (62).to_bytes(2, "little")
        path.chmod(0o600)
        path.write_bytes(wrong)
        with pytest.raises(AuthorityDenied):
            inspector._elf(path)


def test_linux_fact_inspector_hashes_actual_root_owned_dependency_closure():
    with tempfile.TemporaryDirectory(dir="/private/tmp") as temp:
        root = Path(temp)
        expected = {}
        for name in ("libgomp.so.1", "libm.so.6", "libc.so.6"):
            content = elf64_aarch64()
            path = root / name
            path.write_bytes(content)
            path.chmod(0o444)
            expected[name] = hashlib.sha256(content).hexdigest()
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=lambda _profile: root,
            source_root_resolver=lambda _profile: root,
            runtime_probe=SimpleNamespace(inspect_cpython39=lambda _profile, _path: {}),
            owner_uid=os.getuid())
        closure = inspector._dependency_closure(root, tuple(expected))
        assert {row["name"]: row["sha256"] for row in closure} == expected
        assert all(row["owner_uid"] == os.getuid() and Path(row["absolute_path"]).is_absolute() for row in closure)
