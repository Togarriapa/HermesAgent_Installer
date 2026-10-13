"""Fixed two-file Resources plugin transition I/O contracts.

Filesystem-effect cases require root ownership and are intentionally skipped
on ordinary developer hosts; the Pi qualification runs them as root.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from hermes_installer.remote import native_plugin_bootstrap as bootstrap


pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="fixed plugin transition requires root file custody")


OLD = {"plugin.yaml": b"name: fixed-resources\nversion: 1\n",
       "__init__.py": b"OLD_ADAPTER = True\n"}
NEW = {"plugin.yaml": OLD["plugin.yaml"],
       "__init__.py": b"NEW_ADAPTER = True\n"}


class _Context:
    def __init__(self, operation, signatures):
        self.operation = operation
        self.cohort_transaction_id = None if operation == "prepare" else "cohort-fixture"
        self.old_adapter_generation = "old-generation-fixture"
        self.new_adapter_generation = "new-generation-fixture"
        self.plugin_selection_sha256 = "a" * 64
        self.old_members = MappingProxyType(dict(OLD))
        self.new_members = MappingProxyType(dict(NEW))
        self.installed_member_signatures = MappingProxyType(dict(signatures))
        self.transition_row = None if operation == "prepare" else MappingProxyType({"schema": 1})
        self.backup_reference = None if operation == "prepare" else MappingProxyType({"backup": "fixture"})
        self.phase = None if operation == "prepare" else "stopped"


def _install_fixture(monkeypatch, tmp_path: Path, members=OLD):
    tmp_path.chmod(0o755)
    for name, data in members.items():
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o444)
    dir_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)

    def open_fixture_directory():
        duplicate = os.dup(dir_fd)
        try:
            bootstrap._validate_transition_directory_names(duplicate)
            return duplicate
        except BaseException:
            os.close(duplicate)
            raise

    monkeypatch.setattr(bootstrap, "_transition_plugin_directory_fd", open_fixture_directory)
    signatures = {name: bootstrap._read_transition_member(dir_fd, name)[1]
                  for name in bootstrap.PLUGIN_FILES}
    current = {"value": _Context("prepare", signatures)}
    import hermes_installer.core_runtime as core_runtime
    monkeypatch.setattr(core_runtime, "_NativeResourcesPluginTransitionContext", _Context,
                        raising=False)
    monkeypatch.setattr(core_runtime, "_current_native_resources_plugin_transition",
                        lambda: current["value"], raising=False)
    return dir_fd, current


def _set_operation(current, operation, dir_fd):
    signatures = {name: bootstrap._read_transition_member(dir_fd, name)[1]
                  for name in bootstrap.PLUGIN_FILES}
    current["value"] = _Context(operation, signatures)


def test_prepare_install_and_mixed_pair_restore_preserve_exact_fixed_scope(monkeypatch, tmp_path):
    dir_fd, current = _install_fixture(monkeypatch, tmp_path)
    try:
        prepared = bootstrap.prepare_native_resources_plugin_transition()
        assert prepared.operation == "prepare"
        assert dict(prepared.installed_member_sha256) == {
            name: hashlib.sha256(OLD[name]).hexdigest() for name in bootstrap.PLUGIN_FILES}
        assert prepared.old_member_sha256["plugin.yaml"] == prepared.new_member_sha256["plugin.yaml"]
        assert prepared.old_member_sha256["__init__.py"] != prepared.new_member_sha256["__init__.py"]
        assert {path.name for path in tmp_path.iterdir()} == set(bootstrap.PLUGIN_FILES)

        _set_operation(current, "install", dir_fd)
        installed = bootstrap.install_native_resources_plugin_transition()
        assert installed.operation == "install"
        assert {name: (tmp_path / name).read_bytes() for name in bootstrap.PLUGIN_FILES} == NEW

        # Simulate the supported equal-manifest/different-module transition:
        # the manifest remains old-identical while the module changes.
        assert (tmp_path / "plugin.yaml").read_bytes() == OLD["plugin.yaml"]
        _set_operation(current, "restore", dir_fd)
        restored = bootstrap.restore_native_resources_plugin_transition()
        assert restored.operation == "restore"
        assert {name: (tmp_path / name).read_bytes() for name in bootstrap.PLUGIN_FILES} == OLD
        assert {path.name for path in tmp_path.iterdir()} == set(bootstrap.PLUGIN_FILES)
    finally:
        os.close(dir_fd)


def test_install_denies_pre_effect_signature_or_byte_drift(monkeypatch, tmp_path):
    dir_fd, current = _install_fixture(monkeypatch, tmp_path)
    try:
        _set_operation(current, "install", dir_fd)
        (tmp_path / "__init__.py").write_bytes(b"foreign module\n")
        (tmp_path / "__init__.py").chmod(0o444)
        with pytest.raises(bootstrap.NativePluginBootstrapUnavailable):
            bootstrap.install_native_resources_plugin_transition()
        assert (tmp_path / "plugin.yaml").read_bytes() == OLD["plugin.yaml"]
    finally:
        os.close(dir_fd)


def test_install_denies_foreign_plugin_entry_before_replacing_either_member(monkeypatch, tmp_path):
    dir_fd, current = _install_fixture(monkeypatch, tmp_path)
    try:
        _set_operation(current, "install", dir_fd)
        (tmp_path / "unrelated.py").write_bytes(b"unowned\n")
        (tmp_path / "unrelated.py").chmod(0o444)
        with pytest.raises(bootstrap.NativePluginBootstrapUnavailable):
            bootstrap.install_native_resources_plugin_transition()
        assert {name: (tmp_path / name).read_bytes() for name in bootstrap.PLUGIN_FILES} == OLD
    finally:
        os.close(dir_fd)


def test_restore_rejects_foreign_bytes_without_touching_other_member(monkeypatch, tmp_path):
    dir_fd, current = _install_fixture(monkeypatch, tmp_path, NEW)
    try:
        _set_operation(current, "restore", dir_fd)
        (tmp_path / "__init__.py").write_bytes(b"foreign module\n")
        (tmp_path / "__init__.py").chmod(0o444)
        _set_operation(current, "restore", dir_fd)
        with pytest.raises(bootstrap.NativePluginBootstrapUnavailable):
            bootstrap.restore_native_resources_plugin_transition()
        assert (tmp_path / "plugin.yaml").read_bytes() == NEW["plugin.yaml"]
    finally:
        os.close(dir_fd)


def test_install_partial_effect_can_be_restored_from_exact_mixed_pair(monkeypatch, tmp_path):
    dir_fd, current = _install_fixture(monkeypatch, tmp_path)
    original_replace = bootstrap._replace_transition_member
    calls = {"count": 0}

    def interrupt_after_first(directory_fd, name, data, expected_bytes, expected_signature):
        calls["count"] += 1
        result = original_replace(directory_fd, name, data, expected_bytes, expected_signature)
        if calls["count"] == 1:
            raise OSError("fixture interruption")
        return result

    try:
        _set_operation(current, "install", dir_fd)
        monkeypatch.setattr(bootstrap, "_replace_transition_member", interrupt_after_first)
        with pytest.raises(OSError, match="fixture interruption"):
            bootstrap.install_native_resources_plugin_transition()
        actual = {name: (tmp_path / name).read_bytes() for name in bootstrap.PLUGIN_FILES}
        assert actual["plugin.yaml"] == OLD["plugin.yaml"]
        assert actual["__init__.py"] == NEW["__init__.py"]

        monkeypatch.setattr(bootstrap, "_replace_transition_member", original_replace)
        _set_operation(current, "restore", dir_fd)
        bootstrap.restore_native_resources_plugin_transition()
        assert {name: (tmp_path / name).read_bytes() for name in bootstrap.PLUGIN_FILES} == OLD
    finally:
        os.close(dir_fd)
