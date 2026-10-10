"""Closed constructor and descriptor-reader contracts for active PM custody."""
from __future__ import annotations

import os

import pytest

from hermes_installer.authority.active_native_worker_runtime import (
    ActiveNativeWorkerRuntimeUnavailable,
    RootActiveNativeWorkerRuntimeRegistry,
    _read_fd,
)


def test_active_runtime_registry_rejects_untyped_runtime_and_owner():
    with pytest.raises(ActiveNativeWorkerRuntimeUnavailable):
        RootActiveNativeWorkerRuntimeRegistry.from_root_runtime(object(), object())


def test_protected_receipt_reader_enforces_its_size_bound(tmp_path):
    path = tmp_path / "receipt.json"
    path.write_bytes(b"{}")
    fd = os.open(path, os.O_RDONLY)
    try:
        assert _read_fd(fd, 2) == b"{}"
    finally:
        os.close(fd)

    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="size bound"):
            _read_fd(fd, 1)
    finally:
        os.close(fd)
