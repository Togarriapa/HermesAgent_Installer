from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from hermes_installer.managed_process import (
    ManagedProcessError,
    ManagedProcessSpec,
    _validate_spec,
)


def _spec(root: Path, *, digest: str | None = None, deadline: float | None = None,
          max_lifetime: float = 30.0) -> ManagedProcessSpec:
    exe = root / "bin" / "probe"
    cwd = root / "work"
    data = root / "data"
    exe.parent.mkdir(parents=True, exist_ok=True)
    cwd.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"reviewed executable fixture")
    exe.chmod(0o700)
    return ManagedProcessSpec(
        executable=exe,
        argv=(str(exe), "--read-only"),
        artifact_sha256=digest or hashlib.sha256(exe.read_bytes()).hexdigest(),
        owned_root=root,
        cwd=cwd,
        data_root=data,
        env_allowlist={"HOME": str(data), "PATH": "/usr/bin:/bin"},
        journal_operation="probe:test",
        service_identity="installer-test",
        startup_deadline_monotonic=deadline or time.monotonic() + 5,
        max_lifetime_seconds=max_lifetime,
    )


def test_managed_process_requires_owned_pinned_executable_and_roots(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    root, executable, cwd = _validate_spec(spec)
    assert root == tmp_path.resolve()
    assert executable == spec.executable.resolve()
    assert cwd == spec.cwd.resolve()


def test_managed_process_rejects_changed_executable_pin(tmp_path: Path) -> None:
    spec = _spec(tmp_path, digest="0" * 64)
    with pytest.raises(ManagedProcessError, match="artifact pin"):
        _validate_spec(spec)


def test_managed_process_rejects_unowned_data_and_argv_substitution(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    object.__setattr__(spec, "data_root", outside)
    with pytest.raises(ManagedProcessError, match="inside the owned root"):
        _validate_spec(spec)

    valid = _spec(tmp_path / "second")
    object.__setattr__(valid, "argv", ("/bin/sh", "-c", "true"))
    with pytest.raises(ManagedProcessError, match="argv must start"):
        _validate_spec(valid)


@pytest.mark.parametrize("lifetime", [0, -1, float("inf"), 86401])
def test_managed_process_requires_finite_bounded_lifetime(tmp_path: Path, lifetime: float) -> None:
    spec = _spec(tmp_path, max_lifetime=lifetime)
    with pytest.raises(ManagedProcessError, match="finite process lifetime"):
        _validate_spec(spec)


def test_managed_process_rejects_secret_environment_keys(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    object.__setattr__(spec, "env_allowlist", {"API_KEY": "never-accepted"})
    with pytest.raises(ManagedProcessError, match="environment key"):
        _validate_spec(spec)
