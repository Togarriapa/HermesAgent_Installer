from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hermes_installer.components.colibri import (
    COLIBRI_REVISION, ColibriError, ColibriService, ColibriServicePlan, ServiceBounds,
    build_colibri_arm64, probe_host_readiness,
)


class Handle:
    def __init__(self, bounded=True, healthy=True):
        self.healthy = healthy
        self.stopped = []
        self._cgroup_limits = None
        self.bounded = bounded
        self.network_policy = "authenticated-loopback-bridge"
    @property
    def cgroup_limits(self):
        if self._cgroup_limits:
            return self._cgroup_limits
        return type("Snapshot", (), {
            "unit": "hermes-colibri.service", "cgroup_path": "/sys/fs/cgroup/system.slice/hermes-colibri.service",
            "memory_max": str(12 * 1024**3 if self.bounded else 10), "cpu_max": "75000 100000",
            "io_weight": "default 100", "kill_mode": "control-group", "network_policy": self.network_policy,
            "namespace_id": "net:[4026533000]", "lifetime_limit_seconds": 600,
        })()
    def wait_healthy(self, timeout):
        assert timeout <= 30
        return self.healthy
    def stop(self, reason):
        self.stopped.append(reason)
        from hermes_installer.components.colibri import CgroupStopEvidence
        snapshot = self.cgroup_limits
        return CgroupStopEvidence(snapshot.unit, snapshot.cgroup_path, ())


class Launcher:
    def __init__(self, handle): self.handle = handle
    def start_colibri(self, plan):
        self.plan = plan
        return self.handle


def test_colibri_build_rejects_non_arm64_before_touching_source(tmp_path: Path) -> None:
    with pytest.raises(ColibriError, match="Linux ARM64"):
        build_colibri_arm64(tmp_path / "missing", system="Darwin", machine="arm64", runner=subprocess.run)


def test_colibri_build_requires_exact_source_revision(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "c").mkdir()
    (source / "c" / "setup.sh").write_text("exit 0\n")
    calls = []
    def fake_runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "wrong revision\n")
    with pytest.raises(ColibriError, match="reviewed revision pin"):
        build_colibri_arm64(source, system="Linux", machine="aarch64", runner=fake_runner)
    assert calls == [("git", "rev-parse", "HEAD")]
    assert len(COLIBRI_REVISION) == 40


def test_readiness_uses_measured_memory_thermal_and_throttling_facts(tmp_path: Path, monkeypatch) -> None:
    proc, sysroot = tmp_path / "proc", tmp_path / "sys"
    proc.mkdir()
    (proc / "meminfo").write_text("MemTotal: 16384000 kB\nMemAvailable: 8192000 kB\n")
    (proc / "cpuinfo").write_text("Features : fp asimd crc32\n")
    zone = sysroot / "class/thermal/thermal_zone0"
    zone.mkdir(parents=True)
    (zone / "temp").write_text("44\n")
    (sysroot / "bus/usb/devices").mkdir(parents=True)
    model_path = tmp_path / "models"
    model_path.mkdir()
    monkeypatch.setattr("hermes_installer.components.colibri.shutil.which", lambda name: "/usr/bin/vcgencmd" if name == "vcgencmd" else None)
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, "throttled=0x0\n")
    ready = probe_host_readiness(model_path, proc_root=proc, sys_root=sysroot,
        system="Linux", machine="aarch64", runner=runner)
    assert ready.memory_total_bytes == 16_384_000 * 1024
    assert ready.memory_available_bytes == 8_192_000 * 1024
    assert ready.temperature_millidegrees == 44_000
    assert ready.throttling == "throttled=0x0"
    assert ready.cpu_features == ("asimd", "crc32", "fp")
    assert ready.device_access == "no_coral_device"


def test_service_plan_is_loopback_only_and_key_never_enters_argv(tmp_path: Path) -> None:
    executable, models = tmp_path / "colibri", tmp_path / "generation"
    executable.write_text("binary")
    (tmp_path / "coli").write_text("#!/usr/bin/env python3\n")
    models.mkdir()
    bounds = ServiceBounds(12 * 1024**3, 75, 80)
    plan = ColibriServicePlan.create(executable, tmp_path, models, "vault://colibri/key", bounds)
    assert plan.bind_host == "127.0.0.1"
    assert plan.model_revision == "6bbb01ed3e515a8730b694dfae73aadfd6774581"
    assert "vault://colibri/key" not in plan.argv
    assert "127.0.0.1" in plan.argv and "8000" in plan.argv
    assert "COLI_MODEL" in dict(plan.environment)
    with pytest.raises(ValueError, match="fixed to loopback port 8000"):
        ColibriServicePlan.create(executable, tmp_path, models, "vault://colibri/key", bounds, port=8421)
    with pytest.raises(ValueError, match="positive"):
        ServiceBounds(0, 20, 1024)
    with pytest.raises(ValueError, match="exactly one"):
        ServiceBounds(1, 20, 1024, max_concurrent_requests=2)


def test_service_stays_unavailable_without_measured_bounds_and_loopback_bridge(tmp_path: Path) -> None:
    executable, models = tmp_path / "colibri", tmp_path / "generation"
    executable.write_text("binary")
    (tmp_path / "coli").write_text("#!/usr/bin/env python3\n")
    models.mkdir()
    plan = ColibriServicePlan.create(executable, tmp_path, models, "vault://colibri/key",
        ServiceBounds(12 * 1024**3, 75, 80))
    handle = Handle(bounded=False)
    service = ColibriService(plan, Launcher(handle))
    with pytest.raises(ColibriError, match="manager-measured cgroup"):
        service.start()
    assert handle.stopped
    assert not service._handle


def test_service_accepts_only_matching_cgroup_readbacks_and_stops_managed_generation(tmp_path: Path) -> None:
    executable, models = tmp_path / "colibri", tmp_path / "generation"
    executable.write_text("binary")
    (tmp_path / "coli").write_text("#!/usr/bin/env python3\n")
    models.mkdir()
    plan = ColibriServicePlan.create(executable, tmp_path, models, "vault://colibri/key",
        ServiceBounds(12 * 1024**3, 75, 100))
    handle = Handle()
    service = ColibriService(plan, Launcher(handle))
    service.start()
    assert service._handle is handle
    service.cancel_inference()
    assert handle.stopped == ["inference cancelled"]
    assert service._handle is None
