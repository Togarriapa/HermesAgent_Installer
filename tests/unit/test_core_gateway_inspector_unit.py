"""Static and isolated-effect checks for the fixed root Inspector service."""
import os
import shlex
import stat
import subprocess
from pathlib import Path

import pytest


UNIT = (Path(__file__).resolve().parents[2] / "templates" / "core-gateway"
        / "hermes-jarvis-core-inspector.service")


def test_inspector_unit_keeps_primary_group_and_limits_native_write_access():
    lines = UNIT.read_text(encoding="ascii").splitlines()
    service = lines[lines.index("[Service]") + 1:]

    assert service.count("Group=981") == 1
    assert service.count("RuntimeDirectory=hermes-jarvis-mvp-core") == 1
    assert not any(line.startswith("RuntimeDirectory=")
                   and ":root:admin" in line for line in service)
    assert service.count(
        "ExecStartPre=/usr/bin/install -d -o root -g 1000 -m 0750 "
        "/run/hermes-jarvis-native-observer") == 1
    assert service.count("SupplementaryGroups=1000") == 1
    assert service.count("ReadWritePaths=/var/lib/hermes-installer/core-runtime") == 1
    assert "ProtectSystem=strict" in service


@pytest.mark.skipif(os.geteuid() != 0, reason="root ownership effect requires the Pi root test role")
def test_inspector_prestart_recipe_creates_exact_private_runtime_directory(tmp_path):
    lines = UNIT.read_text(encoding="ascii").splitlines()
    recipe = next(line.split("=", 1)[1] for line in lines
                  if line.startswith("ExecStartPre="))
    arguments = shlex.split(recipe)
    target = tmp_path / "native-observer"
    arguments[-1] = str(target)
    subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    info = target.stat()
    assert stat.S_ISDIR(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 1000, 0o750)
