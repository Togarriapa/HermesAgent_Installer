"""Pinned native Hermes plugin integration for obra/superpowers (R0080)."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


SUPERPOWERS_SOURCE = "obra/superpowers"
SUPERPOWERS_REVISION = "8ca22dba9a94f28898bbce59f2537ff4d87c747d"
HERMES_HOST_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
INSTALL_TIMEOUT_SECONDS = 900


class CommandRunner(Protocol):
    def __call__(self, argv: Sequence[str], *, timeout: int, capture_output: bool,
                 text: bool, check: bool) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True, slots=True)
class SuperpowersInstallResult:
    state: str
    returncode: int | None
    detail: str


def install_command(hermes_executable: str | Path, *, host_revision: str) -> tuple[str, ...]:
    """Build the upstream documented Hermes install command, pinned at both ends."""
    if host_revision != HERMES_HOST_REVISION:
        raise ValueError("Superpowers installation requires the reviewed Hermes plugin host revision")
    executable = str(hermes_executable)
    if not executable or "\x00" in executable:
        raise ValueError("Hermes executable path is invalid")
    return (
        executable, "plugins", "install", SUPERPOWERS_SOURCE, "--enable",
        "--ref", SUPERPOWERS_REVISION,
    )


def install_superpowers(
    hermes_executable: str | Path,
    *,
    host_revision: str,
    runner: CommandRunner = subprocess.run,
) -> SuperpowersInstallResult:
    """Request native installation through Hermes and keep hook acceptance separate."""
    argv = install_command(hermes_executable, host_revision=host_revision)
    try:
        result = runner(
            argv, timeout=INSTALL_TIMEOUT_SECONDS, capture_output=True, text=True, check=False,
        )
    except subprocess.TimeoutExpired:
        return SuperpowersInstallResult(
            "failed", None, "Hermes plugin installation exceeded its bounded timeout",
        )
    except OSError as exc:
        return SuperpowersInstallResult("failed", None, f"Hermes plugin installer could not start: {exc}")
    if result.returncode != 0:
        return SuperpowersInstallResult(
            "failed", result.returncode, "Hermes rejected or failed the pinned plugin installation",
        )
    return SuperpowersInstallResult(
        "installed_pending_native_hook_verification", result.returncode,
        "Hermes accepted the pinned plugin install; native hook verification is still pending",
    )
