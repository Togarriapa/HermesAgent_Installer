"""R0080: exercise the pinned upstream Hermes bootstrap hook, not its Markdown alone."""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
from pathlib import Path
import subprocess

import pytest

from hermes_installer.components.superpowers import (
    HERMES_HOST_REVISION,
    INSTALL_TIMEOUT_SECONDS,
    SUPERPOWERS_REVISION,
    install_command,
    install_superpowers,
)


FIXTURE_SOURCE = Path(__file__).parents[1] / "fixtures" / "superpowers-hermes-pinned"
UPSTREAM_PLUGIN_SHA256 = "7fd93899e39371d56ba1e32660548673afa78f3a4a8bd306f93fbb418afa6f3c"


class PinnedHermesContextFixture:
    """The pinned host's register_skill/register_hook boundary for an isolated temp plugin."""

    def __init__(self) -> None:
        self.skills: dict[str, Path] = {}
        self.hooks = {}

    def register_skill(self, name: str, path: Path) -> None:
        assert isinstance(path, Path)
        self.skills[name] = path

    def register_hook(self, event: str, callback):
        assert event == "pre_llm_call"
        self.hooks[event] = callback
        return callback


def _load_plugin(plugin_root: Path):
    module_path = plugin_root / ".hermes-plugin" / "__init__.py"
    spec = importlib.util.spec_from_file_location("pinned_superpowers_hermes_plugin", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_hermes_command_uses_documented_install_and_exact_pins():
    assert install_command("/managed/hermes/bin/hermes", host_revision=HERMES_HOST_REVISION) == (
        "/managed/hermes/bin/hermes", "plugins", "install", "obra/superpowers", "--enable",
        "--ref", SUPERPOWERS_REVISION,
    )
    with pytest.raises(ValueError, match="reviewed Hermes plugin host revision"):
        install_command("hermes", host_revision="0" * 40)


def test_installer_reports_native_activation_pending_until_hook_is_verified():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    result = install_superpowers("hermes", host_revision=HERMES_HOST_REVISION, runner=runner)
    assert result.state == "installed_pending_native_hook_verification"
    assert result.returncode == 0
    assert calls == [(
        ("hermes", "plugins", "install", "obra/superpowers", "--enable", "--ref", SUPERPOWERS_REVISION),
        {"timeout": INSTALL_TIMEOUT_SECONDS, "capture_output": True, "text": True, "check": False},
    )]


def test_pinned_upstream_bootstrap_registers_skills_and_injects_first_turn(tmp_path):
    source_plugin = FIXTURE_SOURCE / ".hermes-plugin" / "__init__.py"
    assert hashlib.sha256(source_plugin.read_bytes()).hexdigest() == UPSTREAM_PLUGIN_SHA256
    plugin_root = tmp_path / "plugins" / "superpowers"
    shutil.copytree(FIXTURE_SOURCE, plugin_root)

    context = PinnedHermesContextFixture()
    _load_plugin(plugin_root).register(context)

    skill_path = plugin_root / "skills" / "using-superpowers" / "SKILL.md"
    assert context.skills == {"using-superpowers": skill_path}
    assert skill_path.is_file()
    hook = context.hooks["pre_llm_call"]
    first_turn = hook(is_first_turn=True, user_message="fixture request")
    assert isinstance(first_turn, dict)
    assert "superpowers:using-superpowers bootstrap for hermes" in first_turn["context"]
    assert "Do not try to load using-superpowers again" in first_turn["context"]
    assert "Hermes Agent Tool Mapping" in first_turn["context"]
    assert hook(is_first_turn=False, user_message="later turn") is None


def test_pinned_upstream_hook_fails_loudly_when_installed_skill_tree_is_missing(tmp_path):
    plugin_root = tmp_path / "plugins" / "superpowers"
    (plugin_root / ".hermes-plugin").mkdir(parents=True)
    shutil.copy2(FIXTURE_SOURCE / ".hermes-plugin" / "__init__.py", plugin_root / ".hermes-plugin" / "__init__.py")
    context = PinnedHermesContextFixture()
    with pytest.raises(RuntimeError, match="cannot find the skills/ tree"):
        _load_plugin(plugin_root).register(context)
    assert not context.hooks
    assert not context.skills
