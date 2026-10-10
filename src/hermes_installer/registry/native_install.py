"""Pinned Hermes native profile/skill discovery and selected content loading.

This is an evidence handoff for the lifecycle owner. It does not create profiles,
write native files, enable resources, or call a model. Call it only after the
owned generation has been materialized into the selected Hermes roots.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PINNED_HERMES_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,95}$")
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class NativeInstallError(RuntimeError):
    """Pinned Hermes cannot discover or load the selected owned native files."""


@dataclass(frozen=True, slots=True)
class NativeInstallReceipt:
    hermes_revision: str
    python_version: str
    profile_id: str
    discovered_profile: bool
    profile_identity_loaded: bool
    profile_display_name: str
    discovered_skills: tuple[str, ...]
    loaded_skills: tuple[str, ...]
    content_digests: dict[str, str]


@dataclass(frozen=True, slots=True)
class NativeBundleReceipt:
    """Bounded actual-source receipt for every profile and skill in the bundle."""

    hermes_revision: str
    python_version: str
    profiles_discovered: tuple[str, ...]
    profiles_loaded: tuple[str, ...]
    profile_aliases: dict[str, str]
    skills_discovered: tuple[str, ...]
    skills_loaded: tuple[str, ...]
    profile_digests: dict[str, str]
    skill_digests: dict[str, str]


def selected_profile_materialization(
    generation: str | Path, profile_id: str, *, native_profile_key: str | None = None,
) -> dict[str, str]:
    """Map one profile's selected generation closure to Hermes' real profile home.

    Pass the result to ``GenerationLifecycle.materialize`` after its verified
    generation inspection. This intentionally maps only native profile/skill
    files; source declarations and adapter records remain in installer data.
    The generation must have been resolved for exactly one profile and its
    dependency closure, so an all-resources generation cannot be projected by
    accident into every profile.
    """
    if (not isinstance(profile_id, str) or not _PROFILE_ID.fullmatch(profile_id)
            or (native_profile_key is not None
                and (not isinstance(native_profile_key, str)
                     or not _PROFILE_ID.fullmatch(native_profile_key)))):
        raise NativeInstallError("selected profile id is malformed")
    destination_profile_id = native_profile_key or profile_id
    root = Path(generation)
    ledger = root / "installer-registry" / "crosswalk.json"
    if ledger.is_symlink() or not ledger.is_file():
        raise NativeInstallError("verified generation has no regular native crosswalk")
    try:
        value = json.loads(ledger.read_text(encoding="utf-8"))
        policy = value["native_materialization"]
        rows = policy["files"]
        items = value["items"]
    except (OSError, ValueError, KeyError, TypeError):
        raise NativeInstallError("native generation crosswalk is invalid") from None
    if policy.get("schema") != 1 or policy.get("destination_root") != "data_root" or policy.get("preserve_existing") is not True:
        raise NativeInstallError("native generation crosswalk has an unsupported destination policy")
    profile_rows = [item for item in items if isinstance(item, dict) and item.get("kind") == "profiles"]
    if [item.get("id") for item in profile_rows] != [profile_id]:
        raise NativeInstallError("generation is not the selected profile's isolated resource closure")

    mapping: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("conflict_policy") != "preserve-existing":
            raise NativeInstallError("native materialization row has an unsupported conflict policy")
        staged, target = row.get("staged"), row.get("target")
        if not isinstance(staged, str) or not isinstance(target, str) or staged in mapping:
            raise NativeInstallError("native materialization row has invalid paths")
        if staged.startswith(f"homes/profiles/{profile_id}/"):
            expected_target = "profiles/" + staged.removeprefix("homes/profiles/")
            if target != expected_target:
                raise NativeInstallError("profile materialization target differs from native profile path")
            relative = staged.removeprefix(f"homes/profiles/{profile_id}/")
            mapping[staged] = (relative if destination_profile_id == "default"
                               else f"profiles/{destination_profile_id}/{relative}")
        elif staged.startswith("homes/skills/"):
            parts = staged.split("/")
            if len(parts) != 4 or parts[-1] != "SKILL.md":
                raise NativeInstallError("staged native skill path is malformed")
            if target != f"skills/{parts[2]}/SKILL.md":
                raise NativeInstallError("skill materialization target differs from native skill path")
            mapping[staged] = (f"skills/{parts[2]}/SKILL.md" if destination_profile_id == "default"
                               else f"profiles/{destination_profile_id}/skills/{parts[2]}/SKILL.md")
        # Other profiles/skill closures and non-native artifacts stay in the
        # installer generation and are never copied into this selected home.
    required_profile = f"homes/profiles/{profile_id}/SOUL.md"
    if required_profile not in mapping:
        raise NativeInstallError("selected profile closure lacks native identity")
    return mapping


_PROBE = r'''import hashlib, json, os, sys
from pathlib import Path

if sys.version_info[:2] != (3, 14):
    raise RuntimeError("Hermes native probe requires official Python 3.14 runtime")
root = Path(sys.argv[1]).resolve()
profile_id = sys.argv[2]
skill_ids = json.loads(sys.argv[3])
sys.path.insert(0, str(root))

from hermes_cli.profiles import list_profiles
profiles = list_profiles()
matches = [p for p in profiles if p.name == profile_id]
if len(matches) != 1:
    raise RuntimeError("selected profile was not uniquely discoverable")
visible_profiles = sorted({p.name for p in profiles})
if os.environ.get("HERMES_REQUIRE_SOLE_PROFILE") == "1" and visible_profiles != [profile_id]:
    raise RuntimeError("selected Desktop home exposes profiles other than its sole user entry")
profile_home = Path(matches[0].path).resolve()

# This is the function Hermes uses to read the profile identity for prompt slot #1.
from agent.prompt_builder import load_soul_md
soul = load_soul_md(home_override=profile_home)
if not isinstance(soul, str) or not soul.strip():
    raise RuntimeError("selected profile has no loadable SOUL.md identity")

# Exercise Hermes' own skill catalog and progressive-disclosure loader in this
# profile's HERMES_HOME. No model/session is started. Compiled installer skills
# carry no pm deps, so this path cannot request lazy package installation.
os.environ["HERMES_HOME"] = str(profile_home)
from tools import skills_tool
listed = json.loads(skills_tool.skills_list())
if listed.get("success") is not True:
    raise RuntimeError("Hermes skill discovery failed")
names = {item.get("name") for item in listed.get("skills", []) if isinstance(item, dict)}
loaded = []
digests = {"profile:" + profile_id: hashlib.sha256(soul.encode()).hexdigest()}
for name in skill_ids:
    if name not in names:
        raise RuntimeError("selected skill was not discoverable by Hermes")
    result = json.loads(skills_tool.skill_view(name, preprocess=False))
    if result.get("success") is not True or result.get("name") != name:
        raise RuntimeError("Hermes skill loader rejected selected skill")
    content = result.get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("Hermes skill loader returned empty content")
    # The native view API may ensure declared PM dependencies. Generated
    # Resources SKILL.md files must remain instruction-only here.
    if result.get("deps_note"):
        raise RuntimeError("selected skill requested a PM dependency during discovery")
    loaded.append(name)
    digests["skill:" + name] = hashlib.sha256(content.encode()).hexdigest()
print(json.dumps({"python_version": sys.version.split()[0], "profile": profile_id,
                  "skills": sorted(names), "loaded": loaded,
                  "visible_profiles": visible_profiles,
                  "profile_display_name": str(matches[0].display_name or ""),
                  "digests": digests}, sort_keys=True))
'''


_BUNDLE_PROBE = r'''import hashlib, json, os, sys
from pathlib import Path

if sys.version_info[:2] != (3, 14):
    raise RuntimeError("Hermes native probe requires official Python 3.14 runtime")
root = Path(sys.argv[1]).resolve()
profile_ids = json.loads(sys.argv[2])
skill_ids = json.loads(sys.argv[3])

from hermes_cli.profiles import list_profiles
profiles = list_profiles()
by_name = {p.name: p for p in profiles}
missing_profiles = [name for name in profile_ids if name not in by_name]
if missing_profiles:
    raise RuntimeError("one or more bundled profiles were not discovered")
from agent.prompt_builder import load_soul_md
profile_digests = {}
profile_aliases = {}
for name in profile_ids:
    home = Path(by_name[name].path).resolve()
    soul = load_soul_md(home_override=home)
    if not isinstance(soul, str) or not soul.strip():
        raise RuntimeError("one or more native profile identities failed to load")
    profile_digests[name] = hashlib.sha256(soul.encode()).hexdigest()
    profile_aliases[name] = str(by_name[name].display_name or "")

# Full-bundle skill audit is performed in the selected/default HERMES_HOME,
# whose native skills/ root represents the package's discoverable skill set.
os.environ["HERMES_HOME"] = str(root)
from tools import skills_tool
listed = json.loads(skills_tool.skills_list())
if listed.get("success") is not True:
    raise RuntimeError("Hermes skill discovery failed")
rows = listed.get("skills", [])
names = {item.get("name") for item in rows if isinstance(item, dict)}
missing_skills = [name for name in skill_ids if name not in names]
if missing_skills:
    raise RuntimeError("one or more bundled skills were not discovered")
skill_digests = {}
for name in skill_ids:
    result = json.loads(skills_tool.skill_view(name, preprocess=False))
    if result.get("success") is not True or result.get("name") != name:
        raise RuntimeError("one or more bundled skills failed to load")
    content = result.get("content")
    if not isinstance(content, str) or not content.strip() or result.get("deps_note"):
        raise RuntimeError("a bundled skill is empty or requested dependency installation")
    skill_digests[name] = hashlib.sha256(content.encode()).hexdigest()
print(json.dumps({"python_version": sys.version.split()[0],
                  "profiles": sorted(name for name in profile_ids if name in by_name),
                  "skills": sorted(name for name in skill_ids if name in names),
                  "profile_aliases": profile_aliases,
                  "profile_digests": profile_digests, "skill_digests": skill_digests},
                 sort_keys=True))
'''


def _hermes_revision(source: Path) -> str:
    if source.is_symlink() or not source.is_dir():
        raise NativeInstallError("pinned Hermes source checkout is unavailable")
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=5, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise NativeInstallError("cannot verify pinned Hermes source revision") from None
    revision = result.stdout.strip()
    if revision != PINNED_HERMES_REVISION:
        raise NativeInstallError("Hermes source checkout does not match the reviewed pin")
    return revision


_PROFILE_LIST_PROBE = r'''import json, sys
from pathlib import Path
if sys.version_info[:2] != (3, 14):
    raise RuntimeError("Hermes native probe requires official Python 3.14 runtime")
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from hermes_cli.profiles import list_profiles
print(json.dumps(sorted({row.name for row in list_profiles()}), sort_keys=True))
'''


def discover_profile_names(*, hermes_source: str | Path, python: str | Path,
                           hermes_root: str | Path, timeout: float = 20.0) -> tuple[str, ...]:
    """Return names from the pinned Hermes API for this exact selected home."""
    source_input = Path(hermes_source)
    root_input = Path(hermes_root)
    interpreter = Path(os.path.abspath(os.fspath(python)))
    if (source_input.is_symlink() or root_input.is_symlink()
            or not interpreter.is_file() or not os.access(interpreter, os.X_OK)):
        raise NativeInstallError("selected Hermes source, home, or Python runtime is unavailable")
    source = source_input.resolve(strict=True)
    root = root_input.resolve(strict=True)
    revision = _hermes_revision(source)
    if revision != PINNED_HERMES_REVISION:
        raise NativeInstallError("Hermes source checkout does not match the reviewed pin")
    env = {
        "PATH": os.environ.get("PATH", ""), "HOME": str(root),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "HERMES_HOME": str(root),
        "PYTHONPATH": str(source), "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        result = subprocess.run(
            [str(interpreter), "-c", _PROFILE_LIST_PROBE, str(source)],
            cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=True,
        )
        names = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise NativeInstallError("pinned Hermes profile listing failed") from None
    if (not isinstance(names, list) or any(not isinstance(name, str) for name in names)
            or names != sorted(set(names))):
        raise NativeInstallError("pinned Hermes returned an invalid profile listing")
    return tuple(names)


def discover_and_load_selected(
    *,
    hermes_source: str | Path,
    python: str | Path,
    hermes_root: str | Path,
    profile_id: str,
    skill_ids: Sequence[str],
    require_sole_profile: bool = False,
    timeout: float = 20.0,
) -> NativeInstallReceipt:
    """Use pinned Hermes APIs to discover a profile and load selected skills.

    ``default`` resolves to ``hermes_root``; named profiles resolve to
    ``hermes_root/profiles/<profile_id>``. The selected home contains its
    native ``skills/`` directory and identity files.
    Only roots supplied by the installer are used. The caller retains lifecycle
    ownership of writing, rollback, overlays, and activation.
    """
    if not isinstance(profile_id, str) or not _PROFILE_ID.fullmatch(profile_id):
        raise NativeInstallError("selected profile id is malformed")
    if len(skill_ids) > 64 or any(not isinstance(name, str) or not _IDENTIFIER.fullmatch(name) for name in skill_ids):
        raise NativeInstallError("selected skill ids are malformed or exceed the probe bound")
    if len(set(skill_ids)) != len(skill_ids):
        raise NativeInstallError("selected skill ids contain duplicates")
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise NativeInstallError("probe timeout is invalid") from None
    if not 0.1 <= timeout <= 60:
        raise NativeInstallError("probe timeout is outside the supported bound")

    source_input = Path(hermes_source)
    if source_input.is_symlink():
        raise NativeInstallError("pinned Hermes source checkout cannot be a symlink")
    source = source_input.resolve(strict=True)
    revision = _hermes_revision(source)
    # Keep a venv/PM executable symlink intact: resolving it bypasses the
    # interpreter's adjacent site-packages and silently selects the system
    # Python executable instead.
    interpreter = Path(os.path.abspath(os.fspath(python)))
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise NativeInstallError("selected official Hermes Python runtime is unavailable")
    root_input = Path(hermes_root)
    if root_input.is_symlink():
        raise NativeInstallError("selected Hermes root cannot be a symlink")
    root = root_input.resolve(strict=True)
    profile_home = (root if profile_id == "default"
                    else root / "profiles" / profile_id).resolve(strict=False)
    if root.is_symlink() or not profile_home.is_relative_to(root):
        raise NativeInstallError("selected Hermes roots escape the installer-owned root")
    if not profile_home.is_dir() or profile_home.is_symlink():
        raise NativeInstallError("selected Hermes profile home is not materialized")

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "HERMES_HOME": str(root),
        "HERMES_REQUIRE_SOLE_PROFILE": "1" if require_sole_profile else "0",
        "PYTHONPATH": str(source),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        result = subprocess.run(
            [str(interpreter), "-c", _PROBE, str(source), profile_id, json.dumps(list(skill_ids))],
            cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=True,
        )
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        # Do not relay Hermes exception text, which can contain local paths or
        # environment details. The per-resource blocker remains actionable.
        raise NativeInstallError("pinned Hermes profile/skill discovery or content loading failed") from None
    found_skills = set(payload.get("skills", ()))
    loaded_skills = tuple(payload.get("loaded", ()))
    if (payload.get("profile") != profile_id
            or (require_sole_profile and payload.get("visible_profiles") != [profile_id])
            or not isinstance(payload.get("profile_display_name"), str)
            or not set(skill_ids).issubset(found_skills)
            or set(loaded_skills) != set(skill_ids)):
        raise NativeInstallError("pinned Hermes returned an incomplete native discovery receipt")
    return NativeInstallReceipt(
        hermes_revision=revision,
        python_version=str(payload.get("python_version", "")),
        profile_id=profile_id,
        discovered_profile=True,
        profile_identity_loaded=True,
        profile_display_name=payload["profile_display_name"],
        discovered_skills=tuple(sorted(found_skills)),
        loaded_skills=loaded_skills,
        content_digests=dict(payload.get("digests", {})),
    )


def discover_and_load_bundle(
    *,
    hermes_source: str | Path,
    python: str | Path,
    hermes_root: str | Path,
    profile_ids: Sequence[str],
    skill_ids: Sequence[str],
    timeout: float = 60.0,
) -> NativeBundleReceipt:
    """Exercise Hermes discovery and content loading for a complete bounded bundle.

    The fixture must contain every profile under ``profiles/<id>/`` and every
    skill under the selected Hermes root's ``skills/<id>/SKILL.md``. This
    validates all native identities/cards with real pinned Hermes APIs; it does
    not claim that each profile's distinct dependency closure or required
    external effects are functional.
    """
    if len(profile_ids) != 208 or len(skill_ids) != 396:
        raise NativeInstallError("full-bundle probe requires exactly 208 profiles and 396 skills")
    if any(not isinstance(value, str) or not _PROFILE_ID.fullmatch(value) for value in profile_ids):
        raise NativeInstallError("full-bundle profile ids are malformed")
    if any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in skill_ids):
        raise NativeInstallError("full-bundle native ids are malformed")
    if len(set(profile_ids)) != 208 or len(set(skill_ids)) != 396:
        raise NativeInstallError("full-bundle native ids contain duplicates")
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise NativeInstallError("probe timeout is invalid") from None
    if not 0.1 <= timeout <= 300:
        raise NativeInstallError("full-bundle probe timeout is outside the supported bound")

    source_input = Path(hermes_source)
    if source_input.is_symlink():
        raise NativeInstallError("pinned Hermes source checkout cannot be a symlink")
    source = source_input.resolve(strict=True)
    revision = _hermes_revision(source)
    interpreter = Path(os.path.abspath(os.fspath(python)))
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise NativeInstallError("selected official Hermes Python runtime is unavailable")
    root_input = Path(hermes_root)
    if root_input.is_symlink():
        raise NativeInstallError("full-bundle Hermes root cannot be a symlink")
    root = root_input.resolve(strict=True)
    skill_root = root / "skills"
    if root.is_symlink() or skill_root.is_symlink() or not skill_root.is_dir():
        raise NativeInstallError("full-bundle Hermes skill root is not materialized")
    profile_root = root / "profiles"
    if profile_root.is_symlink() or not profile_root.is_dir():
        raise NativeInstallError("full-bundle Hermes profile root is not materialized")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "HERMES_HOME": str(root),
        "PYTHONPATH": str(source),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        result = subprocess.run(
            [str(interpreter), "-c", _BUNDLE_PROBE, str(root), json.dumps(list(profile_ids)), json.dumps(list(skill_ids))],
            cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=True,
        )
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise NativeInstallError("pinned Hermes full-bundle discovery or content loading failed") from None
    profiles = tuple(payload.get("profiles", ()))
    skills = tuple(payload.get("skills", ()))
    if set(profiles) != set(profile_ids) or set(skills) != set(skill_ids):
        raise NativeInstallError("pinned Hermes full-bundle receipt is incomplete")
    profile_digests = dict(payload.get("profile_digests", {}))
    skill_digests = dict(payload.get("skill_digests", {}))
    profile_aliases = dict(payload.get("profile_aliases", {}))
    if set(profile_digests) != set(profile_ids) or set(skill_digests) != set(skill_ids) or set(profile_aliases) != set(profile_ids):
        raise NativeInstallError("pinned Hermes full-bundle content digests are incomplete")
    return NativeBundleReceipt(
        hermes_revision=revision,
        python_version=str(payload.get("python_version", "")),
        profiles_discovered=tuple(sorted(profiles)),
        profiles_loaded=tuple(sorted(profile_ids)),
        profile_aliases=profile_aliases,
        skills_discovered=tuple(sorted(skills)),
        skills_loaded=tuple(skill_ids),
        profile_digests=profile_digests,
        skill_digests=skill_digests,
    )
