#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

import yaml

from registry_lib import RESOURCE_DIRS, ROOT, SEMVER_RE, version_tuple

FORBIDDEN_ROOT_DOCS = [
    re.compile(r".*_V\d+\.md$", re.I),
    re.compile(r"CAPABILITY_EXPANSION_.*\.md$", re.I),
    re.compile(r"CATALOG_DISCOVERY_.*\.md$", re.I),
    re.compile(r"QUALITY_POLICY_EXPANSION_.*\.ya?ml$", re.I),
]
CANONICAL_DOCS = {
    "README.md", "SPEC.md", "TOPOLOGY.md", "ORCHESTRATION.md", "DELIBERATION.md",
    "PROFILE_MATRIX.md", "INTEGRATION_MATRIX.md", "CAPABILITY_COVERAGE.md",
    "RESOURCE_QUALITY.md", "RESOURCE_EVOLUTION.md", "RUNTIME_IMPORT.md",
    "EXTERNAL_INTEGRATIONS.md", "SECURITY.md", "FINANCIAL_ACCESS.md",
    "INVESTMENT_GOVERNANCE.md", "CONTRIBUTING.md",
}
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def load_yaml_text(text: str) -> dict:
    data = yaml.safe_load(text) or {}
    return data if isinstance(data, dict) else {}


def manifest_version_from_text(text: str) -> str | None:
    metadata = load_yaml_text(text).get("metadata") or {}
    value = metadata.get("version")
    return value if isinstance(value, str) else None


def base_text(base: str, path: str) -> str | None:
    try:
        return run("git", "show", f"{base}:{path}")
    except subprocess.CalledProcessError:
        return None


def check_markdown_links(errors: list[str]) -> None:
    for path in sorted(ROOT.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for raw in LINK_RE.findall(text):
            target = raw.split("#", 1)[0].strip()
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = unquote(target)
            if not (path.parent / target).exists():
                errors.append(f"{path.name}: broken local link -> {raw}")


def main() -> int:
    errors: list[str] = []

    for required in sorted(CANONICAL_DOCS):
        if not (ROOT / required).is_file():
            errors.append(f"missing canonical document: {required}")

    for path in ROOT.iterdir():
        if path.is_file() and any(regex.fullmatch(path.name) for regex in FORBIDDEN_ROOT_DOCS):
            errors.append(f"versioned/supplemental root document is forbidden; update a canonical document instead: {path.name}")

    check_markdown_links(errors)

    base_ref = os.getenv("GITHUB_BASE_REF")
    if base_ref:
        base = f"origin/{base_ref}"
        try:
            run("git", "rev-parse", "--verify", base)
        except subprocess.CalledProcessError:
            errors.append(f"cannot resolve PR base {base}; checkout must use fetch-depth: 0")
            base = ""

        if base:
            changed = run("git", "diff", "--name-status", f"{base}...HEAD").splitlines()
            resource_prefixes = tuple(f"{directory}/" for directory in RESOURCE_DIRS.values())
            resource_set_changed = False
            for line in changed:
                if not line:
                    continue
                parts = line.split("\t")
                status, path = parts[0], parts[-1]
                if not path.startswith(resource_prefixes) or not path.endswith(".yaml"):
                    continue
                resource_set_changed = True
                if status.startswith("D") or status.startswith("A"):
                    continue
                before = base_text(base, path)
                current_path = ROOT / path
                if before is None or not current_path.is_file():
                    continue
                old = manifest_version_from_text(before)
                new = manifest_version_from_text(current_path.read_text(encoding="utf-8"))
                if not old or not new or not SEMVER_RE.fullmatch(old) or not SEMVER_RE.fullmatch(new):
                    errors.append(f"{path}: cannot compare valid semantic versions for changed existing resource")
                elif version_tuple(new) <= version_tuple(old):
                    errors.append(f"{path}: changed existing resource must bump metadata.version ({old} -> {new})")

            if resource_set_changed:
                old_catalog = base_text(base, "catalog.yaml")
                current_catalog = ROOT / "catalog.yaml"
                if old_catalog is not None and current_catalog.is_file():
                    old = manifest_version_from_text(old_catalog)
                    new = manifest_version_from_text(current_catalog.read_text(encoding="utf-8"))
                    if not old or not new or not SEMVER_RE.fullmatch(old) or not SEMVER_RE.fullmatch(new):
                        errors.append("catalog.yaml: resource changes require comparable semantic catalog versions")
                    elif version_tuple(new) <= version_tuple(old):
                        errors.append(f"catalog.yaml: resource changes require catalog version bump ({old} -> {new})")

    if errors:
        print("PR quality checks failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("PR quality checks OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
