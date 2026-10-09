"""Structural checks for source-pinned isolated runtime locks."""
from __future__ import annotations

import json
import tomllib


def lockfile_errors(path: str, body: bytes) -> tuple[str, ...]:
    """Report missing dependency resolution structure without installing anything."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return ("lockfile is not UTF-8",)
    if path in {"uv.lock", "backend/poetry.lock"}:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return ("lockfile TOML is invalid",)
        packages = data.get("package")
        if not isinstance(packages, list) or not packages:
            return ("TOML lockfile has no resolved package records",)
        if any(not isinstance(row, dict) or not row.get("name") or not row.get("version") for row in packages):
            return ("TOML lockfile has an incomplete package record",)
        if path == "uv.lock" and data.get("version") != 1:
            return ("uv.lock has an unsupported lock version",)
        if path.endswith("poetry.lock") and not data.get("metadata", {}).get("lock-version"):
            return ("poetry.lock lacks lock metadata",)
    elif path.endswith("package-lock.json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ("package-lock.json is invalid JSON",)
        version = data.get("lockfileVersion")
        if not isinstance(version, int) or version < 1:
            return ("package-lock.json lacks a supported lockfileVersion",)
        if version >= 2:
            packages = data.get("packages")
            if not isinstance(packages, dict) or "" not in packages or len(packages) < 2:
                return ("package-lock.json lacks root and resolved package entries",)
        elif not isinstance(data.get("dependencies"), dict) or not data["dependencies"]:
            return ("legacy package-lock.json has no resolved dependencies",)
    elif path == "bun.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ("bun.lock is invalid JSON",)
        workspaces, packages = data.get("workspaces"), data.get("packages")
        if data.get("lockfileVersion") not in {1, 2}:
            return ("bun.lock has an unsupported lock version",)
        if not isinstance(workspaces, dict) or "" not in workspaces or "packages/cli" not in workspaces:
            return ("bun.lock does not bind root and CLI workspaces",)
        if not isinstance(packages, (dict, list)) or not packages:
            return ("bun.lock has no resolved external packages",)
    elif path.endswith("pnpm-lock.yaml"):
        if not all(marker in text for marker in ("lockfileVersion:", "importers:", "packages:")):
            return ("pnpm lock lacks version, importer, or package sections",)
        importer_section = text.split("importers:", 1)[-1].split("\\npackages:", 1)[0]
        if not any(line.startswith("  .:") or line.startswith('  ".":') for line in importer_section.splitlines()):
            return ("pnpm lock has no root importer",)
    return ()
