"""Source review for the optional Ruflo runtime.

Ruflo is an independent orchestrator with a large optional native dependency
tree. This module inspects the selected source and leaves start/MCP activation
closed until an isolated Linux ARM64 qualification exists.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter


_PACKAGE = "package.json"
_MCP_SERVER = "v3/@claude-flow/cli/bin/mcp-server.js"
_MCP_PACKAGE = "v3/@claude-flow/mcp/package.json"
_PIN = "58e0ae7e14e68aab45a4127d6f42f567bbcfb328"


class RufloAdapterError(ValueError):
    """The selected Ruflo source cannot be reviewed safely."""


@dataclass(frozen=True, slots=True)
class RufloSourceReview:
    source_revision: str
    package_version: str
    node_requirement: str
    mcp_server_source_present: bool
    optional_native_dependencies: tuple[str, ...]
    coordinator_replaced: bool
    may_start: bool
    blockers: tuple[str, ...]


def review_ruflo_source(files: Mapping[str, bytes], *, target: str = "linux/aarch64") -> RufloSourceReview:
    """Inspect the exact selected package without starting its CLI or MCP server."""
    contract = resolve_component_adapter("ruflo")
    if contract.revision != _PIN:
        raise RufloAdapterError("Ruflo adapter pin differs from the selected source contract")
    package_bytes, mcp_server, mcp_package_bytes = (
        files.get(_PACKAGE), files.get(_MCP_SERVER), files.get(_MCP_PACKAGE)
    )
    if not isinstance(package_bytes, bytes) or not isinstance(mcp_server, bytes) or not isinstance(mcp_package_bytes, bytes):
        raise RufloAdapterError("pinned Ruflo package and MCP server source files are required")
    try:
        package = json.loads(package_bytes)
        mcp_package = json.loads(mcp_package_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RufloAdapterError("Ruflo package metadata is malformed") from None
    if not isinstance(package, dict) or not isinstance(mcp_package, dict):
        raise RufloAdapterError("Ruflo package metadata is malformed")
    if (package.get("name"), package.get("version"), package.get("license")) != ("claude-flow", "3.56.1", "MIT"):
        raise RufloAdapterError("Ruflo package metadata does not match the reviewed source pin")
    description = mcp_package.get("description", "")
    if mcp_package.get("name") != "@claude-flow/mcp" or not isinstance(description, str) or not description.startswith("Standalone MCP"):
        raise RufloAdapterError("Ruflo MCP package does not match the selected source contract")
    optional = package.get("optionalDependencies", {})
    dependencies = package.get("dependencies", {})
    if not isinstance(optional, dict) or not isinstance(dependencies, dict):
        raise RufloAdapterError("Ruflo dependency declarations are malformed")
    native = tuple(sorted(name for name in optional if any(term in name.casefold() for term in (
        "better-sqlite", "ruvector", "napi", "native", "agentdb",
    ))))
    blockers = [
        "Linux ARM64 native dependency installation and harmless runtime probe are not qualified",
        "MCP tool scope has not been enrolled per tool; server activation remains disabled",
    ]
    if target != "linux/aarch64":
        blockers.insert(0, f"requested target {target!r} is outside the reviewed Linux ARM64 target")
    if not native:
        blockers.append("expected Ruflo optional native dependency declarations are absent")
    return RufloSourceReview(
        source_revision=_PIN,
        package_version=package["version"],
        node_requirement=str(package.get("engines", {}).get("node", "")) if isinstance(package.get("engines", {}), dict) else "",
        mcp_server_source_present=True,
        optional_native_dependencies=native,
        coordinator_replaced=False,
        may_start=False,
        blockers=tuple(blockers),
    )
