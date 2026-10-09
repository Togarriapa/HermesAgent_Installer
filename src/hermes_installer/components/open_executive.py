"""Fail-closed source review for the separate Open Executive application.

The pinned application runs its own agent/tool workflows and has independent
provider configuration. This adapter describes the documented local API but
does not launch the service or allow its direct provider settings to bypass
Hermes provider policy.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter


_PYPROJECT = "packages/core/pyproject.toml"
_CHAT_ROUTE = "packages/core/openexecutive/api/routes/chat.py"
_CHAT_MODEL = "packages/core/openexecutive/api/models.py"
_SETTINGS = "packages/core/openexecutive/config.py"
_PIN = "303d45eaa0b2323f2e9646d19bf35dbcc98c6d71"


class OpenExecutiveAdapterError(ValueError):
    """Pinned Open Executive source or its provider contract is unsupported."""


@dataclass(frozen=True, slots=True)
class OpenExecutiveSourceReview:
    source_revision: str
    package_version: str
    python_requirement: str
    license: str
    chat_path: str
    chat_streams: bool
    chat_request_limit: int
    separate_provider_configuration: bool
    workflow_available: bool
    blockers: tuple[str, ...]


def review_open_executive_source(
    files: Mapping[str, bytes], *, target: str = "linux/aarch64"
) -> OpenExecutiveSourceReview:
    """Review the pinned API contract without starting Open Executive."""
    contract = resolve_component_adapter("open-executive")
    if contract.revision != _PIN:
        raise OpenExecutiveAdapterError("Open Executive adapter pin differs from the selected source contract")
    required = (_PYPROJECT, _CHAT_ROUTE, _CHAT_MODEL, _SETTINGS)
    if any(not isinstance(files.get(path), bytes) or not files[path] for path in required):
        raise OpenExecutiveAdapterError("pinned Open Executive manifest, chat API, and provider settings are required")
    try:
        project = tomllib.loads(files[_PYPROJECT].decode("utf-8"))["project"]
        route = files[_CHAT_ROUTE].decode("utf-8")
        model = files[_CHAT_MODEL].decode("utf-8")
        settings = files[_SETTINGS].decode("utf-8")
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise OpenExecutiveAdapterError("Open Executive source contract is malformed") from None
    if not isinstance(project, dict) or not isinstance(project.get("license"), dict):
        raise OpenExecutiveAdapterError("Open Executive project metadata is malformed")
    if (project.get("name"), project.get("version"), project["license"].get("text")) != (
        "openexecutive", "0.5.2", "Apache-2.0"
    ):
        raise OpenExecutiveAdapterError("Open Executive package metadata does not match the reviewed source pin")
    if not re.search(r"class ChatRequest\(BaseModel\):[\s\S]{0,1400}message: str = Field\(\.\.\., min_length=1, max_length=32000\)", model):
        raise OpenExecutiveAdapterError("pinned Open Executive chat request contract is unrecognized")
    if not re.search(r'@router\.post\("/chat"\)[\s\S]{0,350}StreamingResponse', route):
        raise OpenExecutiveAdapterError("pinned Open Executive does not expose the reviewed streaming chat API")
    if not all(alias in settings for alias in ("ANTHROPIC_API_KEY", "OPENROUTER_ENABLED", "LOCAL_BASE_URL")):
        raise OpenExecutiveAdapterError("Open Executive provider assumptions differ from the reviewed source")
    blockers = [
        "Open Executive selects providers inside its own application; no Hermes policy-gateway binding is installed",
        "Open Executive chat can run specialist tools; no bounded per-tool enrollment is installed",
        "Open Executive Python and native inference dependency support has not been qualified on Linux ARM64",
    ]
    if target != "linux/aarch64":
        blockers.insert(0, f"requested target {target!r} is outside the reviewed Linux ARM64 target")
    return OpenExecutiveSourceReview(
        source_revision=_PIN,
        package_version=project["version"],
        python_requirement=project.get("requires-python", ""),
        license="Apache-2.0",
        chat_path="/chat",
        chat_streams=True,
        chat_request_limit=32000,
        separate_provider_configuration=True,
        workflow_available=False,
        blockers=tuple(blockers),
    )


def require_open_executive_workflow(review: OpenExecutiveSourceReview) -> None:
    """Prevent the separate app's provider/tool workflow from bypassing policy."""
    if review.source_revision != _PIN or not review.workflow_available:
        reason = review.blockers[0] if review.blockers else "no enrolled Open Executive workflow capability is available"
        raise PermissionError(reason)
