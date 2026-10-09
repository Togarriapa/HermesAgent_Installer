"""Pinned, capability-gated adapter for the screenshot-to-code application.

The upstream application remains an independent web application. This module
checks its pinned backend runtime and only accepts model routes whose reviewed
capability includes image input. The local functional fixture drives the
upstream ``/generate-code`` WebSocket route; live account/target evidence stays
separate.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.application_handlers import (
    RuntimeProfileError,
    RuntimeReview,
    review_isolated_runtime,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.components.runtime_source import (
    VerifiedComponentGeneration,
    bind_component_runtime_source,
)


SOURCE_IDENTITY = "abi/screenshot-to-code"
SOURCE_REVISION = "d026163f586dfa8c5c10d28c36edd59a9d3b0e88"
SOURCE_FILE_SHA256: Mapping[str, str] = MappingProxyType({
    "backend/pyproject.toml": "d7bee433721d949bc95e7376961e50dd888cd39c1a5c26efa7222de04c884440",
    "backend/poetry.lock": "b4f49ac319c479a7e152984b1a8f1fb323a6e5a8f18a71ca949ffa6a3c438d29",
    "backend/routes/generate_code.py": "0ec0b95e15b757317dc2bb87eba2dcc302873e0b6d457831cc64dae4d927fe84",
})

# Keep this catalog narrow: the pinned upstream's OpenAI-only model set
# resolves both variants to gpt-5.5, which accepts image input. Other
# providers/models remain unavailable until separately reviewed.
_ROUTE_CATALOG: Mapping[str, tuple[str, str]] = MappingProxyType({
    "openai-gpt-5.5": ("openai", "gpt-5.5"),
})
_INSTALLER_CREDENTIAL_REFERENCE = "host:installer/screenshot-to-code/openai"


class ScreenshotToCodeError(RuntimeProfileError):
    """The pinned application or requested model route is not eligible."""


@dataclass(frozen=True, slots=True)
class HostCredentialReference:
    """Protected credential handle; never a credential value."""

    reference: str

    def __post_init__(self) -> None:
        if self.reference != _INSTALLER_CREDENTIAL_REFERENCE:
            raise ScreenshotToCodeError("vision route must use its installer-owned credential reference")


@dataclass(frozen=True, slots=True)
class VisionRoute:
    """A fixed catalog route and typed handle, with no caller endpoint/model fields."""

    route_id: str
    credential: HostCredentialReference

    @property
    def provider(self) -> str:
        return _ROUTE_CATALOG[self.route_id][0]

    @property
    def model(self) -> str:
        return _ROUTE_CATALOG[self.route_id][1]


def resolve_vision_route(route_id: str) -> VisionRoute:
    """Resolve the installer-owned route and credential without caller values."""
    provider_model = _ROUTE_CATALOG.get(route_id)
    if provider_model is None:
        raise ScreenshotToCodeError("selected provider model is not reviewed for image input")
    route = VisionRoute(route_id, HostCredentialReference(_INSTALLER_CREDENTIAL_REFERENCE))
    return validate_vision_route(route)


def validate_vision_route(route: VisionRoute) -> VisionRoute:
    """Reject altered, unsupported, or text-only routes before image bytes are read."""
    if not isinstance(route, VisionRoute):
        raise TypeError("vision route must come from the typed provider catalog")
    if route.route_id not in _ROUTE_CATALOG:
        raise ScreenshotToCodeError("selected provider model is not reviewed for image input")
    if not isinstance(route.credential, HostCredentialReference):
        raise TypeError("vision route requires an installer-owned host credential handle")
    if route.credential.reference != _INSTALLER_CREDENTIAL_REFERENCE:
        raise ScreenshotToCodeError("vision route must use its installer-owned credential reference")
    contract = resolve_component_adapter("screenshot-to-code")
    if (contract.source_identity != SOURCE_IDENTITY or contract.revision != SOURCE_REVISION):
        raise ScreenshotToCodeError("screenshot-to-code source contract differs from the reviewed pin")
    return route


def review_screenshot_to_code_source(
    source: VerifiedComponentSource, store: object,
) -> tuple[RuntimeReview, VerifiedComponentGeneration]:
    """Bind the full pinned source tree before reviewing its isolated runtime files."""
    try:
        generation = bind_component_runtime_source(
            source, store, component_id="screenshot-to-code",
        )
    except Exception as exc:
        raise ScreenshotToCodeError("screenshot-to-code source is not a verified owned generation") from exc
    required = (*SOURCE_FILE_SHA256, "frontend/package.json", "frontend/pnpm-lock.yaml")
    staged_files: dict[str, bytes] = {}
    for relative in required:
        path = generation.root / relative
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError("not a regular file")
            staged_files[relative] = path.read_bytes()
        except OSError:
            raise ScreenshotToCodeError(f"verified screenshot-to-code runtime file is missing: {relative}") from None
    review = review_screenshot_to_code_files(
        generation.source_identity, generation.revision, staged_files,
    )
    return review, generation


def review_screenshot_to_code_files(
    source_identity: str, revision: str, files: Mapping[str, bytes]
) -> RuntimeReview:
    """Review exact pinned file bytes after the caller verifies the complete source tree."""
    if source_identity != SOURCE_IDENTITY or revision != SOURCE_REVISION:
        raise ScreenshotToCodeError("source tree is not the selected screenshot-to-code revision")
    contract = resolve_component_adapter("screenshot-to-code")
    if contract.source_identity != source_identity or contract.revision != revision:
        raise ScreenshotToCodeError("screenshot-to-code source contract differs from the reviewed pin")
    for path, expected in SOURCE_FILE_SHA256.items():
        body = files.get(path)
        if not isinstance(body, bytes) or hashlib.sha256(body).hexdigest() != expected:
            raise ScreenshotToCodeError(f"pinned source file is missing or changed: {path}")
    review = review_isolated_runtime("screenshot-to-code", files)
    if review.blockers:
        raise ScreenshotToCodeError("isolated screenshot-to-code runtime is incomplete: " + "; ".join(review.blockers))
    return review
