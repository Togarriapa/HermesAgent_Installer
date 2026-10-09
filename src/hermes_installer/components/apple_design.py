"""Rights-aware review status for the selected Apple design reference skill."""
from __future__ import annotations

from dataclasses import dataclass

from hermes_installer.components.adapters import resolve_component_adapter


@dataclass(frozen=True, slots=True)
class AppleDesignStatus:
    component_id: str
    source_identity: str
    revision: str
    attribution: str
    source_review_status: str
    activation_available: bool
    reason: str
    xcode_required: bool = False


def apple_design_status() -> AppleDesignStatus:
    """Keep the chosen reference source private until its license is reviewed."""
    source = resolve_component_adapter("apple-design")
    if (source.source_identity != "dickwu/apple-design-skill"
            or source.revision != "904b0eedc7cc778152f545506075d5bb5219ce77"):
        raise RuntimeError("apple-design source contract differs from the reviewed pin")
    if not source.redistribution_license_review_required:
        raise RuntimeError("apple-design rights status changed; review the adapter")
    return AppleDesignStatus(
        component_id=source.component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        attribution="Third-party Apple Human Interface Guidelines reference; not Apple-owned software",
        source_review_status="private source review only; no detected license",
        activation_available=False,
        reason="verify redistribution and activation rights for reproduced Apple HIG text",
    )
