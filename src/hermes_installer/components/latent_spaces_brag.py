"""Status for the pinned Brag skill and its existing Hyperframes renderer."""
from __future__ import annotations

from dataclasses import dataclass

from hermes_installer.components.adapters import resolve_component_adapter


@dataclass(frozen=True, slots=True)
class BragStatus:
    component_id: str
    source_identity: str
    revision: str
    renderer_component: str
    installs_renderer: bool
    rendering_available: bool
    render_status: str
    narration_available: bool
    narration_status: str
    reason: str


def latent_spaces_brag_status(*, narration_requested: bool = False) -> BragStatus:
    """Report source-only availability without treating fixture rendering as Brag."""
    source = resolve_component_adapter("latent-spaces/brag")
    if (source.source_identity != "latent-spaces/brag"
            or source.revision != "7079945d391573edebe48fdc0a23b39c4b4e8726"):
        raise RuntimeError("latent-spaces/brag source contract differs from the reviewed pin")
    narration_status = (
        "unavailable: no eligible narration account and metered budget"
        if narration_requested else "disabled: narration is opt-in"
    )
    return BragStatus(
        component_id=source.component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        renderer_component="hyperframes",
        installs_renderer=False,
        rendering_available=False,
        render_status="unavailable: only the fixed Hyperframes smoke fixture is registered",
        narration_available=False,
        narration_status=narration_status,
        reason=("the pinned Brag skill delegates per-project composition and rendering to "
                "Hyperframes; no authorized Brag composition workload is registered"),
    )
