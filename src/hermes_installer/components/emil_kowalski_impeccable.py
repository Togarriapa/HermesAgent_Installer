"""Pinned Impeccable skill routing, distinct from Emil Kowalski's skill pack."""
from __future__ import annotations

import json

from hermes_installer.components.adapters import resolve_optional_source_offer
from hermes_installer.components.portable_skill_adapters import (
    CapabilityState,
    PortableSkill,
    PortableSkillError,
    SkillRoute,
    route_skill,
    select_portable_skill,
    unavailable_capability,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


SOURCE_IDENTITY = "pbakaus/impeccable"
SOURCE_REVISION = "d631a8827f99414d2b6daba4ef08b7f8701751d7"
HERMES_SKILL_PATH = ".hermes/skills/impeccable/SKILL.md"
LINUX_ARM64_MANIFEST = "cli/platform-packages/linux-arm64/package.json"
LINUX_ARM64_BINARY = "cli/platform-packages/linux-arm64/bin/impeccable"


def invoke_impeccable_skill(source: VerifiedComponentSource, request: str) -> SkillRoute:
    """Resolve the documented /impeccable skill route without running its launcher."""
    skill = select_portable_skill("emil-kowalski-impeccable", source, HERMES_SKILL_PATH)
    return route_skill("emil-kowalski-impeccable", skill, request)


def native_design_hook_state(_source: VerifiedComponentSource | None = None) -> CapabilityState:
    """The selected Hermes source has no verified native design-hook adapter."""
    return unavailable_capability(
        "native design hook and its Linux ARM64 runtime have not been verified; portable skill routing is separate"
    )


def linux_arm64_engine_asset_state(source: VerifiedComponentSource) -> CapabilityState:
    """Check the pinned npm platform package declaration and actual binary bytes."""
    from hermes_installer.components.portable_skill_adapters import validate_pinned_source

    try:
        validate_pinned_source("emil-kowalski-impeccable", source)
        raw = source.files.get(LINUX_ARM64_MANIFEST)
        manifest = json.loads(raw) if isinstance(raw, bytes) else None
    except (PortableSkillError, UnicodeError, json.JSONDecodeError):
        manifest = None
    if (not isinstance(manifest, dict)
            or manifest.get("name") != "@impeccable/cli-linux-arm64"
            or manifest.get("os") != ["linux"]
            or manifest.get("cpu") != ["arm64"]
            or manifest.get("bin") != {"impeccable-linux-arm64": "bin/impeccable"}):
        return CapabilityState(
            "unavailable", "the pinned Linux ARM64 optional-package manifest is missing or changed"
        )
    binary = source.files.get(LINUX_ARM64_BINARY)
    if not isinstance(binary, bytes):
        return CapabilityState(
            "pending-runtime",
            "the pinned source declares @impeccable/cli-linux-arm64, but the engine binary is delivered by a separate npm optional package; install and inspect it only in an isolated ARM64 runtime",
        )
    if len(binary) < 20 or binary[:4] != b"\x7fELF" or binary[5] not in {1, 2}:
        return CapabilityState("unavailable", "the selected Linux ARM64 engine asset is not a valid ELF binary")
    byte_order = "little" if binary[5] == 1 else "big"
    machine = int.from_bytes(binary[18:20], byte_order)
    if machine != 183:
        return CapabilityState("unavailable", "the selected engine ELF machine is not AArch64")
    return CapabilityState("asset-verified-runtime-pending", "AArch64 ELF asset is present; execution remains untested")


def emil_kowalski_skill_pack_offer() -> tuple[str, str, str]:
    """Return Emil's separate optional repository pin without merging identities."""
    offer = resolve_optional_source_offer("emilkowalski/skills")
    if not offer.identity or not offer.revision or not offer.url:
        raise PortableSkillError("Emil Kowalski skill-pack offer is unresolved")
    return offer.identity, offer.revision, offer.url
