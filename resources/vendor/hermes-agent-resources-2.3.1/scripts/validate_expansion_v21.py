#!/usr/bin/env python3
from pathlib import Path

from registry_lib import ROOT, catalog, discover_resources, load_yaml, names_by_kind, version_tuple

EXPECTED_PROFILES = {
    "product-manager", "business-analyst-requirements-engineer", "coo-operations-manager",
    "people-operations-hr-specialist", "recruiter-talent-acquisition-specialist", "privacy-gdpr-specialist",
    "negotiation-conflict-resolution-specialist", "decision-scientist-operations-research-specialist",
    "automotive-maintenance-specialist", "home-energy-solar-specialist", "water-wastewater-specialist",
    "emergency-preparedness-resilience-manager", "arboriculture-tree-care-specialist", "pest-building-biology-specialist",
    "horticulture-orchard-specialist", "livestock-health-navigator", "farm-machinery-maintenance-specialist",
    "child-development-specialist", "special-education-sen-specialist", "mathematics-teacher", "science-teacher",
    "literacy-reading-specialist", "insurance-specialist", "estate-succession-planning-research-specialist",
    "procurement-vendor-manager", "eu-law-regulatory-specialist", "employment-law-portugal-eu-specialist",
    "network-engineer", "site-reliability-engineer", "database-reliability-specialist", "ai-ml-engineer",
    "privacy-security-engineer", "fact-checker-source-verification-specialist", "media-literacy-misinformation-analyst",
    "ethics-specialist", "knowledge-manager-archivist", "catholic-relationship-expert",
    "catholic-traditional-family-advisor", "catholic-tradition-expert", "catholic-history-expert",
    "catholic-prayer-planner-writer", "portuguese-english-translator", "building-architect", "farm-planner",
    "3d-model-designer", "3d-printer-specialist", "3d-model-maker", "3d-model-optimizer",
}
EXPECTED_SKILLS = {
    "claim-verification", "negotiation-preparation", "scenario-sensitivity-analysis", "decision-recording",
    "root-cause-analysis", "vendor-comparison", "privacy-impact-screening", "emergency-checklist-design",
    "cost-benefit-tco-analysis", "requirements-engineering", "professional-translation-portuguese-english",
    "architectural-design-planning", "3d-modeling-cad", "additive-manufacturing", "3d-printability-optimization",
}
EXPECTED_BUNDLES = {
    "product-strategy-team", "people-career-team", "privacy-compliance-team", "home-resilience-team",
    "farm-reliability-team", "decision-science-team", "catholic-tradition-family-team", "core-education-team",
    "architecture-fabrication-team", "additive-manufacturing-team", "information-integrity-team", "farm-planning-team",
}


def text_for(name: str) -> str:
    return " ".join((load_yaml(ROOT / "profiles" / f"{name}.yaml").get("spec") or {}).get("instructions") or []).lower()


def main() -> int:
    errors: list[str] = []
    version = str((catalog().get("metadata") or {}).get("version", "0.0.0"))
    if version_tuple(version) < (2, 1, 0):
        errors.append("catalog.yaml must be at least version 2.1.0")
    resources = discover_resources()
    names = names_by_kind(resources)
    for kind, expected in (("Profile", EXPECTED_PROFILES), ("Skill", EXPECTED_SKILLS), ("Bundle", EXPECTED_BUNDLES)):
        missing = sorted(expected - names.get(kind, set()))
        if missing:
            errors.append(f"missing {kind} resources: {missing}")
    if (ROOT / "CAPABILITY_GAP_AUDIT.md").exists():
        errors.append("CAPABILITY_GAP_AUDIT.md must remain removed after implementation")
    for name in EXPECTED_PROFILES:
        doc = load_yaml(ROOT / "profiles" / f"{name}.yaml")
        interaction = (doc.get("spec") or {}).get("interaction") or {}
        if interaction.get("userFacing") is True or interaction.get("directUserContact") == "allow" or interaction.get("userChannelBinding") == "allow":
            errors.append(f"{name} must remain internal-only")
    livestock = text_for("livestock-health-navigator")
    if "do not diagnose" not in livestock or "prescribe veterinary" not in livestock:
        errors.append("livestock-health-navigator must preserve non-veterinary diagnosis/prescribing boundary")
    architect = text_for("building-architect")
    if "licensed" not in architect or "statutory" not in architect:
        errors.append("building-architect must distinguish design assistance from licensed/statutory responsibility")
    catholic = text_for("catholic-traditional-family-advisor")
    if "binding doctrine" not in catholic or "prudential" not in catholic:
        errors.append("catholic-traditional-family-advisor must distinguish doctrine from prudential/custom matters")
    if errors:
        print("v2.1 expansion validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1
    print(f"v2.1 expansion preserved: {len(EXPECTED_PROFILES)} profiles, {len(EXPECTED_SKILLS)} skills, {len(EXPECTED_BUNDLES)} bundles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
