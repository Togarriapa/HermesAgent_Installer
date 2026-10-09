#!/usr/bin/env python3
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SECTIONS = [
    "Initial Question or Request",
    "Quick Answer / Result / Action",
    "Detailed Answer / Result / Action",
    "Agent Profiles That Contributed",
    "Opinions Against the Final Answer / Solution and Why",
    "Permissions Needed to Proceed",
]


def load(path):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def main():
    errors = []

    hermes = load("profiles/hermes.yaml").get("spec", {})
    output = hermes.get("output") or {}
    if output.get("contract") != "hermes-six-section-v1":
        errors.append("Hermes response contract must be hermes-six-section-v1")
    if output.get("requiredSections") != EXPECTED_SECTIONS:
        errors.append("Hermes requiredSections must match the canonical six-section order")
    if output.get("alwaysRenderAllSections") is not True:
        errors.append("Hermes must always render all six sections")

    orchestrator = load("profiles/orchestrator.yaml").get("spec", {})
    deliberation = orchestrator.get("deliberation") or {}
    if deliberation.get("enabled") is not True:
        errors.append("Orchestrator deliberation must stay enabled")
    if deliberation.get("mode") != "adaptive":
        errors.append("Orchestrator deliberation mode must remain adaptive")
    for field in ("independentFirstPass", "crossCritique", "evidenceOverMajority", "preserveMaterialDissent", "doNotManufactureDissent"):
        if deliberation.get(field) is not True:
            errors.append(f"Orchestrator deliberation.{field} must be true")
    returned = set((orchestrator.get("output") or {}).get("returnFields") or [])
    required = {"result", "contributorProfiles", "materialDissent", "permissionsRequired"}
    if not required.issubset(returned):
        errors.append("Orchestrator must return result/contributors/dissent/permissions to Hermes")

    leader = load("profiles/team-leader.yaml").get("spec", {})
    leader_orch = leader.get("orchestration") or {}
    if leader_orch.get("structuredDeliberation") is not True or leader_orch.get("preserveMaterialDissent") is not True:
        errors.append("Team Leader must retain structured deliberation and dissent preservation")

    debate = load("profiles/debate-analyst.yaml").get("spec", {})
    interaction = debate.get("interaction") or {}
    if interaction.get("userFacing") is True or interaction.get("directUserContact") == "allow" or interaction.get("userChannelBinding") == "allow":
        errors.append("Debate Analyst must remain internal-only")

    family_profiles = [
        "portuguese-catholic-family-advisor",
        "sicilian-catholic-family-advisor",
        "spanish-catholic-family-advisor",
        "german-catholic-family-advisor",
    ]
    for name in family_profiles:
        spec = load(f"profiles/{name}.yaml").get("spec", {})
        text = " ".join(spec.get("instructions") or []).lower()
        if "distinguish catholic teaching" not in text:
            errors.append(f"{name} must distinguish Catholic teaching from cultural custom")
        if "represent all" not in text:
            errors.append(f"{name} must explicitly avoid claiming universal representation")

    strategy_bundle = load("bundles/strategic-deliberation-team.yaml").get("spec", {})
    if (strategy_bundle.get("policy") or {}).get("majorityVoteDecisionRule") != "deny":
        errors.append("Strategic deliberation team must not use majority vote as its decision rule")

    if errors:
        print("Deliberation validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Deliberation and Hermes response contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
