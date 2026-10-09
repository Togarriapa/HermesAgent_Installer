#!/usr/bin/env python3
from __future__ import annotations

from registry_lib import effective_spec, load_quality_policy, resolve_inherited_spec, discover_resources

CASES = {
    "profiles/systems-architect.yaml": {"must": {"software-data-infrastructure"}, "must_not": {"physical-engineering-property-farm", "translation"}},
    "profiles/network-engineer.yaml": {"must": {"software-data-infrastructure"}, "must_not": {"physical-engineering-property-farm"}},
    "profiles/building-architect.yaml": {"must": {"physical-engineering-property-farm"}, "must_not": {"software-data-infrastructure"}},
    "profiles/language-teacher.yaml": {"must": {"children-education"}, "must_not": {"translation"}},
    "profiles/portuguese-english-translator.yaml": {"must": {"translation"}, "must_not": {"children-education"}},
    "profiles/portfolio-manager.yaml": {"must": {"finance-investment"}, "must_not": {"physical-engineering-property-farm"}},
    "profiles/catholic-tradition-expert.yaml": {"must": {"catholic"}, "must_not": {"translation"}},
    "profiles/psychology-expert.yaml": {"must": {"health-psychology-nutrition", "research-information-integrity"}, "must_not": {"physical-engineering-property-farm"}},
    "profiles/eu-law-regulatory-specialist.yaml": {"must": {"legal-regulatory"}, "must_not": {"finance-investment"}},
    "profiles/fact-checker-source-verification-specialist.yaml": {"must": {"research-information-integrity"}, "must_not": {"legal-regulatory", "finance-investment"}},
    "profiles/3d-printer-specialist.yaml": {"must": {"physical-engineering-property-farm"}, "must_not": {"software-data-infrastructure"}},
    "profiles/ai-prompt-engineer.yaml": {"must": {"software-data-infrastructure", "ai-engineering"}, "must_not": {"physical-engineering-property-farm"}},
    "profiles/hermesagent-expert.yaml": {"must": {"ai-engineering"}, "must_not": {"health-psychology-nutrition"}},
    "profiles/amish-remedies-expert.yaml": {"must": {"health-psychology-nutrition", "traditional-remedies", "amish-cultural-context", "research-information-integrity"}, "must_not": {"pregnancy-postpartum-fitness"}},
    "profiles/amish-construction-expert.yaml": {"must": {"amish-cultural-context", "physical-engineering-property-farm"}, "must_not": {"traditional-remedies"}},
    "profiles/ancient-traditional-remedies-expert.yaml": {"must": {"health-psychology-nutrition", "traditional-remedies", "ancient-traditions-context", "research-information-integrity"}, "must_not": {"pregnancy-postpartum-fitness"}},
    "profiles/ancient-building-traditions-expert.yaml": {"must": {"ancient-traditions-context", "physical-engineering-property-farm"}, "must_not": {"traditional-remedies"}},
    "profiles/traditional-latin-mass-expert.yaml": {"must": {"catholic"}, "must_not": {"health-psychology-nutrition"}},
    "profiles/prenatal-postpartum-fitness-coach.yaml": {"must": {"health-psychology-nutrition", "pregnancy-postpartum-fitness", "specialized-fitness"}, "must_not": {"traditional-remedies"}},
    "profiles/powerlifting-coach.yaml": {"must": {"health-psychology-nutrition", "specialized-fitness"}, "must_not": {"pregnancy-postpartum-fitness"}},
    "profiles/kobo-library-notebook-specialist.yaml": {"must": {"ebook-kobo"}, "must_not": {"finance-investment", "health-psychology-nutrition"}},
    "profiles/kobo-integration-specialist.yaml": {"must": {"ebook-kobo"}, "must_not": {"finance-investment", "health-psychology-nutrition"}},
    "profiles/ebook-converter.yaml": {"must": {"ebook-kobo"}, "must_not": {"finance-investment"}},
    "profiles/homelab-infrastructure-operator.yaml": {"must": {"software-data-infrastructure"}, "must_not": {"finance-investment", "health-psychology-nutrition", "physical-engineering-property-farm"}},
}


def main() -> int:
    policy = load_quality_policy()
    resources = discover_resources()
    by_rel = {item["rel"]: item for item in resources}
    errors: list[str] = []
    for relative_path, expected in CASES.items():
        item = by_rel.get(relative_path)
        if item is None:
            errors.append(f"missing regression resource: {relative_path}")
            continue
        doc = item["doc"]
        metadata = doc.get("metadata") or {}
        raw_tags = metadata.get("tags") or []
        tags = set(raw_tags) if isinstance(raw_tags, list) else set()
        resolved = resolve_inherited_spec(item, resources)
        _effective, overlays = effective_spec(str(item["kind"]), str(item["name"]), tags, resolved, policy)
        actual = set(overlays)
        missing = sorted(expected["must"] - actual)
        forbidden = sorted(expected["must_not"] & actual)
        if missing:
            errors.append(f"{relative_path}: expected overlays missing: {missing}; actual={sorted(actual)}")
        if forbidden:
            errors.append(f"{relative_path}: unrelated overlays attached: {forbidden}; actual={sorted(actual)}")
    if errors:
        print("v2.2 quality-overlay regression validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1
    print(f"Quality overlay regression OK: {len(CASES)} representative resources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
