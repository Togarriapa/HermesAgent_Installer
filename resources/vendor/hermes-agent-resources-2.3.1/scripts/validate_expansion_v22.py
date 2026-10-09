#!/usr/bin/env python3
from __future__ import annotations

from registry_lib import ROOT, catalog, discover_resources, load_yaml, names_by_kind

EXPECTED_PROFILES = {
    "hermesagent-expert", "ai-developer", "ai-systems-architect", "ai-prompt-engineer", "ai-agent-orchestration-engineer", "ai-evaluation-engineer", "llmops-engineer", "ai-safety-reliability-engineer", "ai-knowledge-engineer",
    "traditional-remedies-researcher", "herbalism-ethnobotany-researcher", "historical-materia-medica-researcher", "natural-lifestyle-health-educator", "traditional-foodways-health-researcher",
    "amish-remedies-expert", "amish-lifestyle-expert", "amish-construction-expert", "amish-farming-expert", "amish-housekeeping-expert", "amish-cook-expert", "amish-food-preservation-expert",
    "ancient-traditional-remedies-expert", "ancient-lifestyle-expert", "ancient-building-traditions-expert", "ancient-agriculture-expert", "ancient-housekeeping-domestic-life-expert", "ancient-cook-foodways-expert", "ancient-food-preservation-expert", "ancient-crafts-material-culture-expert",
    "traditional-latin-mass-expert", "roman-rite-liturgical-traditions-expert", "pre-vatican-ii-catholic-practice-researcher", "catholic-devotions-sacramentals-expert", "gregorian-chant-sacred-music-expert", "catholic-calendar-fasting-abstinence-expert", "patristics-church-fathers-expert", "ecclesiastical-latin-expert",
    "fitness-coach", "bodybuilding-coach", "calisthenics-coach", "powerlifting-coach", "prenatal-postpartum-fitness-coach", "strength-conditioning-coach", "mobility-flexibility-coach", "endurance-conditioning-coach", "senior-fitness-coach", "youth-fitness-coach",
    "kobo-integration-specialist", "kobo-library-notebook-specialist", "ebook-planner", "ebook-writer", "ebook-designer", "ebook-converter", "ebook-editor-publisher",
    "homelab-infrastructure-operator",
}
EXPECTED_SKILLS = {
    "hermesagent-runtime-architecture", "ai-application-engineering", "ai-system-architecture", "prompt-engineering", "agentic-workflow-engineering", "ai-evaluation-benchmarking", "llmops-model-operations", "ai-safety-reliability-evaluation", "retrieval-knowledge-engineering",
    "traditional-remedy-source-analysis", "herbal-remedy-evidence-screening", "historical-materia-medica-analysis", "natural-lifestyle-evidence-screening", "traditional-foodways-analysis",
    "amish-cultural-practice-research", "amish-building-practice-analysis", "amish-agriculture-practice-analysis", "amish-household-practice-analysis", "amish-foodways-analysis", "historical-food-preservation-analysis",
    "ancient-traditions-context-analysis", "ancient-domestic-life-research", "ancient-agricultural-history", "ancient-building-traditions-analysis", "ancient-foodways-analysis", "ancient-material-culture-analysis",
    "traditional-latin-mass-research", "roman-rite-liturgical-history", "catholic-devotional-traditions", "gregorian-chant-liturgical-music", "catholic-calendar-fasting-practice", "patristic-source-research", "ecclesiastical-latin-analysis",
    "fitness-coaching", "hypertrophy-programming", "calisthenics-programming", "powerlifting-programming", "prenatal-postpartum-exercise", "strength-conditioning", "mobility-flexibility-programming", "endurance-conditioning", "senior-fitness-programming", "youth-fitness-programming",
    "kobo-device-workflow", "kobo-notebook-ingestion", "kobo-book-delivery", "notebook-knowledge-synthesis", "ebook-architecture-planning", "long-form-ebook-writing", "ebook-editing-proofing", "ebook-design-layout", "epub-conversion-validation", "ebook-metadata-packaging",
    "authentik-infrastructure-authorization", "homelab-host-operations", "nextcloud-service-operations", "cloudflare-tunnel-operations", "homelab-backup-recovery", "cross-service-incident-diagnosis", "infrastructure-alarm-triage",
}
EXPECTED_PLUGINS = {"kobo-bridge", "ebook-toolchain", "authentik-authorization", "homelab-ops-broker", "cloudflare-homelab"}
EXPECTED_BUNDLES = {"ai-engineering-team", "traditional-remedies-research-team", "amish-traditional-living-team", "ancient-traditions-team", "traditional-catholic-liturgy-team", "strength-fitness-team", "life-stage-fitness-team", "ebook-publishing-team", "homelab-operations-team"}
EXPECTED_CRONS = {"homelab-health-review"}
REMEDY_PROFILES = {"traditional-remedies-researcher", "herbalism-ethnobotany-researcher", "historical-materia-medica-researcher", "amish-remedies-expert", "ancient-traditional-remedies-expert"}
AMISH_PROFILES = {name for name in EXPECTED_PROFILES if name.startswith("amish-")}
ANCIENT_PROFILES = {name for name in EXPECTED_PROFILES if name.startswith("ancient-")}
KOBO_EBOOK_PROFILES = {"kobo-integration-specialist", "kobo-library-notebook-specialist", "ebook-planner", "ebook-writer", "ebook-designer", "ebook-converter", "ebook-editor-publisher"}


def profile_doc(name: str) -> dict:
    return load_yaml(ROOT / "profiles" / f"{name}.yaml")


def instructions(name: str) -> str:
    return " ".join((profile_doc(name).get("spec") or {}).get("instructions") or []).lower()


def plugin_doc(name: str) -> dict:
    return load_yaml(ROOT / "plugins" / f"{name}.yaml")


def main() -> int:
    errors: list[str] = []
    if (catalog().get("metadata") or {}).get("version") != "2.3.1":
        errors.append("catalog.yaml must be version 2.3.1")

    resources = discover_resources()
    names = names_by_kind(resources)
    for kind, expected in (("Profile", EXPECTED_PROFILES), ("Skill", EXPECTED_SKILLS), ("Plugin", EXPECTED_PLUGINS), ("Bundle", EXPECTED_BUNDLES), ("Cron", EXPECTED_CRONS)):
        missing = sorted(expected - names.get(kind, set()))
        if missing:
            errors.append(f"missing expected {kind} resources: {missing}")

    for name in EXPECTED_PROFILES:
        interaction = (profile_doc(name).get("spec") or {}).get("interaction") or {}
        if interaction.get("userFacing") is True or interaction.get("directUserContact") == "allow" or interaction.get("userChannelBinding") == "allow":
            errors.append(f"{name} must remain internal-only")

    for name in REMEDY_PROFILES:
        text = instructions(name)
        if not any(term in text for term in ("diagnos", "prescrib")):
            errors.append(f"{name}: remedy role must explicitly deny diagnosis/prescribing")
        if name in {"traditional-remedies-researcher", "amish-remedies-expert"} and not any(term in text for term in ("urgent", "effective care", "modern care")):
            errors.append(f"{name}: must preserve modern/urgent-care boundary")

    for name in AMISH_PROFILES:
        text = instructions(name)
        tags = set((profile_doc(name).get("metadata") or {}).get("tags") or [])
        if "amish" not in tags:
            errors.append(f"{name}: missing amish tag")
        if not any(term in text for term in ("region", "community", "affiliation", "uniform")):
            errors.append(f"{name}: must preserve Amish community/region variation")

    for name in ANCIENT_PROFILES:
        tags = set((profile_doc(name).get("metadata") or {}).get("tags") or [])
        text = instructions(name)
        if "ancient-traditions" not in tags:
            errors.append(f"{name}: missing ancient-traditions tag")
        if not any(term in text for term in ("civilization", "culture", "period")):
            errors.append(f"{name}: must be civilization/culture/period specific")

    latin = instructions("traditional-latin-mass-expert")
    if "historical" not in latin or not any(term in latin for term in ("authority", "permission", "clergy")):
        errors.append("traditional-latin-mass-expert must distinguish historical/current context and ecclesiastical authority")

    prompt = instructions("ai-prompt-engineer")
    if "authorization" not in prompt or "substitute" not in prompt:
        errors.append("ai-prompt-engineer must state prompt text cannot substitute for structural authorization")

    maternity = instructions("prenatal-postpartum-fitness-coach")
    if "clinician" not in maternity or "diagnos" not in maternity:
        errors.append("prenatal-postpartum-fitness-coach must preserve clinician and non-diagnosis boundaries")

    bodybuilding = instructions("bodybuilding-coach")
    if "steroids" not in bodybuilding or "dehydration" not in bodybuilding:
        errors.append("bodybuilding-coach must deny drug and dangerous dehydration advice")

    for name in KOBO_EBOOK_PROFILES:
        if "kobo" in name:
            text = instructions(name)
            if not any(term in text for term in ("drm", "export", "authorized", "approved")):
                errors.append(f"{name}: Kobo workflow must preserve exported/authorized content and DRM boundary")

    bridge_policy = (plugin_doc("kobo-bridge").get("spec") or {}).get("policy") or {}
    for field in ("koboAccountCredentialScraping", "drmRemoval", "storePurchases", "deleteDeviceContent"):
        if bridge_policy.get(field) != "deny":
            errors.append(f"kobo-bridge policy.{field} must remain deny")
    if bridge_policy.get("outboundDelivery") != "explicit-user-order":
        errors.append("kobo-bridge outbound delivery must require explicit user order")

    toolchain_policy = (plugin_doc("ebook-toolchain").get("spec") or {}).get("policy") or {}
    if toolchain_policy.get("drmRemoval") != "deny":
        errors.append("ebook-toolchain must deny DRM removal")

    homelab = profile_doc("homelab-infrastructure-operator").get("spec") or {}
    auth = homelab.get("authorization") or {}
    if auth.get("identityProvider") != "authentik" or auth.get("requiredEffectiveGroup") != "System" or auth.get("failClosed") is not True:
        errors.append("homelab-infrastructure-operator must require fail-closed Authentik System authorization")
    if auth.get("mutationCheck") != "fresh-before-tool-call" or auth.get("alarmRecipientCheck") != "fresh-at-delivery":
        errors.append("homelab-infrastructure-operator must freshly check writes and alarm recipients")

    authentik = plugin_doc("authentik-authorization").get("spec") or {}
    authentik_policy = authentik.get("policy") or {}
    authentik_runtime = authentik.get("runtime") or {}
    if authentik_policy.get("writes") != "deny" or authentik_policy.get("groupAdministration") != "deny" or authentik_policy.get("roleAdministration") != "deny":
        errors.append("authentik-authorization must remain read-only")
    if authentik_runtime.get("requiredGroupName") != "System" or authentik_runtime.get("membershipMode") != "direct-and-indirect" or authentik_policy.get("failClosedOnLookupFailure") is not True:
        errors.append("authentik-authorization must verify effective System membership and fail closed")

    broker = plugin_doc("homelab-ops-broker").get("spec") or {}
    broker_policy = broker.get("policy") or {}
    broker_runtime = broker.get("runtime") or {}
    if broker_policy.get("arbitraryShell") != "deny" or broker_policy.get("rawSsh") != "deny" or broker_policy.get("arbitraryCommand") != "deny":
        errors.append("homelab-ops-broker must deny arbitrary shell/raw SSH/commands")
    if broker_policy.get("writesRequireFreshAuthentikSystemMembership") is not True or broker_runtime.get("requiredEffectiveGroupForWrites") != "System":
        errors.append("homelab-ops-broker writes must require fresh Authentik System membership")

    cloudflare = plugin_doc("cloudflare-homelab").get("spec") or {}
    cloudflare_policy = cloudflare.get("policy") or {}
    cloudflare_runtime = cloudflare.get("runtime") or {}
    if cloudflare_policy.get("writesRequireFreshAuthentikSystemMembership") is not True or cloudflare_runtime.get("requiredEffectiveGroupForWrites") != "System":
        errors.append("cloudflare-homelab writes must require fresh Authentik System membership")
    for field in ("unrelatedZoneAccess", "unrelatedTunnelAccess", "accountAdministration", "apiTokenAdministration"):
        if cloudflare_policy.get(field) != "deny":
            errors.append(f"cloudflare-homelab policy.{field} must remain deny")

    cron = load_yaml(ROOT / "crons" / "homelab-health-review.yaml").get("spec") or {}
    cron_policy = cron.get("policy") or {}
    if cron_policy.get("authorityFromSchedule") != "deny" or cron_policy.get("remediationFromSchedule") != "deny":
        errors.append("homelab-health-review must remain read-only and gain no remediation authority from schedule")
    if cron_policy.get("infrastructureAlarmRequiredGroup") != "System" or cron_policy.get("resolveRecipientsAtDelivery") is not True or cron_policy.get("failClosedOnRecipientAuthorizationFailure") is not True:
        errors.append("homelab-health-review alarms must resolve current System recipients and fail closed")

    if errors:
        print("specialist expansion validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print(f"Expansion OK: {len(EXPECTED_PROFILES)} profiles, {len(EXPECTED_SKILLS)} skills, {len(EXPECTED_PLUGINS)} plugins, {len(EXPECTED_BUNDLES)} bundles, {len(EXPECTED_CRONS)} required crons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
