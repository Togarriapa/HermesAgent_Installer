#!/usr/bin/env python3
from __future__ import annotations

import sys
from typing import Any

from registry_lib import (
    API_VERSION,
    DEPENDENCY_KINDS,
    NAME_RE,
    RESOURCE_DIRS,
    SELECTOR_RE,
    SEMVER_RE,
    catalog,
    discover_resources,
    selector_matches,
    versions_index,
)

USER_CHANNELS = {"web", "telegram", "discord", "whatsapp", "voice"}
COMPOSIO_VERSION_RE = __import__("re").compile(r"^\d{8}_\d{2}$")


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def validate_selector(rel: str, field: str, kind: str, selector: Any, versions: dict[tuple[str, str], set[str]], errors: list[str]) -> None:
    if not isinstance(selector, str):
        fail(f"{rel}: {field} selector must be a string", errors)
        return
    match = SELECTOR_RE.fullmatch(selector)
    if not match:
        fail(f"{rel}: {field} has invalid selector {selector!r}", errors)
        return
    name, caret_marker, requested = match.groups()
    candidates = versions.get((kind, name), set())
    if not candidates:
        fail(f"{rel}: {field} references missing {kind} {name!r}", errors)
        return
    if not any(selector_matches(candidate, requested, bool(caret_marker)) for candidate in candidates):
        fail(f"{rel}: {field} selector {selector!r} is not satisfied by {sorted(candidates)}", errors)


def validate_dependency_map(rel: str, field: str, dependency_map: Any, versions: dict[tuple[str, str], set[str]], errors: list[str]) -> None:
    if dependency_map is None:
        return
    if not isinstance(dependency_map, dict):
        fail(f"{rel}: {field} must be a mapping", errors)
        return
    for plural, selectors in dependency_map.items():
        kind = DEPENDENCY_KINDS.get(plural)
        if kind is None:
            fail(f"{rel}: {field} has unknown dependency group {plural!r}", errors)
            continue
        if not isinstance(selectors, list):
            fail(f"{rel}: {field}.{plural} must be a list", errors)
            continue
        for selector in selectors:
            validate_selector(rel, f"{field}.{plural}", kind, selector, versions, errors)


def validate_composio_policy(rel: str, spec: dict[str, Any], errors: list[str]) -> None:
    policy = (spec.get("integrationPolicy") or {}).get("composio")
    if policy is None:
        return
    if not isinstance(policy, dict):
        fail(f"{rel}: integrationPolicy.composio must be a mapping", errors)
        return
    required_plugins = ((spec.get("requires") or {}).get("plugins") or [])
    if not any(isinstance(item, str) and item.startswith("composio@") for item in required_plugins):
        fail(f"{rel}: Composio policy requires an explicit composio plugin dependency", errors)
    toolkits = policy.get("toolkits")
    if not isinstance(toolkits, list) or not toolkits:
        fail(f"{rel}: integrationPolicy.composio.toolkits must be a non-empty list", errors)
        return
    seen: set[str] = set()
    for toolkit in toolkits:
        if not isinstance(toolkit, dict):
            fail(f"{rel}: each Composio toolkit entry must be a mapping", errors)
            continue
        slug = toolkit.get("slug")
        version = toolkit.get("version")
        tools = toolkit.get("allowedTools")
        if not isinstance(slug, str) or not NAME_RE.fullmatch(slug.replace("_", "-")):
            fail(f"{rel}: invalid Composio toolkit slug {slug!r}", errors)
            continue
        if slug in seen:
            fail(f"{rel}: duplicate Composio toolkit {slug!r}", errors)
        seen.add(slug)
        if not isinstance(version, str) or not COMPOSIO_VERSION_RE.fullmatch(version):
            fail(f"{rel}: Composio toolkit {slug!r} must pin a dated version", errors)
        if not isinstance(tools, list) or not tools:
            fail(f"{rel}: Composio toolkit {slug!r} must explicitly allow tools", errors)
            continue
        prefix = slug.upper() + "_"
        for tool in tools:
            if not isinstance(tool, str) or not tool.startswith(prefix):
                fail(f"{rel}: tool {tool!r} does not match toolkit {slug!r}", errors)


def main() -> int:
    errors: list[str] = []
    try:
        cat = catalog()
        resources = discover_resources()
    except (ValueError, OSError) as exc:
        print(f"Registry discovery failed: {exc}", file=sys.stderr)
        return 1

    if cat.get("apiVersion") != API_VERSION:
        fail(f"catalog.yaml: apiVersion must be {API_VERSION}", errors)
    if cat.get("kind") != "Catalog":
        fail("catalog.yaml: kind must be Catalog", errors)
    metadata = cat.get("metadata") or {}
    if not isinstance(metadata.get("version"), str) or not SEMVER_RE.fullmatch(metadata.get("version", "")):
        fail("catalog.yaml: metadata.version must be semantic version", errors)
    discovery = ((cat.get("spec") or {}).get("discovery") or {})
    if discovery.get("mode") != "manifest-roots":
        fail("catalog.yaml: spec.discovery.mode must be manifest-roots", errors)
    if discovery.get("recursive") is not False:
        fail("catalog.yaml: discovery must remain non-recursive until nested-resource semantics are defined", errors)
    roots = discovery.get("roots") or {}
    if set(roots) != set(RESOURCE_DIRS):
        fail(f"catalog.yaml: discovery roots must cover exactly {sorted(RESOURCE_DIRS)}", errors)

    seen: set[tuple[str, str, str]] = set()
    for item in resources:
        rel = item["rel"]
        doc = item["doc"]
        kind = item.get("kind")
        name = item.get("name")
        version = item.get("version")
        expected_kind = item.get("expected_kind")
        if doc.get("apiVersion") != API_VERSION:
            fail(f"{rel}: apiVersion must be {API_VERSION}", errors)
        if kind != expected_kind:
            fail(f"{rel}: kind {kind!r} does not match discovery root kind {expected_kind}", errors)
        if kind not in RESOURCE_DIRS:
            fail(f"{rel}: unsupported kind {kind!r}", errors)
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            fail(f"{rel}: invalid metadata.name {name!r}", errors)
        if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
            fail(f"{rel}: invalid metadata.version {version!r}", errors)
        description = (doc.get("metadata") or {}).get("description")
        if not isinstance(description, str) or not description.strip():
            fail(f"{rel}: metadata.description is required", errors)
        if not isinstance(doc.get("spec"), dict):
            fail(f"{rel}: spec must be a mapping", errors)
        if isinstance(name, str) and item["path"].stem != name:
            fail(f"{rel}: filename must equal metadata.name", errors)
        if isinstance(kind, str) and isinstance(name, str) and isinstance(version, str):
            key = (kind, name, version)
            if key in seen:
                fail(f"{rel}: duplicate resource identity {key}", errors)
            seen.add(key)

    versions = versions_index(resources)
    for item in resources:
        rel = item["rel"]
        kind = item.get("kind")
        name = item.get("name")
        spec = (item["doc"].get("spec") or {}) if isinstance(item["doc"].get("spec"), dict) else {}
        validate_dependency_map(rel, "spec.requires", spec.get("requires"), versions, errors)
        if kind == "Bundle":
            validate_dependency_map(rel, "spec.imports", spec.get("imports"), versions, errors)
        extends = spec.get("extends")
        if extends is not None and isinstance(kind, str):
            validate_selector(rel, "spec.extends", kind, extends, versions, errors)

        if kind == "Profile":
            interaction = spec.get("interaction") or {}
            if name == "hermes":
                if interaction.get("userFacing") is not True:
                    fail(f"{rel}: Hermes must be userFacing=true", errors)
                if interaction.get("directUserContact") != "allow":
                    fail(f"{rel}: Hermes must allow directUserContact", errors)
                if interaction.get("userChannelBinding") != "allow":
                    fail(f"{rel}: Hermes must allow userChannelBinding", errors)
                if interaction.get("soleUserEntryPoint") is not True:
                    fail(f"{rel}: Hermes must be soleUserEntryPoint=true", errors)
            else:
                if interaction.get("userFacing") is True:
                    fail(f"{rel}: only Hermes may be userFacing=true", errors)
                if interaction.get("directUserContact") == "allow":
                    fail(f"{rel}: only Hermes may allow directUserContact", errors)
                if interaction.get("userChannelBinding") == "allow":
                    fail(f"{rel}: only Hermes may allow userChannelBinding", errors)
            validate_composio_policy(rel, spec, errors)

        if kind == "Channel" and name in USER_CHANNELS:
            routing = spec.get("routing") or {}
            policy = spec.get("policy") or {}
            if routing.get("inboundProfile") != "hermes" or routing.get("outboundProfile") != "hermes":
                fail(f"{rel}: user channels must route inbound/outbound through Hermes", errors)
            if routing.get("allowDirectProfileSelection") is not False:
                fail(f"{rel}: direct profile selection must be disabled", errors)
            if routing.get("allowedUserFacingProfiles") != ["hermes"]:
                fail(f"{rel}: allowedUserFacingProfiles must be exactly [hermes]", errors)
            if policy.get("requireHermesGateway") is not True or policy.get("rejectNonHermesProfileTarget") is not True:
                fail(f"{rel}: user channel must structurally require Hermes gateway", errors)

    by_resource = {(r.get("kind"), r.get("name")): r["doc"] for r in resources}

    composio = by_resource.get(("Plugin", "composio"), {}).get("spec", {})
    if composio:
        policy = composio.get("policy") or {}
        sessions = composio.get("sessions") or {}
        if policy.get("denyUnlistedToolkits") is not True:
            fail("plugins/composio.yaml: denyUnlistedToolkits must be true", errors)
        if policy.get("remoteWorkbench") != "deny" or policy.get("remoteBash") != "deny":
            fail("plugins/composio.yaml: remote workbench and bash must be denied", errors)
        if sessions.get("requireToolkitAllowlist") is not True:
            fail("plugins/composio.yaml: toolkit allowlists must be required", errors)

    agent37 = by_resource.get(("Plugin", "agent37-discovery"), {}).get("spec", {})
    if agent37:
        policy = agent37.get("policy") or {}
        if policy.get("autoInstall") is not False or policy.get("autoExecute") is not False:
            fail("plugins/agent37-discovery.yaml: auto-install and auto-execute must stay disabled", errors)
        if policy.get("requireSourceRepositoryReview") is not True:
            fail("plugins/agent37-discovery.yaml: source repository review must be required", errors)

    home_assistant = by_resource.get(("MCP", "home-assistant"), {}).get("spec", {})
    if home_assistant:
        if home_assistant.get("endpoint") != "${HOME_ASSISTANT_URL}/api/mcp":
            fail("mcps/home-assistant.yaml: canonical endpoint must be ${HOME_ASSISTANT_URL}/api/mcp", errors)
        if (home_assistant.get("provenance") or {}).get("officialIntegration") != "mcp_server":
            fail("mcps/home-assistant.yaml: official Home Assistant MCP provenance is required", errors)

    orchestrator = by_resource.get(("Profile", "orchestrator"), {}).get("spec", {})
    if orchestrator:
        orchestration = orchestrator.get("orchestration") or {}
        recruitment = orchestrator.get("recruitment") or {}
        kanban = orchestrator.get("kanban") or {}
        if orchestration.get("parallelExecution") is not True or orchestration.get("hierarchicalDelegation") is not True:
            fail("profiles/orchestrator.yaml: parallel and hierarchical orchestration must stay enabled", errors)
        if orchestration.get("executionModel") != "dependency-dag":
            fail("profiles/orchestrator.yaml: executionModel must remain dependency-dag", errors)
        if recruitment.get("allowMultipleInstancesPerProfile") is not True:
            fail("profiles/orchestrator.yaml: multiple instances per profile must be allowed", errors)
        if recruitment.get("registryMaxInstancesPerProfile") != "none" or recruitment.get("effectiveInstanceLimit") != "host-policy":
            fail("profiles/orchestrator.yaml: instance ceiling must remain host-policy", errors)
        if kanban.get("oneBoardPerEpic") is not True or kanban.get("deleteOnAcceptedDone") is not True:
            fail("profiles/orchestrator.yaml: one ephemeral board per Epic is required", errors)

    team_leader = by_resource.get(("Profile", "team-leader"), {}).get("spec", {})
    if team_leader:
        recruitment = team_leader.get("recruitment") or {}
        orchestration = team_leader.get("orchestration") or {}
        if recruitment.get("allowMultipleInstancesPerProfile") is not True:
            fail("profiles/team-leader.yaml: multiple profile instances must be supported", errors)
        if orchestration.get("parallelSubteams") is not True or orchestration.get("nestedDelegation") is not True:
            fail("profiles/team-leader.yaml: parallel nested subteams must stay enabled", errors)

    overlay_store = by_resource.get(("Plugin", "resource-overlay-store"), {}).get("spec", {})
    if overlay_store:
        policy = overlay_store.get("policy") or {}
        if policy.get("gitSync") != "deny" or policy.get("networkExport") != "deny":
            fail("plugins/resource-overlay-store.yaml: private overlays must not sync/export", errors)
        if policy.get("atomicWrites") is not True or policy.get("versionHistory") is not True:
            fail("plugins/resource-overlay-store.yaml: atomic writes and version history are required", errors)

    evolution = by_resource.get(("Profile", "resource-evolution-manager"), {}).get("spec", {})
    if evolution:
        merge = evolution.get("mergePolicy") or {}
        apply = evolution.get("applyPolicy") or {}
        if merge.get("neverOverwriteLayers") != ["local-experience-overlay", "private-user-learned-overlay"]:
            fail("profiles/resource-evolution-manager.yaml: learned/local overlays must be protected", errors)
        if merge.get("privateLayersMayPublish") is not False:
            fail("profiles/resource-evolution-manager.yaml: private overlays must never auto-publish", errors)
        if apply.get("atomicActivation") is not True or apply.get("rollbackSnapshot") is not True:
            fail("profiles/resource-evolution-manager.yaml: atomic activation and rollback are required", errors)

    reconcile = by_resource.get(("Cron", "daily-resource-reconcile"), {}).get("spec", {})
    if reconcile:
        policy = reconcile.get("policy") or {}
        if policy.get("autoApply") != "safe-compatible-only":
            fail("crons/daily-resource-reconcile.yaml: only safe compatible changes may auto-apply", errors)
        if policy.get("preserveLocalExperienceOverlay") is not True or policy.get("preservePrivateUserLearnedOverlay") is not True:
            fail("crons/daily-resource-reconcile.yaml: both learned overlays must be preserved", errors)
        if policy.get("publishPrivateOverlays") is not False:
            fail("crons/daily-resource-reconcile.yaml: private overlays must not publish", errors)

    epic = by_resource.get(("Plugin", "epic-kanban"), {}).get("spec", {})
    if epic:
        lifecycle = epic.get("lifecycle") or {}
        if lifecycle.get("createOnEpicStart") is not True or lifecycle.get("deleteAfterAcceptedDone") is not True or lifecycle.get("archiveCompletionSummary") is not True:
            fail("plugins/epic-kanban.yaml: Epic board lifecycle contract must be preserved", errors)

    voice = by_resource.get(("Plugin", "voice-pipeline"), {}).get("spec", {})
    if voice:
        policy = voice.get("policy") or {}
        if policy.get("localFirst") is not True or policy.get("cloudFallback") != "deny" or policy.get("rawAudioRetention") is not False:
            fail("plugins/voice-pipeline.yaml: local-first/no-cloud/no-raw-audio policy must be preserved", errors)
        if (voice.get("textToSpeech") or {}).get("preferred") != "piper":
            fail("plugins/voice-pipeline.yaml: Piper must remain preferred TTS", errors)

    whatsapp = by_resource.get(("Channel", "whatsapp"), {}).get("spec", {})
    if whatsapp:
        integration = whatsapp.get("integration") or {}
        policy = whatsapp.get("policy") or {}
        if integration.get("toolkit") != "whatsapp" or not COMPOSIO_VERSION_RE.fullmatch(str(integration.get("version", ""))):
            fail("channels/whatsapp.yaml: pinned Composio WhatsApp toolkit is required", errors)
        if policy.get("businessAccountsOnly") is not True or policy.get("proactiveOutbound") != "delegated-template-only" or policy.get("accountAdministration") != "deny":
            fail("channels/whatsapp.yaml: Business-only/delegated-template/no-admin policy must be preserved", errors)

    if errors:
        print("Registry validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    counts: dict[str, int] = {}
    for item in resources:
        counts[str(item.get("kind"))] = counts.get(str(item.get("kind")), 0) + 1
    summary = ", ".join(f"{kind}={counts.get(kind, 0)}" for kind in RESOURCE_DIRS)
    print(f"Registry OK: {len(resources)} discovered resources ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
