#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from copy import deepcopy
from pathlib import Path

import yaml

from registry_lib import ROOT, catalog, discover_resources, effective_spec, load_quality_policy, quality_policy_files, resolve_inherited_spec

DEFAULT_OUTPUT = ROOT / "build" / "effective-registry"


def materialize(item: dict, resources: list[dict], policy: dict) -> dict:
    doc = deepcopy(item["doc"])
    metadata = doc.get("metadata") or {}
    tags_raw = metadata.get("tags") or []
    tags = set(tags_raw) if isinstance(tags_raw, list) else set()
    resolved = resolve_inherited_spec(item, resources)
    effective, overlays = effective_spec(str(item["kind"]), str(item["name"]), tags, resolved, policy)
    doc["spec"] = effective
    doc["materialization"] = {
        "catalogVersion": str((catalog().get("metadata") or {}).get("version")),
        "qualityPolicyFiles": [path.relative_to(ROOT).as_posix() for path in quality_policy_files()],
        "qualityDomainOverlays": overlays,
        "declaredManifest": item["rel"],
        "inheritanceResolved": True,
        "secretsResolved": False,
        "authorizationExpanded": False,
        "hostAuthorizationApplied": False,
    }
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize effective Hermes registry resources with inheritance and restrictive quality policy applied.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    resources = discover_resources()
    policy = load_quality_policy()
    rendered: list[tuple[dict, dict]] = []
    for item in resources:
        rendered.append((item, materialize(item, resources, policy)))

    if args.check_only:
        print(f"Materialization OK: {len(rendered)} discovered resources; inheritance resolved; secrets unresolved; host authorization not expanded")
        return 0

    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    for item, doc in rendered:
        target = output / item["rel"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    (output / "catalog.yaml").write_text(yaml.safe_dump(catalog(), sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Materialized {len(rendered)} resources under {output.relative_to(ROOT) if output.is_relative_to(ROOT) else output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
