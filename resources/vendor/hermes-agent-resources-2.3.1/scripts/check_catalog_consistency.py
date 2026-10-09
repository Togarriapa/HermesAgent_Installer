#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from registry_lib import RESOURCE_DIRS, ROOT, catalog, discover_resources


def registry_rows(resources):
    return sorted(
        f"{item['kind']}|{item['name']}|{item['version']}|{item['rel']}"
        for item in resources
    )


def digest_rows(rows):
    return hashlib.sha256(("\n".join(rows) + "\n").encode("utf-8")).hexdigest()


def main() -> int:
    errors: list[str] = []
    try:
        cat = catalog()
        resources = discover_resources()
    except (OSError, ValueError) as exc:
        print(f"Catalog consistency failed: {exc}", file=sys.stderr)
        return 1

    discovery = (cat.get("spec") or {}).get("discovery") or {}
    if discovery.get("mode") != "manifest-roots":
        errors.append("catalog discovery.mode must be manifest-roots")
    if discovery.get("recursive") is not False:
        errors.append("catalog discovery.recursive must remain false until recursive discovery is explicitly supported")
    roots = discovery.get("roots") or {}
    if roots != RESOURCE_DIRS:
        errors.append(f"catalog discovery roots must exactly match canonical roots: {RESOURCE_DIRS}")
    if discovery.get("canonicalIdentity") != "metadata":
        errors.append("catalog canonicalIdentity must be metadata")
    if discovery.get("manifestPattern") != "*.yaml":
        errors.append("catalog manifestPattern must be *.yaml")

    identities: set[tuple[str, str, str]] = set()
    rels: set[str] = set()
    counts = {kind: 0 for kind in RESOURCE_DIRS}
    for item in resources:
        ident = (str(item.get("kind")), str(item.get("name")), str(item.get("version")))
        if ident in identities:
            errors.append(f"duplicate discovered identity: {ident}")
        identities.add(ident)
        rel = str(item.get("rel"))
        if rel in rels:
            errors.append(f"duplicate discovered path: {rel}")
        rels.add(rel)
        if item.get("kind") in counts:
            counts[item["kind"]] += 1

    policy_files = (cat.get("spec") or {}).get("qualityPolicyFiles") or []
    if not isinstance(policy_files, list) or not policy_files:
        errors.append("catalog must declare at least one qualityPolicyFiles entry")
    else:
        for rel in policy_files:
            if not (ROOT / str(rel)).is_file():
                errors.append(f"missing quality policy file: {rel}")

    rows = registry_rows(resources)
    digest = digest_rows(rows)
    summary = {
        "catalogVersion": (cat.get("metadata") or {}).get("version"),
        "resourceCount": len(resources),
        "counts": counts,
        "resourceDigestSha256": digest,
    }
    print(json.dumps(summary, sort_keys=True))

    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as handle:
            handle.write("## Registry catalog consistency\n\n")
            handle.write(f"- Catalog: `{summary['catalogVersion']}`\n")
            handle.write(f"- Resources: **{summary['resourceCount']}**\n")
            handle.write(f"- Digest: `{digest}`\n")
            handle.write("- Counts: " + ", ".join(f"{k}={v}" for k, v in counts.items()) + "\n")

    if errors:
        print("Catalog consistency failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
