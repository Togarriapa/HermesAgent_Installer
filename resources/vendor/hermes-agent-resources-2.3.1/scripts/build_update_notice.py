#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from registry_lib import RESOURCE_DIRS, catalog, discover_resources


def git(*args: str) -> str:
    return subprocess.check_output(("git",) + args, text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="registry-update.json")
    args = parser.parse_args()
    resources = discover_resources()
    rows = sorted(f"{r['kind']}|{r['name']}|{r['version']}|{r['rel']}" for r in resources)
    digest = hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()
    counts = {kind: 0 for kind in RESOURCE_DIRS}
    for resource in resources:
        if resource.get("kind") in counts:
            counts[resource["kind"]] += 1
    try:
        changed = [line for line in git("diff-tree", "--no-commit-id", "--name-status", "-r", "HEAD").splitlines() if line]
    except subprocess.CalledProcessError:
        changed = []
    payload = {
        "schemaVersion": 1,
        "event": "registry-update-available",
        "repository": "Togarriapa/HermesAgent_Resources",
        "ref": "main",
        "commit": git("rev-parse", "HEAD"),
        "catalogVersion": (catalog().get("metadata") or {}).get("version"),
        "resourceDigestSha256": digest,
        "resourceCount": len(resources),
        "counts": counts,
        "changed": changed,
    }
    path = Path(args.output)
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(path.read_text(encoding="utf-8").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
