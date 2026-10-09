#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from registry_lib import RESOURCE_DIRS, discover_resources


def join(values):
    return ", ".join(str(v) for v in values) if values else "—"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a current manifest-derived registry reference.")
    parser.add_argument("--output", help="Write Markdown to a file instead of stdout")
    args = parser.parse_args()
    resources = discover_resources()
    lines = ["# Manifest-derived Registry Reference", "", "This reference is generated from the current YAML manifests; it is not a second source of truth.", "", "## Profiles", "", "| Profile | Version | Skills | Plugins | MCPs |", "| --- | --- | --- | --- | --- |"]
    profiles = sorted((r for r in resources if r.get("kind") == "Profile"), key=lambda r: str(r.get("name")))
    for item in profiles:
        spec = (item.get("doc") or {}).get("spec") or {}
        req = spec.get("requires") or {}
        lines.append(f"| `{item['name']}` | `{item['version']}` | {join(req.get('skills') or [])} | {join(req.get('plugins') or [])} | {join(req.get('mcps') or [])} |")
    lines += ["", "## Integration and event resources", "", "| Kind | Name | Version | Purpose |", "| --- | --- | --- | --- |"]
    for item in sorted((r for r in resources if r.get("kind") in {"Plugin", "MCP", "Channel", "Cron", "Webhook"}), key=lambda r: (str(r.get("kind")), str(r.get("name")))):
        desc = str(((item.get("doc") or {}).get("metadata") or {}).get("description") or "").replace("|", "\\|")
        lines.append(f"| {item['kind']} | `{item['name']}` | `{item['version']}` | {desc} |")
    lines += ["", "## Counts", ""]
    counts = {kind: sum(1 for r in resources if r.get("kind") == kind) for kind in RESOURCE_DIRS}
    lines.append(", ".join(f"{kind}={count}" for kind, count in counts.items()))
    text = "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
