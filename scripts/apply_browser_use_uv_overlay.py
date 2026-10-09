"""Apply the reviewed ARM64/Python 3.14 uv constraints without changing upstream input."""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path


PLATFORM = "sys_platform == 'linux' and platform_machine == 'aarch64' and python_version == '3.14'"


def apply_overlay(path: Path) -> None:
    original = path.read_text(encoding="utf-8")
    parsed = tomllib.loads(original)
    uv = parsed.get("tool", {}).get("uv")
    if not isinstance(uv, dict):
        raise ValueError("pinned Browser Use source must define a TOML [tool.uv] table")

    additions = []
    for key in ("environments", "required-environments"):
        configured = uv.get(key)
        if configured is None:
            additions.append(f'{key} = ["{PLATFORM}"]')
        elif not isinstance(configured, list) or PLATFORM not in configured:
            raise ValueError(f"existing [tool.uv].{key} requires explicit review before overlay")
    if not additions:
        return

    lines = original.splitlines(keepends=True)
    table = next((index for index, line in enumerate(lines) if line.strip() == "[tool.uv]"), None)
    if table is None:
        raise ValueError("[tool.uv] table could not be located without rewriting the source")
    insert_at = table + 1
    lines[insert_at:insert_at] = [line + "\n" for line in additions]
    output = "".join(lines)
    tomllib.loads(output)
    path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_browser_use_uv_overlay.py PYPROJECT")
    apply_overlay(Path(sys.argv[1]))
