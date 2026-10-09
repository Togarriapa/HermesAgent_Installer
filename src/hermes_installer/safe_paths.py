"""Narrow path normalization for the two Darwin system temporary aliases."""
from __future__ import annotations

import platform
from pathlib import Path


def canonicalize_darwin_temp_alias(path: Path) -> Path:
    """Canonicalize only Apple's documented ``/tmp`` and ``/var`` aliases.

    Other symlink components are deliberately left untouched so callers can
    continue rejecting them with their existing descriptor/path checks.
    """
    path = Path(path)
    if platform.system() != "Darwin" or not path.is_absolute():
        return path
    aliases = {
        "tmp": Path("/private/tmp"),
        "var": Path("/private/var"),
    }
    parts = path.parts
    if len(parts) < 2 or parts[1] not in aliases:
        return path
    alias = Path("/") / parts[1]
    if not alias.is_symlink():
        return path
    expected = aliases[parts[1]]
    try:
        actual = alias.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Darwin temporary directory alias is unavailable") from exc
    if actual != expected:
        raise ValueError("unexpected Darwin temporary directory alias target")
    return expected.joinpath(*parts[2:])
