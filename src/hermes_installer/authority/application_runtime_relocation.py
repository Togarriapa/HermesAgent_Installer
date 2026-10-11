"""Pure, finite byte normalization for selected Python app entrypoints.

The root materializer calls these helpers after it has reopened the extracted
archive through the selected generation directory.  This module has no path,
filesystem, process, registry, or publication authority: inputs are already
held member bytes and the selected final interpreter spelling, and outputs are
new bytes plus digest rows for the caller's final tree manifest.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


MAX_SCRIPT_BYTES = 256 * 1024
# Linux shebang interpreters must fit the conservative legacy limit used by
# supported Pi kernels. Count the complete line, including "#!" and newline.
MAX_SHEBANG_LINE_BYTES = 127
BUILD_INTERPRETER = (
    "/run/hermes-installer/build/work/application/runtime-env/bin/python"
)
FINAL_INTERPRETER_MEMBER = "environment/bin/python3.14"
SOURCE_CONSOLE_SCRIPTS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "graphify": MappingProxyType({
        "graphify": "graphify.__main__:main",
        "graphify-mcp": "graphify.serve:_main",
    }),
    "browser-use": MappingProxyType({
        "browser-use": "browser_use.cli:main",
        "browseruse": "browser_use.cli:main",
        "bu": "browser_use.cli:main",
        "browser": "browser_use.cli:main",
        "browser-use-tui": "browser_use.cli:browser_use_tui_main",
    }),
    "scrapegraph-ai": MappingProxyType({}),
})
_SCRIPT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z", re.ASCII)
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z", re.ASCII)
_CALLABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)


class RuntimeRelocationError(ValueError):
    """A member is outside the finite source-owned relocation contract."""


@dataclass(frozen=True, slots=True)
class RelocatedRuntimeMember:
    """Hashes for one source-owned executable rewritten without body changes."""

    path: str
    source_entrypoint: str
    source_entrypoint_sha256: str
    original_sha256: str
    normalized_sha256: str
    size_bytes: int
    mode: int

    def as_wire(self) -> dict[str, object]:
        return {
            "path": self.path,
            "source_entrypoint_sha256": self.source_entrypoint_sha256,
            "original_sha256": self.original_sha256,
            "normalized_sha256": self.normalized_sha256,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
        }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected_wrapper(entrypoint: str) -> ast.Module:
    try:
        module, callable_name = entrypoint.split(":", 1)
    except ValueError:
        raise RuntimeRelocationError("source console entrypoint is malformed") from None
    if not _MODULE.fullmatch(module) or not _CALLABLE.fullmatch(callable_name):
        raise RuntimeRelocationError("source console entrypoint is outside the fixed Python form")
    # uv 0.12.3's pinned POSIX launcher form. AST comparison ignores formatting
    # only; imports, argv handling, guard and source callable match exactly.
    source = (
        "import sys\n"
        f"from {module} import {callable_name}\n"
        "if __name__ == '__main__':\n"
        "    if sys.argv[0].endswith('-script.pyw'):\n"
        "        sys.argv[0] = sys.argv[0][:-11]\n"
        "    elif sys.argv[0].endswith('.exe'):\n"
        "        sys.argv[0] = sys.argv[0][:-4]\n"
        f"    sys.exit({callable_name}())\n"
    )
    try:
        return ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - guarded by the expressions above
        raise RuntimeRelocationError("fixed console wrapper template is invalid") from exc


def _validate_console_script(body: bytes, entrypoint: str) -> None:
    if not isinstance(body, bytes) or not body or len(body) > MAX_SCRIPT_BYTES:
        raise RuntimeRelocationError("selected console script is empty or exceeds its fixed bound")
    try:
        text = body.decode("utf-8")
        parsed = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError):
        raise RuntimeRelocationError("selected console script is not a UTF-8 Python launcher") from None
    expected = _expected_wrapper(entrypoint)
    if ast.dump(parsed, include_attributes=False) != ast.dump(expected, include_attributes=False):
        raise RuntimeRelocationError("selected console script differs from its source-owned entrypoint")


def normalize_console_script_bytes(
    application_id: str,
    member_path: str,
    original: bytes,
    *,
    final_interpreter: str,
    mode: int,
) -> tuple[bytes, RelocatedRuntimeMember]:
    """Rewrite only a pinned script's exact temporary Python shebang.

    ``final_interpreter`` must be the absolute spelling for the selected
    generation's ``environment/bin/python3.14``.  No supplied path is opened.
    The source body is parsed and compared to the exact source-owned callable
    before any bytes are returned.
    """
    if application_id not in SOURCE_CONSOLE_SCRIPTS:
        raise RuntimeRelocationError("application is outside the fixed Python relocation profiles")
    expected = SOURCE_CONSOLE_SCRIPTS[application_id]
    if not isinstance(member_path, str) or not member_path.startswith("environment/bin/"):
        raise RuntimeRelocationError("console script member path is not in the fixed environment bin")
    name = member_path.removeprefix("environment/bin/")
    if (not _SCRIPT_NAME.fullmatch(name) or name not in expected
            or member_path != "environment/bin/" + name):
        raise RuntimeRelocationError("console script name is not selected by pinned source metadata")
    if type(mode) is not int or mode not in {0o555, 0o755}:
        raise RuntimeRelocationError("console script mode is not an immutable executable mode")
    if (not isinstance(original, bytes) or len(original) > MAX_SCRIPT_BYTES):
        raise RuntimeRelocationError("selected console script bytes are malformed or oversized")
    if (not isinstance(final_interpreter, str) or not final_interpreter.startswith("/")
            or any(ch.isspace() or ord(ch) < 0x21 or ord(ch) > 0x7e for ch in final_interpreter)
            or "\\" in final_interpreter or "\x00" in final_interpreter
            or "//" in final_interpreter or "/./" in final_interpreter
            or "/../" in final_interpreter
            or not final_interpreter.endswith("/" + FINAL_INTERPRETER_MEMBER)
            or len(b"#!" + final_interpreter.encode("ascii") + b"\n") > MAX_SHEBANG_LINE_BYTES):
        raise RuntimeRelocationError("selected final interpreter cannot be represented by the fixed shebang")
    first, separator, body = original.partition(b"\n")
    expected_shebang = b"#!" + BUILD_INTERPRETER.encode("ascii")
    if not separator or first != expected_shebang or b"\r" in first:
        raise RuntimeRelocationError("console script shebang does not name the fixed temporary build interpreter")
    _validate_console_script(body, expected[name])
    normalized = b"#!" + final_interpreter.encode("ascii") + b"\n" + body
    receipt = RelocatedRuntimeMember(
        path=member_path,
        source_entrypoint=expected[name],
        source_entrypoint_sha256=_sha(expected[name].encode("ascii")),
        original_sha256=_sha(original),
        normalized_sha256=_sha(normalized),
        size_bytes=len(normalized),
        mode=mode,
    )
    return normalized, receipt


def normalize_selected_python_entrypoints(
    application_id: str,
    members: Mapping[str, tuple[bytes, int]],
    *,
    final_interpreter: str,
) -> tuple[dict[str, tuple[bytes, int]], tuple[RelocatedRuntimeMember, ...]]:
    """Return copied runtime members with only selected console shebangs changed.

    ``members`` is a root-reopened subset keyed by canonical archive member
    path and carrying ``(bytes, normalized_mode)``.  It must contain precisely
    the console scripts selected by the app's pinned source entrypoints; an
    empty source script set stays empty (ScrapeGraphAI has no invented CLI).
    Other archive members are neither read nor changed by this pure helper.
    """
    expected = SOURCE_CONSOLE_SCRIPTS.get(application_id)
    if expected is None:
        raise RuntimeRelocationError("application is outside the fixed Python relocation profiles")
    if not isinstance(members, Mapping):
        raise RuntimeRelocationError("root-selected script member set is malformed")
    expected_paths = {"environment/bin/" + name for name in expected}
    if set(members) != expected_paths:
        raise RuntimeRelocationError("console script members differ from pinned source metadata")
    normalized: dict[str, tuple[bytes, int]] = {}
    rows: list[RelocatedRuntimeMember] = []
    for path in sorted(expected_paths):
        item = members[path]
        if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], bytes)
                or type(item[1]) is not int):
            raise RuntimeRelocationError("root-selected script bytes or mode are malformed")
        result, receipt = normalize_console_script_bytes(
            application_id, path, item[0], final_interpreter=final_interpreter, mode=item[1])
        normalized[path] = (result, item[1])
        rows.append(receipt)
    return normalized, tuple(rows)


@dataclass(frozen=True, slots=True)
class RelocatedPyvenvConfig:
    """Observed config rewrite from held builder PM base to final PM base."""

    original_sha256: str
    normalized_sha256: str
    original_size_bytes: int
    normalized_size_bytes: int
    original_home: str
    normalized_home: str

    def as_wire(self) -> dict[str, object]:
        return {
            "original_sha256": self.original_sha256,
            "normalized_sha256": self.normalized_sha256,
            "original_size_bytes": self.original_size_bytes,
            "normalized_size_bytes": self.normalized_size_bytes,
            "original_home": self.original_home,
            "normalized_home": self.normalized_home,
        }


def normalize_selected_pyvenv_config(
    original: bytes,
    *,
    expected_base_bin: str,
    final_base_bin: str,
    python_version: str,
    uv_version: str = "0.12.3",
) -> tuple[bytes, RelocatedPyvenvConfig]:
    """Rewrite only uv 0.12.3's measured ``home`` field.

    The two absolute paths come from current root-held PM and final-generation
    selections. All other bytes and key order must equal the measured template.
    This pure function does not open or resolve paths.
    """
    def canonical_path(value: str) -> bool:
        return (isinstance(value, str) and value.startswith("/") and value != "/"
                and value == value.rstrip("/")
                and all(part not in {"", ".", ".."} for part in value[1:].split("/"))
                and all(0x21 <= ord(ch) <= 0x7e for ch in value)
                and "\\" not in value)

    if (not isinstance(original, bytes) or not canonical_path(expected_base_bin)
            or not canonical_path(final_base_bin) or not isinstance(python_version, str)
            or not re.fullmatch(r"3\.14\.[0-9]+", python_version, re.ASCII)
            or uv_version != "0.12.3"):
        raise RuntimeRelocationError("selected Python base/config identity is malformed")
    prefix = (
        "implementation = CPython\n"
        f"uv = {uv_version}\n"
        f"version_info = {python_version}\n"
        "include-system-site-packages = false\n"
    )
    expected = f"home = {expected_base_bin}\n".encode("ascii") + prefix.encode("ascii")
    if original != expected:
        raise RuntimeRelocationError("pyvenv.cfg differs from the observed fixed uv template")
    normalized = f"home = {final_base_bin}\n".encode("ascii") + prefix.encode("ascii")
    return normalized, RelocatedPyvenvConfig(
        original_sha256=_sha(original), normalized_sha256=_sha(normalized),
        original_size_bytes=len(original), normalized_size_bytes=len(normalized),
        original_home=expected_base_bin, normalized_home=final_base_bin,
    )
