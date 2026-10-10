"""Strict lock inventory helpers for pre-active application runtimes.

This module intentionally does not treat a lockfile as proof that packages
were acquired, licensed, or installed. It identifies the exact compatible
wheel bytes a later root-held package receipt must acquire and inspect.
"""
from __future__ import annotations

import ast
import hashlib
import re
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping


_MAX_LOCK_BYTES = 16 * 1024 * 1024
_MAX_LOCK_PACKAGES = 8192
_MAX_MARKER_DEPTH = 32
_TARGET_GLIBC_MINOR = 36
_PYTHON_LOCK_APPS = frozenset({"graphify", "browser-use", "scrapegraph-ai"})
_MARKER_ENV = {
    "python_version": "3.14",
    "python_full_version": "3.14.0",
    "implementation_name": "cpython",
    "platform_python_implementation": "CPython",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "platform_machine": "aarch64",
    "os_name": "posix",
    "extra": "",
}


class ApplicationRuntimePreparationDenied(PermissionError):
    """A selected lock cannot be mapped to a finite Linux ARM64 wheel closure."""


@dataclass(frozen=True, slots=True)
class LockedPythonWheel:
    package_name: str
    package_version: str
    url: str
    integrity_algorithm: str
    integrity_digest: str
    size_bytes: int
    wheel_filename: str
    selected_tag: str


@dataclass(frozen=True, slots=True)
class LockedPythonWheelSelection:
    application_id: str
    lock_sha256: str
    environment: tuple[tuple[str, str], ...]
    wheels: tuple[LockedPythonWheel, ...]
    blockers: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.blockers


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate lock key")
        result[key] = value
    return result


def _norm_name(value: Any) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)):
        raise ValueError
    return re.sub(r"[-_.]+", "-", value).lower()


def _version_key(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", value):
        raise ValueError
    return tuple(int(item) for item in value.split("."))


def _marker_value(node: ast.AST, *, depth: int = 0) -> str:
    if depth > _MAX_MARKER_DEPTH:
        raise ValueError
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in _MARKER_ENV:
        return _MARKER_ENV[node.id]
    raise ValueError


def _marker_compare(left: str, op: ast.cmpop, right: str) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
        if left.startswith("3.") and right[:1].isdigit():
            a, b = _version_key(left), _version_key(right)
            a = a + (0,) * (4 - len(a))
            b = b + (0,) * (4 - len(b))
        else:
            a, b = left, right
        if isinstance(op, ast.Lt):
            return a < b
        if isinstance(op, ast.LtE):
            return a <= b
        if isinstance(op, ast.Gt):
            return a > b
        return a >= b
    raise ValueError


def _eval_marker(expression: Any) -> bool:
    if expression is None:
        return True
    if not isinstance(expression, str) or len(expression) > 4096:
        raise ValueError
    root = ast.parse(expression, mode="eval").body

    def visit(node: ast.AST, depth: int = 0) -> bool:
        if depth > _MAX_MARKER_DEPTH:
            raise ValueError
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [visit(item, depth + 1) for item in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand, depth + 1)
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators):
            left = _marker_value(node.left, depth=depth + 1)
            for op, right_node in zip(node.ops, node.comparators):
                right = _marker_value(right_node, depth=depth + 1)
                if not _marker_compare(left, op, right):
                    return False
                left = right
            return True
        raise ValueError

    return visit(root)


def _wheel_tag(filename: str) -> tuple[str, str] | None:
    if not filename.endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return None
    python_tag, abi_tag, platform_tag = parts[-3:]
    pythons = python_tag.split(".")
    abis = abi_tag.split(".")
    platforms = platform_tag.split(".")
    best: tuple[int, str] | None = None
    for py in pythons:
        for abi in abis:
            for platform in platforms:
                compatible = (
                    (py == "cp314" and abi == "cp314"
                     and _manylinux_aarch64_compatible(platform))
                    or (_stable_abi_python_tag(py) and abi == "abi3"
                        and _manylinux_aarch64_compatible(platform))
                    or (py in {"py3", "py2.py3"} and abi == "none"
                        and platform == "any")
                )
                if compatible:
                    rank = 0 if platform != "any" else 1
                    tag = f"{py}-{abi}-{platform}"
                    if best is None or rank < best[0]:
                        best = rank, tag
    return None if best is None else (best[1], parts[0])


def _stable_abi_python_tag(tag: str) -> bool:
    match = re.fullmatch(r"cp3([0-9]+)", tag)
    return match is not None and 2 <= int(match.group(1)) <= 14


def _manylinux_aarch64_compatible(platform: str) -> bool:
    if platform == "manylinux2014_aarch64":
        return True
    match = re.fullmatch(r"manylinux_2_([0-9]+)_aarch64", platform)
    return (match is not None and 17 <= int(match.group(1)) <= _TARGET_GLIBC_MINOR)


def _wheel_matches_package(filename: str, package: Mapping[str, Any]) -> bool:
    parts = filename[:-4].split("-") if filename.endswith(".whl") else []
    if len(parts) < 5:
        return False
    try:
        return (_norm_name(parts[0]) == _norm_name(package.get("name"))
                and parts[1] == package.get("version"))
    except ValueError:
        return False


def _wheel_row(package: Mapping[str, Any]) -> LockedPythonWheel | None:
    candidates: list[tuple[int, LockedPythonWheel]] = []
    for wheel in package.get("wheels", ()):
        if not isinstance(wheel, dict) or set(wheel) - {"url", "hash", "size", "upload-time"}:
            continue
        url, integrity, size = wheel.get("url"), wheel.get("hash"), wheel.get("size")
        if (not isinstance(url, str) or not isinstance(integrity, str)
                or type(size) is not int or size <= 0 or size > 2 * 1024**3):
            continue
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org"
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)):
            continue
        match = re.fullmatch(r"sha256:([0-9a-f]{64})", integrity)
        if match is None:
            continue
        filename = PurePosixPath(parsed.path).name
        tag = _wheel_tag(filename)
        if tag is None or not _wheel_matches_package(filename, package):
            continue
        rank = 0 if tag[0].split("-")[0] == "cp314" else 1
        candidates.append((rank, LockedPythonWheel(
            _norm_name(package.get("name")), package.get("version"), url,
            "sha256", match.group(1), size, filename, tag[0])))
    if not candidates:
        return None
    candidates.sort(key=lambda row: (row[0], row[1].wheel_filename, row[1].url))
    return candidates[0][1]


def select_locked_python_wheels(lock_bytes: bytes, *, application_id: str) -> LockedPythonWheelSelection:
    """Resolve only default transitive deps and select exact Python 3.14 ARM64 wheels.

    Source builds, malformed markers, ambiguous duplicate package versions,
    custom indexes, non-SHA256 integrity, and missing compatible wheels remain
    explicit blockers. This function issues no artifact or license receipt.
    """
    if (application_id not in _PYTHON_LOCK_APPS or not isinstance(lock_bytes, bytes)
            or not 1 <= len(lock_bytes) <= _MAX_LOCK_BYTES):
        raise ApplicationRuntimePreparationDenied("application lock is outside the fixed Python profile contract")
    digest = hashlib.sha256(lock_bytes).hexdigest()
    try:
        document = tomllib.loads(lock_bytes.decode("utf-8"))
        packages = document.get("package")
        if (type(document.get("version")) is not int or document["version"] != 1
                or not isinstance(packages, list) or not 1 <= len(packages) <= _MAX_LOCK_PACKAGES):
            raise ValueError
        by_name: dict[str, list[Mapping[str, Any]]] = {}
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("version"), str):
                raise ValueError
            name = _norm_name(package.get("name"))
            source = package.get("source")
            if not isinstance(source, dict):
                raise ValueError
            by_name.setdefault(name, []).append(package)
        roots = [row for rows in by_name.values() for row in rows
                 if row.get("source") == {"editable": "."}]
        if len(roots) != 1:
            raise ValueError
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError, TypeError):
        raise ApplicationRuntimePreparationDenied("selected uv lock has an unsupported or malformed schema") from None

    selected: dict[str, Mapping[str, Any]] = {}
    pending = [roots[0]]
    blockers: set[str] = set()
    while pending:
        package = pending.pop()
        name = _norm_name(package.get("name"))
        if name in selected:
            continue
        selected[name] = package
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            blockers.add(f"{name}:malformed-dependencies")
            continue
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                blockers.add(f"{name}:malformed-dependency-row")
                continue
            try:
                if not _eval_marker(dependency.get("marker")):
                    continue
                child_name = _norm_name(dependency.get("name"))
            except (ValueError, SyntaxError):
                blockers.add(f"{name}:unsupported-marker")
                continue
            candidates = by_name.get(child_name, [])
            # Multiple versions need a reviewed marker-to-version selection;
            # never pick an arbitrary lock candidate.
            if len(candidates) != 1:
                blockers.add(f"{child_name}:ambiguous-lock-version" if candidates
                             else f"{child_name}:missing-lock-package")
                continue
            pending.append(candidates[0])

    results: list[LockedPythonWheel] = []
    for name, package in sorted(selected.items()):
        if package is roots[0]:
            continue
        source = package.get("source")
        if source != {"registry": "https://pypi.org/simple"}:
            blockers.add(f"{name}:non-pypi-source")
            continue
        wheel = _wheel_row(package)
        if wheel is None:
            blockers.add(f"{name}:no-compatible-cp314-aarch64-wheel")
            continue
        results.append(wheel)
    return LockedPythonWheelSelection(
        application_id, digest, tuple(sorted(_MARKER_ENV.items())),
        tuple(results), tuple(sorted(blockers)))
