#!/usr/bin/env python3
"""Fixed-function rollback transport for one retained failed Core cohort.

There are no caller-selected source, code, function, target, credential, or
operation arguments. Reviewed fix-source pins remain a fail-closed build-time
constant until Root seals the reviewed Core artifact.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from types import FunctionType, ModuleType

_FAILED_COMMIT = "c91b4f4ba1a7f2652cf21fb598f3ad2338849a18"
_FAILED_ARCHIVE_SHA256 = "e855f96f349527e97993d5d303ede313ff72e932298b02333358190e723bdc42"
_FAILED_CORE_SHA256 = "6992eb4eed8eb4397fc9e330a60edeec7b0025a55a6fa0b57660549738d6266e"
_FIX_COMMIT = "577333cbe30d3ce7f1dde465528560586756b7e3"
_FIX_ARCHIVE_SHA256 = "82eee1a1dcdaeafb39ca2f783298d1fa76ebde9d2f4cb94a4ec476c316a3b0b3"
_FIX_CORE_SHA256 = "e9e0a47911a7b9df24194d20b07cadf33e94d9b1cf5135d7e7de3dc28826eaf5"
_FIX_CORE_FILENAME = "/opt/hermes-installer-core-577333cbe/src/hermes_installer/core_runtime.py"
_FIX_FUNCTIONS = (
    ("_check_adapter_cohort_rollback_currentness", ("cohort", "prior", "contents")),
    ("_verify_absent_initial_primary_rollback", ("cohort", "initial")),
)
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 1024


class RecoveryTransportDenied(RuntimeError):
    """Fixed fail-closed error; callers must not expose an underlying message."""


def _validate_pins() -> None:
    fixed = ((_FAILED_COMMIT, 40), (_FAILED_ARCHIVE_SHA256, 64),
             (_FAILED_CORE_SHA256, 64), (_FIX_COMMIT, 40),
             (_FIX_ARCHIVE_SHA256, 64), (_FIX_CORE_SHA256, 64))
    if any(type(value) is not str or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None
           for value, length in fixed) or _FAILED_COMMIT == _FIX_COMMIT:
        raise RecoveryTransportDenied("reviewed recovery source pins are unavailable")


def _source_directory(commit: str) -> Path:
    if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RecoveryTransportDenied("fixed source identity is malformed")
    return Path(f"/opt/hermes-installer-core-{commit[:9]}")


def _read_root_file(generation: Path, relative: str, *, maximum: int,
                    mode: int | None = None,
                    under_source: bool = True) -> tuple[bytes, tuple[int, ...]]:
    """Read a fixed relative file through Root-owned, no-follow descriptors."""
    parts = Path(relative).parts
    if (not parts or Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in parts)
            or len(parts) > 4 or type(maximum) is not int or maximum < 1):
        raise RecoveryTransportDenied("fixed source path is malformed")
    root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                      | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    opened: list[int] = []
    file_fd = None
    try:
        parent = root_fd
        prefix = (*generation.parts[1:], *(('src',) if under_source else ()), *parts[:-1])
        for component in prefix:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                            dir_fd=parent)
            opened.append(child)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RecoveryTransportDenied("fixed source directory custody differs")
            parent = child
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        before = os.fstat(file_fd)
        named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        signature = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                     before.st_gid, before.st_nlink, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum
                or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
                or signature != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                                 named.st_gid, named.st_nlink, named.st_size,
                                 named.st_mtime_ns, named.st_ctime_ns)):
            raise RecoveryTransportDenied("fixed source file custody differs")
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(file_fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(file_fd)
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        after_signature = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                           after.st_gid, after.st_nlink, after.st_size,
                           after.st_mtime_ns, after.st_ctime_ns)
        if (len(raw) != before.st_size or after_signature != signature
                or after_signature != (current.st_dev, current.st_ino, current.st_mode,
                                       current.st_uid, current.st_gid, current.st_nlink,
                                       current.st_size, current.st_mtime_ns,
                                       current.st_ctime_ns)):
            raise RecoveryTransportDenied("fixed source changed during read")
        return bytes(raw), signature
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def _verify_source_receipt(generation: Path, *, commit: str, archive_sha256: str,
                           core_sha256: str) -> tuple[bytes, tuple[int, ...]]:
    receipt_raw, _receipt_signature = _read_root_file(
        generation, ".source-provenance.json", maximum=_MAX_RECEIPT_BYTES, mode=0o444,
        under_source=False)
    try:
        receipt = json.loads(receipt_raw.decode("utf-8", "strict"),
                             object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, TypeError):
        raise RecoveryTransportDenied("fixed source receipt is malformed") from None
    if (type(receipt) is not dict or set(receipt) != {"schema", "source_commit", "archive_sha256"}
            or type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or receipt.get("source_commit") != commit
            or receipt.get("archive_sha256") != archive_sha256
            or _canonical_json(receipt) != receipt_raw):
        raise RecoveryTransportDenied("fixed source receipt differs")
    source, signature = _read_root_file(
        generation, "hermes_installer/core_runtime.py", maximum=_MAX_SOURCE_BYTES,
        mode=0o644)
    if hashlib.sha256(source).hexdigest() != core_sha256:
        raise RecoveryTransportDenied("fixed Core source digest differs")
    return source, signature


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _definition_code_objects(source: bytes, *, expected_sha256: str) -> tuple[object, object]:
    """Parse pinned source, compiling only the two fixed top-level definitions."""
    if (type(source) is not bytes or not 1 <= len(source) <= _MAX_SOURCE_BYTES
            or type(expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or hashlib.sha256(source).hexdigest() != expected_sha256):
        raise RecoveryTransportDenied("reviewed recovery source identity differs")
    try:
        tree = ast.parse(source.decode("utf-8", "strict"),
                         filename="hermes_installer/core_runtime.py", mode="exec")
    except (SyntaxError, UnicodeError, ValueError, TypeError):
        raise RecoveryTransportDenied("reviewed recovery source is malformed") from None
    code_objects = []
    for name, parameters in _FIX_FUNCTIONS:
        found = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name == name]
        if len(found) != 1 or type(found[0]) is not ast.FunctionDef:
            raise RecoveryTransportDenied("reviewed recovery definition count differs")
        node = found[0]
        args = node.args
        argument_nodes = (*args.posonlyargs, *args.args, *args.kwonlyargs)
        if (tuple(arg.arg for arg in args.args) != parameters or args.posonlyargs
                or args.vararg is not None or args.kwonlyargs or args.kwarg is not None
                or args.defaults or args.kw_defaults or node.decorator_list
                or node.returns is not None or node.type_comment is not None
                or any(arg.annotation is not None for arg in argument_nodes)
                or getattr(node, "type_params", ())):
            raise RecoveryTransportDenied("reviewed recovery definition shape differs")
        isolated = ast.Module(body=[node], type_ignores=[])
        ast.fix_missing_locations(isolated)
        try:
            namespace = {"__builtins__": __builtins__}
            exec(compile(isolated, _FIX_CORE_FILENAME, "exec"), namespace)
            function = namespace.get(name)
            code = getattr(function, "__code__", None)
        except (SyntaxError, TypeError, ValueError, MemoryError):
            raise RecoveryTransportDenied("reviewed recovery definition did not compile") from None
        if (type(function) is not FunctionType or code is None or code.co_name != name
                or code.co_freevars or code.co_argcount != len(parameters)
                or code.co_kwonlyargcount != 0 or function.__defaults__ is not None
                or code.co_filename != _FIX_CORE_FILENAME):
            raise RecoveryTransportDenied("reviewed recovery code object differs")
        code_objects.append(code)
    return tuple(code_objects)


def _restore_with_transported_functions(core_module: ModuleType, code_objects: tuple[object, object],
                                        target_guard) -> object:
    """Call the unchanged API once, restoring only two function bindings in finally."""
    if (type(core_module) is not ModuleType or type(code_objects) is not tuple
            or len(code_objects) != 2 or not callable(target_guard)):
        raise RecoveryTransportDenied("fixed failed Core transport input differs")
    namespace = core_module.__dict__
    names = tuple(name for name, _parameters in _FIX_FUNCTIONS)
    saved = {name: (name in namespace, namespace.get(name)) for name in names}
    prior_bindings = {name: id(value) for name, value in namespace.items() if name not in names}
    old_check = saved[names[0]][1]
    if type(old_check) is not FunctionType:
        raise RecoveryTransportDenied("failed Core currentness binding is unavailable")
    check_impl = FunctionType(code_objects[0], namespace, names[0])
    helper_impl = FunctionType(code_objects[1], namespace, names[1])

    def guarded_check(cohort, prior, contents):
        target_guard(cohort, prior, contents)
        return check_impl(cohort, prior, contents)

    namespace[names[0]] = guarded_check
    namespace[names[1]] = helper_impl
    try:
        api = namespace.get("restore_owned_core_adapter_update")
        if type(api) is not FunctionType:
            raise RecoveryTransportDenied("fixed failed Core restore API is unavailable")
        return api()
    finally:
        if saved[names[0]][0]:
            namespace[names[0]] = saved[names[0]][1]
        else:
            namespace.pop(names[0], None)
        if saved[names[1]][0]:
            namespace[names[1]] = saved[names[1]][1]
        else:
            namespace.pop(names[1], None)
        if {name: id(value) for name, value in namespace.items() if name not in names} != prior_bindings:
            raise RecoveryTransportDenied("failed Core authority bindings changed")


def _source_snapshot(commit: str, archive_sha256: str, core_sha256: str):
    generation = _source_directory(commit)
    source_bytes, file_signature = _verify_source_receipt(
        generation, commit=commit, archive_sha256=archive_sha256,
        core_sha256=core_sha256)
    receipt_bytes, receipt_signature = _read_root_file(
        generation, ".source-provenance.json", maximum=_MAX_RECEIPT_BYTES,
        mode=0o444, under_source=False)
    return generation / "src", source_bytes, file_signature, receipt_bytes, receipt_signature


def _load_failed_core(source_root: Path):
    if "hermes_installer" in sys.modules:
        raise RecoveryTransportDenied("unexpected Core package was loaded")
    sys.path.insert(0, str(source_root))
    try:
        from hermes_installer import core_runtime
        from hermes_installer.remote import core_gateway_inspector as inspector
    except Exception:
        raise RecoveryTransportDenied("failed Core could not be loaded") from None
    if (type(core_runtime) is not ModuleType
            or Path(core_runtime.__file__).resolve(strict=True)
            != (source_root / "hermes_installer" / "core_runtime.py").resolve(strict=True)
            or core_runtime.ADAPTER_SOURCE != source_root
            or type(inspector) is not ModuleType
            or Path(inspector.__file__).resolve(strict=True)
            != (source_root / "hermes_installer" / "remote" / "core_gateway_inspector.py").resolve(strict=True)
            or inspector.CORE_NATIVE_ADAPTER_SOURCE != source_root):
        raise RecoveryTransportDenied("failed Core source identity differs")
    return core_runtime


def _read_retained_ingress(core_module) -> tuple[bytes, dict]:
    raw = core_module._projection_file(
        core_module.NATIVE_ADOPTION_INGRESS_BACKUP, owner=core_module.ROOT_UID,
        group=core_module.ROOT_UID, mode=0o600, maximum=128 * 1024)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, TypeError):
        raise RecoveryTransportDenied("retained ingress receipt is malformed") from None
    return raw, value


def _capture_exact_target(core_module) -> dict:
    """Capture the one recovery-required cohort; the restore API rechecks it under lock."""
    try:
        cohort, cohort_raw = core_module._read_adapter_update_cohort()
        ingress_raw, ingress = _read_retained_ingress(core_module)
        refresh = ingress.get("adapter_refresh") if type(ingress) is dict else None
        if (type(cohort) is not dict or type(refresh) is not dict
                or ingress.get("state") != "recovery-required"
                or ingress.get("candidate_sha") != _FAILED_COMMIT
                or cohort.get("phase") != "rolling-back"
                or cohort.get("new_source") != str(core_module.ADAPTER_SOURCE)
                or cohort.get("new_source") != str(_source_directory(_FAILED_COMMIT) / "src")):
            raise RecoveryTransportDenied("retained recovery target differs")
        joins = (refresh.get("core_update_backup_reference"),
                 refresh.get("core_update_cohort_transaction_id"),
                 refresh.get("core_update_cohort_sha256"))
        if not all(value is None for value in joins):
            if (any(value is None for value in joins)
                    or joins[0] != core_module._adapter_update_backup_reference(cohort)
                    or joins[1] != cohort.get("cohort_transaction_id")
                    or type(joins[2]) is not str):
                raise RecoveryTransportDenied("retained recovery joins are partial or differ")
            if (core_module._retained_committed_adapter_cohort_sha256(cohort, cohort_raw)
                    != joins[2]):
                raise RecoveryTransportDenied("retained recovery cohort digest differs")
        return {"cohort": cohort, "cohort_raw": cohort_raw,
                "ingress_raw": ingress_raw, "refresh": refresh}
    except RecoveryTransportDenied:
        raise
    except Exception:
        raise RecoveryTransportDenied("retained recovery target is unavailable") from None


def _target_guard(core_module, target: dict, failed_source, fix_source):
    """Build the sole inline guard used under the Core API's already-held lock."""
    namespace = core_module.__dict__
    protected_bindings = {name: id(value) for name, value in namespace.items()
                          if name not in {name for name, _ in _FIX_FUNCTIONS}}

    def check(cohort, prior, contents):
        try:
            if core_module._ADAPTER_UPDATE_LOCK_HELD.get() is not True:
                raise RecoveryTransportDenied("recovery lock is not held")
            if ({name: id(value) for name, value in namespace.items()
                 if name not in {name for name, _ in _FIX_FUNCTIONS}} != protected_bindings):
                raise RecoveryTransportDenied("failed Core authority bindings changed")
            current_cohort, current_raw = core_module._read_adapter_update_cohort()
            ingress_raw, ingress = _read_retained_ingress(core_module)
            if (current_raw != target["cohort_raw"] or current_cohort != target["cohort"]
                    or ingress_raw != target["ingress_raw"]):
                raise RecoveryTransportDenied("retained recovery target changed")
            if (cohort != target["cohort"]
                    or type(prior) is not dict or type(contents) is not dict
                    or hashlib.sha256(contents.get("journal.json", b"")).hexdigest()
                       != target["refresh"].get("old_core_journal_sha256")
                    or prior.get("adapter_source")
                       != target["refresh"].get("old_core_adapter_source")
                    or prior.get("adapter_generation")
                       != target["refresh"].get("old_core_adapter_generation")
                    or prior.get("core_source_generation")
                       != target["refresh"].get("old_core_source_generation")):
                raise RecoveryTransportDenied("retained prior Core tuple changed")
            if (ingress.get("candidate_sha") != _FAILED_COMMIT
                    or ingress.get("state") != "recovery-required"):
                raise RecoveryTransportDenied("retained ingress identity changed")
            _recheck_source_snapshot(failed_source)
            _recheck_source_snapshot(fix_source)
            inspector = sys.modules.get("hermes_installer.remote.core_gateway_inspector")
            if type(inspector) is not ModuleType:
                raise RecoveryTransportDenied("failed Core source verifier is unavailable")
            generation = inspector._current_native_adapter_generation(
                deadline=time.monotonic() + 35.0)
            if generation != cohort.get("new_adapter_generation"):
                raise RecoveryTransportDenied("failed adapter generation changed")
        except RecoveryTransportDenied:
            raise
        except Exception:
            raise RecoveryTransportDenied("retained recovery target recheck failed") from None

    return check


def _recheck_source_snapshot(snapshot) -> None:
    source_root, source_bytes, source_signature, receipt_bytes, receipt_signature = snapshot
    generation = source_root.parent
    current_source, current_signature = _read_root_file(
        generation, "hermes_installer/core_runtime.py", maximum=_MAX_SOURCE_BYTES,
        mode=0o644)
    current_receipt, current_receipt_signature = _read_root_file(
        generation, ".source-provenance.json", maximum=_MAX_RECEIPT_BYTES,
        mode=0o444, under_source=False)
    if (current_source != source_bytes or current_signature != source_signature
            or current_receipt != receipt_bytes or current_receipt_signature != receipt_signature):
        raise RecoveryTransportDenied("fixed source identity changed")


def _safe_failure_projection(error: BaseException) -> dict:
    """Expose only static exception types and bounded pinned-Core frame labels."""
    source_roots = {
        str(_source_directory(_FAILED_COMMIT) / "src"): "failed",
        str(_source_directory(_FIX_COMMIT) / "src"): "fix",
    }
    exceptions = []
    seen: set[int] = set()
    current = error
    frame_count = 0
    while isinstance(current, BaseException) and id(current) not in seen and len(exceptions) < 4:
        seen.add(id(current))
        name = type(current).__name__
        if type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name) is None:
            name = "Exception"
        frames = []
        current_tb = current.__traceback__
        while current_tb is not None and frame_count < 12:
            code = current_tb.tb_frame.f_code
            filename = os.path.abspath(code.co_filename)
            source_kind = None
            for root, label in source_roots.items():
                if filename == os.path.join(root, "hermes_installer", "core_runtime.py"):
                    source_kind = label
                    break
            if source_kind is not None:
                function = code.co_name
                if (type(function) is not str
                        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", function) is None):
                    function = "function"
                frames.append({"source": source_kind,
                               "relative_path": "hermes_installer/core_runtime.py",
                               "function": function,
                               "line": int(current_tb.tb_lineno)})
                frame_count += 1
            current_tb = current_tb.tb_next
        exceptions.append({"exception_type": name, "frames": frames})
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return {"schema": 1, "operation": "retained-core-rollback",
            "outcome": "failed", "exceptions": exceptions}


def run_fixed_recovery() -> int:
    """Run the one Root-only recovery. Returns 0 only when the fixed API returns."""
    _validate_pins()
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        raise RecoveryTransportDenied("fixed rollback requires the Root Linux actor")
    if (sys.executable != "/opt/hermes-jarvis-mvp-20261011/gateway-venv/bin/python"
            or sys.gettrace() is not None or sys.getprofile() is not None
            or not sys.flags.isolated or not sys.flags.dont_write_bytecode
            or not sys.flags.no_user_site):
        raise RecoveryTransportDenied("fixed rollback requires an isolated untraced process")
    failed_source = _source_snapshot(
        _FAILED_COMMIT, _FAILED_ARCHIVE_SHA256, _FAILED_CORE_SHA256)
    fix_source = _source_snapshot(_FIX_COMMIT, _FIX_ARCHIVE_SHA256, _FIX_CORE_SHA256)
    code_objects = _definition_code_objects(fix_source[1], expected_sha256=_FIX_CORE_SHA256)
    core_module = _load_failed_core(failed_source[0])
    if hashlib.sha256(failed_source[1]).hexdigest() != _FAILED_CORE_SHA256:
        raise RecoveryTransportDenied("failed Core changed before import")
    target = _capture_exact_target(core_module)
    inspector = sys.modules.get("hermes_installer.remote.core_gateway_inspector")
    if type(inspector) is not ModuleType:
        raise RecoveryTransportDenied("failed Core source verifier is unavailable")
    generation = inspector._current_native_adapter_generation(deadline=time.monotonic() + 35.0)
    if generation != target["cohort"].get("new_adapter_generation"):
        raise RecoveryTransportDenied("retained adapter generation differs")
    guard = _target_guard(core_module, target, failed_source, fix_source)
    _restore_with_transported_functions(core_module, code_objects, guard)
    _recheck_source_snapshot(failed_source)
    _recheck_source_snapshot(fix_source)
    if hashlib.sha256(failed_source[1]).hexdigest() != _FAILED_CORE_SHA256:
        raise RecoveryTransportDenied("failed Core source changed during rollback")
    if inspector._current_native_adapter_generation(
            deadline=time.monotonic() + 35.0) != generation:
        raise RecoveryTransportDenied("failed adapter closure changed during rollback")
    return 0


def main() -> int:
    try:
        if len(sys.argv) != 1:
            return 4
        result = run_fixed_recovery()
    except Exception as error:
        print(json.dumps(_safe_failure_projection(error), sort_keys=True,
                         separators=(",", ":")))
        return 4
    if result != 0:
        return 4
    print(json.dumps({"schema": 1, "operation": "retained-core-rollback",
                      "outcome": "restore-api-returned",
                      "failed_source_commit": _FAILED_COMMIT,
                      "failed_source_archive_sha256": _FAILED_ARCHIVE_SHA256,
                      "failed_core_source_sha256": _FAILED_CORE_SHA256,
                      "fix_source_commit": _FIX_COMMIT,
                      "fix_source_archive_sha256": _FIX_ARCHIVE_SHA256,
                      "fix_core_source_sha256": _FIX_CORE_SHA256,
                      "function_bindings_restored": True,
                      "acceptance": "not-claimed"},
                     sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
