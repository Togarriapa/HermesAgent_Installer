"""Effects and fail-closed checks for the finite core-service adapter.

These tests use temporary files and mocked systemd calls; target acceptance is
performed separately on the enrolled Pi.
"""
import hashlib
import contextlib
import ctypes
import io
import json
import os
import pwd
import re
import select
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from types import MappingProxyType, ModuleType, SimpleNamespace

import pytest

from hermes_installer import core_runtime as core
_PRODUCTION_READ_CURRENT_RESOURCES_DISCOVERY = core.read_current_resources_discovery


_KNOWN_HELPER_IMPORTER_ERRORS = {
    ("manual Jarvis skill stage refused: " + message + "\n").encode("utf-8"):
    message for message in (
        "helper-only transition input is outside its bound",
        "helper-only transition framing differs",
        "archives are not the exact reviewed helper-only transition",
        "helper-only transition requires the fixed root runuser and inherited root pipe",
        "helper-only importer process identity is unavailable",
        "Hermes home must be an explicit absolute path",
        "Hermes home path contains a symbolic-link component",
        "Hermes home must be a real directory owned by the current user",
        "existing skill generation root permissions differ",
        "existing skill generation is unowned or its ownership journal changed",
        "owned Resources generation contains missing or untracked files",
        "owned Resources generation member changed",
        "the revision-owned Jarvis skill generation path already exists",
        "atomic owned-generation exchange is unavailable on this OS",
        "helper transition backup identity is invalid",
        "helper transition backup identity already exists",
    )
}


def _classify_owner_marker_mismatch(expected_raw, actual_raw):
    """Classify bounded in-memory marker bytes without exposing their values."""
    maximum = 2 * 1024 * 1024
    if (type(expected_raw) is not bytes or type(actual_raw) is not bytes
            or not expected_raw or not actual_raw
            or len(expected_raw) > maximum or len(actual_raw) > maximum):
        return "unclassified"
    try:
        expected = json.loads(expected_raw)
        actual = json.loads(actual_raw)
    except (UnicodeError, ValueError, TypeError):
        return "unclassified"
    fields = {
        "schema", "stage", "artifact_sha256", "source_revision", "source_tree",
        "profile_source_id", "user_visible_profile", "internal_profile_count",
        "target_home_role", "members",
    }
    if (type(expected) is not dict or type(actual) is not dict
            or set(expected) != fields or set(actual) != fields):
        return "marker-schema"
    if any(type(value) is not int for value in (expected["schema"], actual["schema"])):
        return "marker-schema"
    if any(expected[key] != actual[key] for key in (
            "schema", "stage", "profile_source_id", "user_visible_profile",
            "internal_profile_count", "target_home_role")):
        return "marker-schema"
    if expected["artifact_sha256"] != actual["artifact_sha256"]:
        return "artifact"
    if expected["source_revision"] != actual["source_revision"]:
        return "source-revision"
    if expected["source_tree"] != actual["source_tree"]:
        return "source-tree"
    left, right = expected["members"], actual["members"]
    if type(left) is not list or type(right) is not list:
        return "marker-schema"
    if len(left) != len(right):
        return "member-count"
    row_fields = {"path", "sha256", "size_bytes"}
    for first, second in zip(left, right):
        if (type(first) is not dict or type(second) is not dict
                or set(first) != row_fields or set(second) != row_fields
                or type(first["size_bytes"]) is not int
                or type(second["size_bytes"]) is not int):
            return "marker-schema"
        if first != second:
            return "member-digest"
    return "unclassified"


def test_owner_marker_mismatch_classifier_uses_only_bounded_fixed_categories():
    marker = {
        "schema": 1, "stage": "manual-owned-bundled-resources-import",
        "artifact_sha256": "a" * 64, "source_revision": "b" * 40,
        "source_tree": "c" * 40, "profile_source_id": "hermes",
        "user_visible_profile": {"source_id": "hermes", "native_key": "default",
                                 "display_name": "Jarvis"},
        "internal_profile_count": 207, "target_home_role": "jarvis-primary-home",
        "members": [{"path": "generation/member", "sha256": "d" * 64, "size_bytes": 4}],
    }

    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    assert _classify_owner_marker_mismatch(encode(marker), encode(marker)) == "unclassified"
    for field, label, replacement in (
            ("schema", "marker-schema", 2),
            ("artifact_sha256", "artifact", "e" * 64),
            ("source_revision", "source-revision", "f" * 40),
            ("source_tree", "source-tree", "0" * 40),
            ("internal_profile_count", "marker-schema", 206)):
        changed = dict(marker)
        changed[field] = replacement
        assert _classify_owner_marker_mismatch(encode(marker), encode(changed)) == label
    changed = dict(marker, members=[])
    assert _classify_owner_marker_mismatch(encode(marker), encode(changed)) == "member-count"
    changed = dict(marker, members=[dict(marker["members"][0], sha256="e" * 64)])
    assert _classify_owner_marker_mismatch(encode(marker), encode(changed)) == "member-digest"
    assert _classify_owner_marker_mismatch(b"{}", encode(marker)) == "marker-schema"
    assert _classify_owner_marker_mismatch(b"x" * (2 * 1024 * 1024 + 1), encode(marker)) == "unclassified"


@contextlib.contextmanager
def _bounded_cohort_exception_sites():
    """Expose only code locations/types for a hidden cohort failure on Pi."""
    previous = sys.gettrace()
    sites = []
    first_substantive = []
    importer_outcomes = []
    owner_marker_mismatches = []
    custody_false_returns = []
    initial_primary_exceptions = []
    owner_restore_receipts = []
    routine = {"GeneratorExit", "StopIteration", "StopAsyncIteration"}
    allowed = {"core_runtime.py", "manual_jarvis_skills.py",
               "resources_skill_overlay.py", "primary_prompt_manager.py"}
    filename_kinds = {}

    def filename_kind(filename):
        # Trace every line only in the reviewed cohort modules. Returning None
        # at call time leaves stdlib, pytest, and archive-library frames alone.
        kind = filename_kinds.get(filename)
        if kind is None:
            kind = filename.rsplit("/", 1)[-1]
            filename_kinds[filename] = kind
        return kind

    def trace(frame, event, arg):
        if event == "call":
            return trace if filename_kind(frame.f_code.co_filename) in allowed else None
        kind = filename_kinds.get(frame.f_code.co_filename)
        if (event == "exception" and kind == "core_runtime.py"
                and frame.f_code.co_name == "_restore_adapter_update_owner_generation"
                and type(arg[1]).__name__ == "CoreRuntimeError"
                and str(arg[1]) == "owner generation rollback receipt does not bind the prior bytes"):
            values = frame.f_locals
            result = values.get("result")
            expected_keys = {"state", "artifact_sha256", "generation_path",
                             "retained_generation_backup", "retained_artifact_sha256"}
            row = {
                "result_object": type(result) is dict,
                "keys_exact": type(result) is dict and set(result) == expected_keys,
                "state_restored": type(result) is dict and result.get("state") == "restored",
                "artifact_old": type(result) is dict and result.get("artifact_sha256") == values.get("old_sha"),
                "generation_target": type(result) is dict and result.get("generation_path") == str(values.get("target")),
                "retained_artifact_new": type(result) is dict and result.get("retained_artifact_sha256") == values.get("new_sha"),
                "retained_backup_path": type(result) is dict and result.get("retained_generation_backup") == str(values.get("target").parent / values.get("name")),
            }
            owner_restore_receipts.append(row)
            if len(owner_restore_receipts) > 2:
                del owner_restore_receipts[0]
        if (event == "exception" and kind == "core_runtime.py"
                and frame.f_code.co_name == "_hash_generation_tree"
                and type(arg[1]).__name__ == "CoreRuntimeError"
                and str(arg[1]) == "owned Resources manifest differs from the pinned bundle"):
            values = frame.f_locals
            artifact = values.get("artifact_sha")
            expected_raw = values.get("expected_owner")
            actual_raw = values.get("marker")
            label = "unknown"
            parent = frame.f_back
            while parent is not None:
                if (filename_kind(parent.f_code.co_filename) == "core_runtime.py"
                        and parent.f_code.co_name == "_restore_adapter_update_backup"):
                    cohort = parent.f_locals.get("cohort")
                    if type(cohort) is dict:
                        if artifact == cohort.get("old_artifact_sha256"):
                            label = "A0"
                        elif artifact == cohort.get("new_artifact_sha256"):
                            label = "A1"
                    break
                parent = parent.f_back
            if label in {"A0", "A1"} and not any(row[0] == label for row in owner_marker_mismatches):
                owner_marker_mismatches.append((label, _classify_owner_marker_mismatch(
                    expected_raw, actual_raw)))
                if len(owner_marker_mismatches) > 2:
                    del owner_marker_mismatches[0]
        if (event == "return" and kind == "core_runtime.py"
                and frame.f_code.co_name in {"_initial_primary_current", "_validate_guarded_new_read"}
                and arg is False):
            custody_false_returns.append((kind, frame.f_code.co_name, frame.f_lineno))
            if len(custody_false_returns) > 12:
                del custody_false_returns[0]
        if (event == "return" and kind == "core_runtime.py"
                and frame.f_code.co_name == "_run_same_materialization_import"):
            values = frame.f_locals
            process = values.get("process")
            stdout = values.get("stdout")
            stderr = values.get("stderr")
            if (process is not None and isinstance(stdout, bytes)
                    and isinstance(stderr, bytes)):
                # Retain bytes only in this in-process test collector; never
                # print or attach raw child output to diagnostics.
                importer_outcomes.append({"returncode": process.returncode,
                                          "stdout": stdout,
                                          "stderr_bytes": len(stderr)})
        if event == "exception" and kind in allowed:
            exception_type = type(arg[1]).__name__
            if exception_type not in routine:
                site = (kind, frame.f_code.co_name, frame.f_lineno, exception_type)
                if len(sites) < 80:
                    sites.append(site)
                else:
                    del sites[30]
                    sites.append(site)
                if (kind == "core_runtime.py"
                        and frame.f_code.co_name == "_initial_primary_current"):
                    initial_primary_exceptions.append(site)
                    if len(initial_primary_exceptions) > 12:
                        del initial_primary_exceptions[0]
                if not first_substantive and exception_type != "CoreRuntimeError":
                    first_substantive.append(site)
        return trace

    sys.settrace(trace)
    try:
        yield importer_outcomes
    except BaseException as failure:
        sys.settrace(previous)
        contexts = []
        current = failure
        seen = set()
        for _ in range(4):
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            frames = []
            tb = current.__traceback__
            while tb is not None and len(frames) < 8:
                frame = tb.tb_frame
                if Path(frame.f_code.co_filename).name in allowed:
                    frames.append((Path(frame.f_code.co_filename).name,
                                   frame.f_code.co_name, tb.tb_lineno))
                tb = tb.tb_next
            contexts.append((type(current).__name__, frames))
            current = current.__context__
        print("bounded exception context chain: " + repr(contexts))
        print("first substantive non-CoreRuntimeError site: " + repr(first_substantive[:1]))
        print("bounded cohort exception sites: " + repr(sites[:30] + sites[-50:]))
        print("bounded owner marker mismatch classes: " + repr(owner_marker_mismatches[:2]))
        print("bounded custody false-return sites: " + repr(custody_false_returns[-12:]))
        print("bounded initial-primary predicate exceptions: " + repr(initial_primary_exceptions[-12:]))
        print("bounded owner-generation restore receipt predicates: " + repr(owner_restore_receipts[-2:]))
        # Read only outcome metadata from the genuine fixed importer frame.
        # Never print child stdout or stderr; the sole textual diagnostic is
        # an exact constant message reviewed in manual_jarvis_skills.py.
        importer_outcome = None
        current = failure
        seen = set()
        for _ in range(4):
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            tb = current.__traceback__
            while tb is not None:
                frame = tb.tb_frame
                if (Path(frame.f_code.co_filename).name == "core_runtime.py"
                        and frame.f_code.co_name == "_run_same_materialization_import"):
                    values = frame.f_locals
                    process = values.get("process")
                    stdout = values.get("stdout")
                    stderr = values.get("stderr")
                    if process is not None:
                        importer_outcome = {
                            "returncode": process.returncode,
                            "stdout_bytes": len(stdout) if isinstance(stdout, bytes) else None,
                            "stderr_bytes": len(stderr) if isinstance(stderr, bytes) else None,
                            "known_error": (_KNOWN_HELPER_IMPORTER_ERRORS.get(stderr)
                                            if isinstance(stderr, bytes) else None),
                        }
                    break
                tb = tb.tb_next
            if importer_outcome is not None:
                break
            current = current.__context__
        if importer_outcome is not None:
            print("bounded helper importer outcome: " + repr(importer_outcome))
        raise
    finally:
        sys.settrace(previous)


@contextlib.contextmanager
def _bounded_owner_generation_restore_failure():
    """Capture fixed metadata only when the protected owner restore rejects."""
    previous = sys.gettrace()
    code = core._restore_adapter_update_owner_generation.__code__
    observed = []
    refusal_codes = {
        b"manual Jarvis skill stage refused: helper-only transition requires the fixed root runuser and inherited root pipe\n": "origin_refused",
        b"manual Jarvis skill stage refused: restore pair is not the exact reviewed helper-only transition\n": "transition_pair_refused",
        b"manual Jarvis skill stage refused: restore home is not the fixed Jarvis home\n": "home_path_refused",
        b"manual Jarvis skill stage refused: restore home custody differs\n": "home_custody_refused",
        b"manual Jarvis skill stage refused: restore backup identity is invalid\n": "backup_name_refused",
        b"manual Jarvis skill stage refused: existing skill generation root permissions differ\n": "generation_root_permissions_refused",
        b"manual Jarvis skill stage refused: existing skill generation is unowned or its ownership journal changed\n": "generation_journal_refused",
        b"manual Jarvis skill stage refused: existing generation directory permissions differ\n": "generation_permissions_refused",
        b"manual Jarvis skill stage refused: owned Resources generation contains missing or untracked files\n": "generation_inventory_refused",
        b"manual Jarvis skill stage refused: owned Resources generation member changed\n": "generation_member_refused",
    }

    def trace(frame, event, arg):
        if event == "call":
            return trace if frame.f_code is code else None
        if (event == "exception" and frame.f_code is code
                and type(arg[1]).__name__ == "CoreRuntimeError"
                and str(arg[1]) == "owner generation rollback operation failed"):
            values = frame.f_locals
            process = values.get("process")
            stdout = values.get("stdout")
            stderr = values.get("stderr")
            writer = values.get("writer")
            errors = values.get("write_error")
            old_sha = values.get("old_sha")
            new_sha = values.get("new_sha")
            target = values.get("target")
            name = values.get("name")
            receipt = None
            if type(stdout) is bytes and len(stdout) <= 8192:
                try:
                    parsed = json.loads(stdout)
                except (ValueError, TypeError, RecursionError):
                    parsed = None
                expected = {"state", "artifact_sha256", "generation_path",
                            "retained_generation_backup", "retained_artifact_sha256"}
                if type(parsed) is dict:
                    receipt = {
                        "keys_exact": set(parsed) == expected,
                        "restored": parsed.get("state") == "restored",
                        "prior_artifact": parsed.get("artifact_sha256") == old_sha,
                        "target_path": parsed.get("generation_path") == str(target),
                        "new_artifact_retained": parsed.get("retained_artifact_sha256") == new_sha,
                        "backup_path": (isinstance(name, str) and
                                        parsed.get("retained_generation_backup") ==
                                        str(core.HERMES_HOME / name)),
                    }
            observed.append({
                "process_present": process is not None,
                "returncode": process.returncode if process is not None else None,
                "stdout_bytes": len(stdout) if type(stdout) is bytes else None,
                "stderr_bytes": len(stderr) if type(stderr) is bytes else None,
                "stdout_within_bound": type(stdout) is bytes and len(stdout) <= 8192,
                "stderr_within_bound": type(stderr) is bytes and len(stderr) <= 8192,
                "dispatch_revalidated": True,
                "writer_alive": writer.is_alive() if writer is not None else None,
                "write_error_present": bool(errors),
                "write_error_type": type(errors[0]).__name__ if errors else None,
                "stderr_refusal": refusal_codes.get(stderr, "unclassified")
                    if type(stderr) is bytes else "unavailable",
                "receipt": receipt,
            })
        return trace

    sys.settrace(trace)
    try:
        yield
    except BaseException:
        sys.settrace(previous)
        if observed:
            print("bounded owner-generation restore failure metadata: " + repr(observed[-1]))
        raise
    finally:
        sys.settrace(previous)


def _systemd_decoded_exec_start_pre(unit_bytes, *, runner=None):
    """Read the manager-decoded ExecStartPre argv for an exact temporary unit."""
    if os.geteuid() != 0:
        raise AssertionError("systemd directive decoding requires the enrolled Pi root actor")
    directive = next((row for row in unit_bytes.splitlines()
                      if row.startswith(b"ExecStartPre=")), None)
    if directive is None or len(directive) > 256 * 1024:
        raise AssertionError("bounded generated ExecStartPre is required")
    root = Path("/run/systemd/system")
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
            or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022):
        raise AssertionError("systemd runtime unit directory custody differs")
    fixed_paths_before = _fixed_service_path_identity()
    name = f"hermes-guard-decode-{os.getpid()}-{time.monotonic_ns()}.service"
    path = root / name
    content = (b"[Unit]\nDescription=No-start ExecStartPre decoder fixture\n"
               b"[Service]\nType=oneshot\n" + directive + b"\nExecStart=/usr/bin/true\n")
    run = subprocess.run if runner is None else runner
    def checked(argv, *, maximum=1024 * 1024):
        result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, check=False, timeout=15,
                     close_fds=True)
        if (result.returncode != 0 or len(result.stdout) > maximum
                or len(result.stderr) > 8192):
            raise AssertionError("bounded systemd parser query failed")
        return result.stdout
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o644)
    identity = None
    try:
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o644)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short probe unit write")
            view = view[written:]
        os.fsync(fd)
        final = os.fstat(fd)
        if (not stat.S_ISREG(final.st_mode) or final.st_uid != 0 or final.st_gid != 0
                or stat.S_IMODE(final.st_mode) != 0o644 or final.st_nlink != 1
                or final.st_size != len(content)):
            raise AssertionError("temporary parser unit custody differs")
    except BaseException:
        if identity is not None:
            try:
                current = path.lstat()
                if ((current.st_dev, current.st_ino) == identity
                        and stat.S_ISREG(current.st_mode) and current.st_uid == 0
                        and current.st_gid == 0 and current.st_nlink == 1):
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        os.close(fd)
    loaded = False
    try:
        loaded = True
        checked(("systemctl", "daemon-reload"), maximum=65536)
        raw = checked(("busctl", "--json=short", "call",
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "LoadUnit", "s", name))
        loaded_result = json.loads(raw)
        object_path = loaded_result.get("data") if type(loaded_result) is dict else None
        if type(object_path) is list and len(object_path) == 1:
            object_path = object_path[0]
        expected_path = "/org/freedesktop/systemd1/unit/" + name.replace(
            "\\", "_5c").replace("-", "_2d").replace(".", "_2e")
        if (type(loaded_result) is not dict or loaded_result.get("type") != "o"
                or object_path != expected_path):
            raise AssertionError("systemd returned an unexpected probe unit")
        raw = checked(("busctl", "--json=short", "get-property",
            "org.freedesktop.systemd1", object_path,
            "org.freedesktop.systemd1.Service", "ExecStartPre"))
        payload = json.loads(raw)
        if type(payload) is not dict or payload.get("type") != "a(sasbttttuii)":
            raise AssertionError("systemd returned an unexpected ExecStartPre type")
        rows = payload.get("data")
        if type(rows) is not list or len(rows) != 1:
            raise AssertionError("systemd returned an unexpected ExecStartPre count")
        row = rows[0]
        if (type(row) is not list or len(row) != 10 or type(row[0]) is not str
                or type(row[1]) is not list
                or any(type(value) is not str for value in row[1])
                or type(row[2]) is not bool
                or any(type(value) is not int for value in row[3:])):
            raise AssertionError("systemd returned an unexpected ExecStartPre row")
        if (row[0] != str(core.PYTHON) or len(row[1]) != 5
                or row[1][0] != str(core.PYTHON)
                or row[1][1:4] != ["-I", "-S", "-c"]):
            raise AssertionError("systemd returned an unexpected guard argv")
        return tuple(row[1])
    finally:
        current = path.lstat()
        if (identity is None or (current.st_dev, current.st_ino) != identity
                or not stat.S_ISREG(current.st_mode) or current.st_uid != 0
                or current.st_gid != 0 or stat.S_IMODE(current.st_mode) != 0o644
                or current.st_nlink != 1 or path.read_bytes() != content):
            raise AssertionError("temporary parser unit cleanup refused")
        path.unlink()
        if loaded:
            checked(("systemctl", "daemon-reload"), maximum=65536)
        if _fixed_service_path_identity() != fixed_paths_before:
            raise AssertionError("parser fixture changed a fixed Core service file")


def _exec_start_pre(unit_bytes, *, credential_mutations=None, expect_success=None,
                    runner=None, diagnostic=False, service_sources=None,
                    return_result=False, systemd_argv=None,
                    credential_projection=False):
    """Run the untouched generated guard as admin in a private mount view."""
    if os.geteuid() != 0:
        raise AssertionError("the Pi startup-guard fixture requires root to model admin")
    line = next((row for row in unit_bytes.decode().splitlines()
                 if row.startswith("ExecStartPre=")), None)
    if line is None:
        if expect_success is True:
            raise AssertionError("generated unit has no ExecStartPre guard")
        return None
    unshare = shutil.which("unshare")
    runuser = shutil.which("runuser")
    if not unshare or not runuser:
        raise AssertionError("Pi guard fixture requires unshare and runuser")
    before_fixed_paths = _fixed_service_path_identity()
    source_unit, source_launcher = service_sources or (core.UNIT, core.LAUNCHER)
    source_unit, source_launcher = Path(source_unit), Path(source_launcher)
    if diagnostic:
        for path, mode, maximum in ((source_unit, 0o644, 256 * 1024),
                                    (source_launcher, 0o755, 128 * 1024)):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    != (0, 0, mode) or not 1 <= info.st_size <= maximum):
                raise AssertionError("diagnostic service input custody differs")
        if source_unit.read_bytes() != unit_bytes:
            raise AssertionError("diagnostic unit bytes differ from retained service input")
    cred_dir = Path(tempfile.mkdtemp(prefix="core-start-guard-", dir="/tmp"))
    cred_dir.chmod(0o700)
    cred_view = Path(tempfile.mkdtemp(prefix="core-start-guard-view-", dir="/tmp"))
    admin = pwd.getpwnam("admin")
    try:
        loads = [row.partition("=")[2] for row in unit_bytes.decode().splitlines()
                 if row.startswith("LoadCredential=")]
        credentials = []
        for item in loads:
            name, separator, source = item.partition(":")
            if not separator:
                raise AssertionError("generated service credential declaration is malformed")
            credentials.append((name, Path(source)))
        def set_projected_credential(target, content):
            target.write_bytes(content)
            os.chown(target, core.ROOT_UID, core.ROOT_UID)
            target.chmod(0o440)
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry) for entry in (
                    (1, 4, 0xffffffff), (2, 4, 1000), (4, 0, 0xffffffff),
                    (16, 4, 0xffffffff), (32, 0, 0xffffffff)))
            os.setxattr(target, "system.posix_acl_access", acl, follow_symlinks=False)
        for name, source in credentials:
            target = cred_dir / name
            try:
                content = source.read_bytes()
            except OSError:
                raise AssertionError(
                    f"generated LoadCredential source is unreadable: {name}"
                ) from None
            if credential_projection:
                set_projected_credential(target, content)
            else:
                target.write_bytes(content)
                target.chmod(0o400)
                os.chown(target, admin.pw_uid, admin.pw_gid)
        for name, mutation in (credential_mutations or {}).items():
            target = cred_dir / name
            if mutation[0] == "remove":
                target.unlink()
            elif mutation[0] == "bytes":
                if credential_projection:
                    set_projected_credential(target, mutation[1])
                else:
                    target.write_bytes(mutation[1])
                    target.chmod(0o400)
                    os.chown(target, admin.pw_uid, admin.pw_gid)
            elif mutation[0] == "mode":
                target.chmod(mutation[1])
            elif mutation[0] == "owner":
                os.chown(target, mutation[1], mutation[2])
            elif mutation[0] == "acl-wrong":
                acl = struct.pack("<I", 2) + b"".join(
                    struct.pack("<HHI", *entry) for entry in (
                        (1, 4, 0xffffffff), (2, 4, 1000), (2, 4, 1001),
                        (4, 0, 0xffffffff), (16, 4, 0xffffffff),
                        (32, 0, 0xffffffff)))
                os.setxattr(target, "system.posix_acl_access", acl,
                            follow_symlinks=False)
        os.chown(cred_dir, core.ROOT_UID if credential_projection else admin.pw_uid,
                 core.ROOT_UID if credential_projection else admin.pw_gid)
        os.chmod(cred_dir, 0o755 if credential_projection else 0o500)
        command = (list(systemd_argv) if systemd_argv is not None
                   else shlex.split(line.partition("=")[2]))
        original_command = list(command)
        if diagnostic:
            try:
                code_index = command.index("-c")
                guard_source = command[code_index + 1]
            except (ValueError, IndexError):
                raise AssertionError("generated guard command has no isolated source") from None
            wrapper = (
                "import builtins,hashlib,json,os,sys\n"
                "_guard_access_failures=[]\n"
                "def _guard_path_label(path):\n"
                " try: name=os.path.basename(os.fspath(path))\n"
                " except Exception: return 'other'\n"
                " allowed={'admin','.hermes','plugins','hermes-installer-resources-delegation','plugin.yaml','__init__.py','SOUL.md','core-ownership-journal','hermes-session-token','adapter-update-cohort','resources-discovery','adapter-backup-manifest','adapter-backup-journal','hermes-jarvis-core.service','hermes-jarvis-core-launcher'}\n"
                " return name if name in allowed else 'other'\n"
                "def _guard_wrap_access(function,operation):\n"
                " def wrapped(path,*args,**kwargs):\n"
                "  try: return function(path,*args,**kwargs)\n"
                "  except PermissionError:\n"
                "   _guard_access_failures.append((operation,_guard_path_label(path)))\n"
                "   if len(_guard_access_failures)>16: del _guard_access_failures[0]\n"
                "   raise\n"
                " return wrapped\n"
                "os.open=_guard_wrap_access(os.open,'os.open')\n"
                "os.stat=_guard_wrap_access(os.stat,'os.stat')\n"
                "builtins.open=_guard_wrap_access(builtins.open,'open')\n"
                "_guard_source=" + repr(guard_source) + "\n"
                "_guard_diag_state={}\n"
                "def _guard_emit(values):\n"
                " result={name:values[name] for name in ('ok','cp_ok','rp_ok','backup_ok','initial_ok','keys_ok','transition_ok','cohort_ok','starting','reconstruction_ok','source_ok','native_ok','starting_ok','active_update_ok','phase_ok') if type(values.get(name)) is bool}\n"
                " if type(_guard_diag_state.get('base_ok')) is bool: result['base_ok']=_guard_diag_state['base_ok']\n"
                " if values.get('phase') in ('source-starting','bindings-verified','committed'): result['phase']=values['phase']\n"
                " def check(name,fn):\n"
                "  try: result[name]=bool(fn())\n"
                "  except Exception: result[name]=False\n"
                " c=values.get('c'); d=values.get('d'); r=values.get('r')\n"
                " check('record_identity',lambda: values.get('canonical')(c)==values.get('cr') and values.get('keys_ok') and c.get('schema')==1 and c.get('purpose')=='adapter-source-binding-cohort' and c.get('owner_uid')==1000 and c.get('home_role')=='jarvis-primary-home')\n"
                " check('journal_join',lambda: values.get('expected_j')==hashlib.sha256(values.get('raw')).hexdigest())\n"
                " check('resources_join',lambda: values.get('expected_r')==hashlib.sha256(values.get('rr')).hexdigest() and r.get('core_ownership_sha256')==hashlib.sha256(values.get('raw')).hexdigest() and r.get('core_source_generation')==c.get('new_core_source_generation') and r.get('artifact_sha256')==c.get('new_artifact_sha256'))\n"
                " check('generation_recipe_join',lambda: c.get('new_source')==values.get('source') and c.get('new_adapter_generation')==d.get('adapter_generation') and c.get('new_core_source_generation')==d.get('core_source_generation') and c.get('new_source_recipe_sha256')==values.get('recipe')(values.get('source'),d.get('adapter_generation'),d.get('unit_sha256'),d.get('launcher_sha256')))\n"
                " check('adapter_state_join',lambda: d.get('adapter_update_cohort_transaction_id')==c.get('cohort_transaction_id') and d.get('adapter_update_target_source')==values.get('source') and d.get('adapter_update_target_generation')==d.get('adapter_generation') and ((values.get('starting') and d.get('adapter_update_state')=='starting') or (values.get('phase')=='committed' and d.get('adapter_update_state')=='active')))\n"
                " check('service_files',lambda: all(values.get('valid')(p,u,g,m,h) for p,u,g,m,h in values.get('files')))\n"
                " return result\n"
                "def _guard_trace(frame,event,arg):\n"
                " if frame.f_code.co_filename!='<untouched-generated-guard>' or frame.f_code.co_name!='<module>': return _guard_trace\n"
                " if event=='call': frame.f_trace_opcodes=True; return _guard_trace\n"
                " values=frame.f_locals\n"
                " if event=='opcode' and 'cohort_ok' in values and 'base_ok' not in _guard_diag_state and type(values.get('ok')) is bool: _guard_diag_state['base_ok']=values['ok']; return _guard_trace\n"
                " if event=='exception' and arg[0] is SystemExit and arg[1]==0: return _guard_trace\n"
                " if event not in ('return','exception'): return _guard_trace\n"
                " result=_guard_emit(values)\n"
                " sys.stdout.write('GUARD_DIAGNOSTIC='+json.dumps(result,sort_keys=True,separators=(',',':'))+'\\n')\n"
                " sys.stdout.write('GUARD_ACCESS_DIAGNOSTIC='+json.dumps(_guard_access_failures,separators=(',',':'))+'\\n')\n"
                " sys.settrace(None)\n"
                " return _guard_trace\n"
                "sys.settrace(_guard_trace)\n"
                "exec(compile(_guard_source,'<untouched-generated-guard>','exec'),{'__name__':'__main__'})\n"
            )
            command[code_index + 1] = wrapper
        namespace_script = """\
set -eu
unit_source=$1; shift
launcher_source=$1; shift
credential_source=$1; shift
credential_target=$1; shift
runuser_bin=$1; shift
mount --make-rprivate /
mount --bind -- "$unit_source" /etc/systemd/system/hermes-jarvis-core.service
mount -o remount,bind,ro /etc/systemd/system/hermes-jarvis-core.service
mount --bind -- "$launcher_source" /usr/local/libexec/hermes-jarvis-core-launcher
mount -o remount,bind,ro /usr/local/libexec/hermes-jarvis-core-launcher
mount --bind -- "$credential_source" "$credential_target"
mount -o remount,bind,ro "$credential_target"
export CREDENTIALS_DIRECTORY="$credential_target" PATH=/usr/bin:/bin
actual_uid=$("$runuser_bin" -u admin -- /usr/bin/id -u)
test "$actual_uid" = 1000
printf 'FIXTURE_NAMESPACE_READY\\n'
exec "$runuser_bin" -u admin -- "$@"
"""
        run = subprocess.run if runner is None else runner
        def execute(guard_command):
            return run(
                [unshare, "--mount", "--propagation", "private", "--", "sh", "-eu", "-c",
                 namespace_script, "core-start-guard", str(source_unit), str(source_launcher),
                 str(cred_dir), str(cred_view), runuser, *guard_command],
                cwd="/", env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False,
            )

        # The untouched guard always decides the result. A diagnostic execution
        # is permitted only after that command has denied startup, while the
        # same private credentials and source view are still present.
        result = execute(original_command)
        diagnostic_result = None
        if diagnostic and result.returncode != 0:
            diagnostic_result = execute(command)
        after_fixed_paths = _fixed_service_path_identity()
        if after_fixed_paths != before_fixed_paths:
            raise AssertionError("private guard fixture changed a live Pi Core service file")
        stdout = result.stdout.decode("utf-8", errors="replace")
        if not stdout.startswith("FIXTURE_NAMESPACE_READY\n"):
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise AssertionError(
                "private mount namespace or admin actor setup failed; "
                f"exit={result.returncode}; stderr={stderr or '<empty>'}; "
                f"stdout={stdout.strip() or '<empty>'}"
            )
        if (expect_success is not None
                and (result.returncode == 0) is not expect_success):
            outcome = "succeed" if expect_success else "fail closed"
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            diagnostic_summary = None
            diagnostic_meta = None
            if diagnostic_result is not None:
                diagnostic_stdout = diagnostic_result.stdout.decode("utf-8", errors="replace")
                diagnostic_stderr = diagnostic_result.stderr.decode("utf-8", errors="replace")
                error_match = re.search(r"(?m)^([A-Za-z]+(?:Error|Exception))(?::|$)",
                                        diagnostic_stderr)
                line_match = re.search(r"(?m)^\s*File \"<string>\", line ([0-9]+)",
                                       diagnostic_stderr)
                diagnostic_meta = {
                    "exit": diagnostic_result.returncode,
                    "namespace_ready": diagnostic_stdout.startswith("FIXTURE_NAMESPACE_READY\n"),
                    "guard_emitted": any(row.startswith("GUARD_DIAGNOSTIC=")
                                          for row in diagnostic_stdout.splitlines()),
                    "stderr_type": error_match.group(1) if error_match else None,
                    "stderr_line": int(line_match.group(1)) if line_match else None,
                }
                for row in diagnostic_stdout.splitlines():
                    if row.startswith("GUARD_DIAGNOSTIC="):
                        try:
                            candidate = json.loads(row.partition("=")[2])
                        except (ValueError, TypeError):
                            candidate = None
                        if (type(candidate) is dict
                                and set(candidate) <= {
                                    "ok", "cp_ok", "rp_ok", "backup_ok", "initial_ok",
                                    "keys_ok", "transition_ok", "cohort_ok", "starting",
                                    "reconstruction_ok", "source_ok", "native_ok", "starting_ok",
                                    "active_update_ok", "phase_ok", "base_ok", "phase",
                                    "record_identity", "journal_join", "resources_join",
                                    "generation_recipe_join", "adapter_state_join", "service_files"}
                                and all(type(value) is bool for key, value in candidate.items()
                                        if key not in {"phase", "base_ok"})
                                and ("base_ok" not in candidate or type(candidate["base_ok"]) is bool)
                                and ("phase" not in candidate or candidate["phase"] in {
                                    "source-starting", "bindings-verified", "committed"})):
                            diagnostic_summary = candidate
                        break
                access_names = {"admin", ".hermes", "plugins",
                                "hermes-installer-resources-delegation", "plugin.yaml",
                                "__init__.py", "SOUL.md", "core-ownership-journal",
                                "hermes-session-token", "adapter-update-cohort",
                                "resources-discovery", "adapter-backup-manifest",
                                "adapter-backup-journal", "hermes-jarvis-core.service",
                                "hermes-jarvis-core-launcher", "other"}
                for row in diagnostic_stdout.splitlines():
                    if row.startswith("GUARD_ACCESS_DIAGNOSTIC="):
                        try:
                            candidate = json.loads(row.partition("=")[2])
                        except (ValueError, TypeError):
                            candidate = None
                        if (type(candidate) is list and len(candidate) <= 16
                                and all(type(item) is list and len(item) == 2
                                        and item[0] in {"open", "os.open", "os.stat"}
                                        and item[1] in access_names for item in candidate)):
                            diagnostic_meta["permission_failures"] = candidate
                        break
            if diagnostic:
                print("bounded ExecStartPre failure diagnostics: " + repr({
                    "guard_flags": diagnostic_summary,
                    "diagnostic_meta": diagnostic_meta,
                }))
            raise AssertionError(
                f"generated ExecStartPre should {outcome}; exit={result.returncode}; "
                f"stderr={'<suppressed>' if diagnostic else (stderr or '<empty>')}; "
                f"stdout={'<suppressed>' if diagnostic else (result.stdout.decode('utf-8', errors='replace').strip() or '<empty>')}"
                + (f"; guard_flags={diagnostic_summary!r}; diagnostic_meta={diagnostic_meta!r}"
                   if diagnostic else "")
            )
        return result if return_result else result.returncode
    finally:
        for child in cred_dir.iterdir():
            child.unlink()
        cred_dir.rmdir()
        cred_view.rmdir()


def _bind_private_fixed_hermes_home(source, request):
    """Bind a disposable owner tree at the real fixed path inside a private mount namespace."""
    if os.geteuid() != 0 or not hasattr(os, "unshare"):
        raise AssertionError("the owner-import fixture requires Root mount-namespace support")
    target = Path("/home/admin/.hermes")
    if target.is_symlink() or not target.is_dir():
        raise AssertionError("fixed Hermes home is unavailable for the private bind fixture")
    source_info = source.lstat()
    target_info = target.lstat()
    if (stat.S_ISLNK(source_info.st_mode) or not stat.S_ISDIR(source_info.st_mode)
            or source_info.st_uid != target_info.st_uid or source_info.st_gid != target_info.st_gid
            or stat.S_IMODE(source_info.st_mode) != 0o700):
        raise AssertionError("temporary Hermes home does not match fixed owner custody")
    before = os.stat("/proc/self/ns/mnt").st_ino
    os.unshare(getattr(os, "CLONE_NEWNS", 0x00020000))
    if os.stat("/proc/self/ns/mnt").st_ino == before:
        raise AssertionError("owner-import fixture did not enter a private mount namespace")

    libc = ctypes.CDLL(None, use_errno=True)
    mount = libc.mount
    mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                      ctypes.c_ulong, ctypes.c_void_p)
    mount.restype = ctypes.c_int
    umount2 = libc.umount2
    umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
    umount2.restype = ctypes.c_int

    def require_mount(result, action):
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), action)

    # Keep every mount in this test's namespace; do not propagate it to the Pi.
    require_mount(mount(None, b"/", None, 0x4000 | 0x40000, None), "private root mounts")
    require_mount(mount(os.fsencode(source), os.fsencode(target), None, 0x1000, None),
                  "temporary Hermes home bind")

    def cleanup():
        if umount2(os.fsencode(target), 0) != 0:
            error = ctypes.get_errno()
            raise AssertionError(f"could not unmount the private Hermes fixture: {error}")

    request.addfinalizer(cleanup)
    if (os.stat(source).st_dev, os.stat(source).st_ino) != (
            os.stat(target).st_dev, os.stat(target).st_ino):
        umount2(os.fsencode(target), 0)
        raise AssertionError("fixed Hermes home does not resolve to the disposable tree")


def _resource_receipt(*, prompt_matches=False):
    return {
        "state": "discovered", "materialized": True, "discovered": True,
        "selectable_profile_mutations": [], "functional": False,
        "enabled": False, "target_verified": False,
        "resource_counts": {"native_skills": 396, "source_profiles_preserved": 208},
        "native_receipt": {
            "hermes_revision": core.COMMIT, "python_version": "3.14.7",
            "profile_identity_loaded": True, "loaded_skill_count": 396,
            "active_prompt_matches_bundled_primary": prompt_matches,
        },
    }


def _isolate_resource_import_paths(tmp_path, monkeypatch):
    """Keep import-eligibility checks away from a host's real Hermes tree."""
    home = tmp_path / "isolated-home" / "admin"
    hermes_home = home / ".hermes"
    cas = tmp_path / "isolated-resource-cas"
    home.mkdir(parents=True)
    hermes_home.mkdir()
    cas.mkdir()
    monkeypatch.setattr(core, "HOME", home)
    monkeypatch.setattr(core, "HERMES_HOME", hermes_home)
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)


def _fake_runtime(tmp_path, monkeypatch, *, fail_enable_once=False,
                  public_service_files=False, request=None):
    etc = tmp_path / "etc" / "hermes-installer"
    var = tmp_path / "var" / "lib" / "hermes-installer"
    if public_service_files:
        if request is None:
            raise AssertionError("public service fixture needs pytest cleanup ownership")
        service_root = Path(tempfile.mkdtemp(prefix="core-m1-service-", dir="/tmp"))
        service_root.chmod(0o755)
        request.addfinalizer(lambda: shutil.rmtree(service_root))
        unit_dir = service_root / "etc" / "systemd" / "system"
        libexec = service_root / "usr" / "local" / "libexec"
    else:
        service_root = None
        unit_dir = tmp_path / "etc" / "systemd" / "system"
        libexec = tmp_path / "usr" / "local" / "libexec"
    home = tmp_path / "home" / "admin" / ".hermes"
    for path in (etc, var.parent, unit_dir, libexec, home):
        path.mkdir(parents=True, exist_ok=True)
    for path in (etc, unit_dir, libexec):
        path.chmod(0o755)
    if service_root is not None:
        # The untouched ExecStartPre guard stats the original embedded source
        # paths as admin, in addition to checking the private fixed-path binds.
        # Make only the disposable service tree's traversal ancestors public;
        # pytest data, credentials, journals and backups remain private.
        for path in (service_root / "etc", service_root / "etc" / "systemd",
                     service_root / "usr", service_root / "usr" / "local"):
            path.chmod(0o755)
    monkeypatch.setattr(core, "ETC_INSTALLER", etc)
    monkeypatch.setattr(core, "VAR_LIB_INSTALLER", var)
    monkeypatch.setattr(core, "SYSTEMD_UNIT_DIR", unit_dir)
    monkeypatch.setattr(core, "LIBEXEC_DIR", libexec)
    monkeypatch.setattr(core, "TOKEN", etc / "jarvis-core" / "session-token")
    monkeypatch.setattr(core, "JOURNAL", var / "core-runtime" / "ownership.json")
    monkeypatch.setattr(core, "RESOURCES_MIGRATION_RECORD",
                        var / "core-runtime" / "resources-migration-backup.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_COHORT",
                        var / "core-runtime" / "adapter-update-cohort.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS",
                        var / "core-runtime" / "adapter-update-backups")
    monkeypatch.setattr(core, "ADAPTER_MIGRATION_BACKUP",
                        var / "core-runtime" / "adapter-migration-backup")
    monkeypatch.setattr(core, "RESOURCES_RECORD",
                        var / "core-runtime" / "resources-discovery.json")
    monkeypatch.setattr(core, "RESOURCES_CAS",
                        var / "core-runtime" / "resources-cas")
    monkeypatch.setattr(core, "PRIMARY_PROMPT_JOURNAL",
                        var / "core-runtime" / "primary-prompt-ownership.json")
    monkeypatch.setattr(core, "PRIMARY_PROMPT_BACKUPS",
                        var / "core-runtime" / "primary-prompt-backups")
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS",
                        var / "core-runtime" / "resources-skill-overlays")
    monkeypatch.setattr(core, "NATIVE_ADOPTION_INGRESS_BACKUP",
                        var / "core-runtime" / "native-adoption-ingress-backup.json")
    monkeypatch.setattr(core, "UNIT", unit_dir / core.SERVICE)
    monkeypatch.setattr(core, "LAUNCHER", libexec / "hermes-jarvis-core-launcher")
    monkeypatch.setattr(core, "HOME", home.parent)
    monkeypatch.setattr(core, "HERMES_HOME", home)
    monkeypatch.setattr(core, "WORKSPACE", home / "workspaces" / "jarvis-core")
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "GATEWAY_GID", os.getgid())
    monkeypatch.setattr(core, "FILE_CONTRACT", (
        (core.UNIT, "unit_sha256", os.getuid(), os.getuid(), 0o644),
        (core.LAUNCHER, "launcher_sha256", os.getuid(), os.getuid(), 0o755),
        (core.TOKEN, "token_sha256", os.getuid(), os.getgid(), 0o640)))
    fixture_root = tmp_path.resolve()
    controlled_write_paths = (
        core.ETC_INSTALLER, core.VAR_LIB_INSTALLER,
        core.TOKEN, core.JOURNAL, core.RESOURCES_RECORD,
        core.RESOURCES_CAS, core.RESOURCES_MIGRATION_RECORD,
        core.PRIMARY_PROMPT_JOURNAL, core.PRIMARY_PROMPT_BACKUPS,
        core.RESOURCES_SKILL_OVERLAYS, core.ADAPTER_MIGRATION_BACKUP,
        core.ADAPTER_UPDATE_BACKUPS, core.ADAPTER_UPDATE_COHORT,
        core.NATIVE_ADOPTION_INGRESS_BACKUP,
    )
    outside = [str(path) for path in controlled_write_paths
               if not path.resolve().is_relative_to(fixture_root)]
    if service_root is not None:
        if (core.UNIT.resolve() != (service_root / "etc/systemd/system" / core.SERVICE).resolve()
                or core.LIBEXEC_DIR.resolve() != (service_root / "usr/local/libexec").resolve()
                or core.LAUNCHER.resolve() != (service_root / "usr/local/libexec/hermes-jarvis-core-launcher").resolve()):
            raise AssertionError("only the exact disposable service files may use public fixture custody")
    else:
        outside.extend(str(path) for path in (core.SYSTEMD_UNIT_DIR, core.LIBEXEC_DIR,
                                               core.UNIT, core.LAUNCHER)
                       if not path.resolve().is_relative_to(fixture_root))
    if outside:
        raise AssertionError(f"Core fixture write paths escaped tmp_path: {outside}")
    if not core.HERMES_HOME.resolve().is_relative_to(fixture_root):
        raise AssertionError("initial Core fixture Hermes home is outside tmp_path")
    monkeypatch.setattr(core.os, "geteuid", lambda: 0)

    class Account:
        pw_uid = 1000
        pw_gid = 1000
        pw_dir = "/home/admin"

    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    monkeypatch.setattr(core.grp, "getgrgid", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    identity = {"commit": core.COMMIT, "lock_sha256": core.LOCK_SHA256,
                "python_sha256": "a" * 64, "python_link": "pinned-link",
                "python_uid": 1000, "python_gid": 1000, "python_mode": 0o755}
    monkeypatch.setattr(core, "_identity", lambda **_kwargs: identity)
    monkeypatch.setattr(core, "_owned_listener", lambda **_kwargs: True)
    monkeypatch.setattr(core, "_launcher",
                        lambda adapter_source=None: b"test fixed core launcher")
    monkeypatch.setattr(core, "_install_bundled_resources", lambda _account: _resource_receipt())

    def write_fixture_resources_discovery(*, repair_umask_dirs=False):
        """Write a source-bound receipt and real immutable archive for cohort tests."""
        from hermes_installer.registry import manual_jarvis_skills as native

        archive = native.build_manual_jarvis_skills_artifact()
        artifact_sha = hashlib.sha256(archive).hexdigest()
        manifest, files = native._read_artifact(archive, artifact_sha)
        journal_raw = core._projection_file(
            core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID,
            mode=0o600, maximum=64 * 1024)
        core._ensure_dir(core.RESOURCES_CAS, core.ROOT_UID, core.ROOT_UID, 0o700)
        core._atomic_replace(core.RESOURCES_CAS / (artifact_sha + ".zip"),
                             archive, 0o600, core.ROOT_UID, core.ROOT_UID)
        record = {
            "schema": 3,
            "native_readback_method": "root-pinned-hermes-loader-v2",
            "core_source_generation": core._core_source_generation(),
            "core_ownership_sha256": hashlib.sha256(journal_raw).hexdigest(),
            "hermes_revision": core.COMMIT,
            "python_version": "3.14.7",
            "resources_revision": manifest["source"]["revision"],
            "resources_tree": manifest["source"]["git_tree"],
            "artifact_sha256": artifact_sha,
            "ownership_manifest_sha256": hashlib.sha256(
                native._canonical_json(manifest)).hexdigest(),
            "loaded_skill_inventory_sha256": hashlib.sha256(
                native._canonical_json([
                    {"path": name, "size_bytes": len(content),
                     "sha256": hashlib.sha256(content).hexdigest()}
                    for name, content in sorted(files.items())])).hexdigest(),
            "active_primary_prompt_sha256": hashlib.sha256(b"fixture active prompt").hexdigest(),
            "bundled_primary_prompt_sha256": hashlib.sha256(
                files["registry/profiles/hermes/SOUL.md"]).hexdigest(),
            "active_prompt_matches_bundled_primary": False,
            "effective_overlay": manifest["effective_overlay"],
            "resource_counts": {"native_skills": 396, "internal_profiles": 207,
                                "source_profiles_preserved": 208,
                                "other_declarations_preserved": 88},
            "observed_at_utc": "2026-10-13T00:00:00Z",
            "state": "discovered", "functional": False,
            "enabled": False, "target_verified": False,
        }
        core._atomic_replace(
            core.RESOURCES_RECORD,
            (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600, core.ROOT_UID, core.ROOT_UID)
        return record

    monkeypatch.setattr(core, "_write_resources_discovery", write_fixture_resources_discovery)

    def read_fixture_resources_discovery(*, core_source_generation):
        """Project only a fixture receipt whose journal and CAS still join."""
        try:
            raw = core._projection_file(core.RESOURCES_RECORD, owner=core.ROOT_UID,
                                        group=core.ROOT_UID, mode=0o600, maximum=16 * 1024)
            record = json.loads(raw)
            journal_raw = core._projection_file(core.JOURNAL, owner=core.ROOT_UID,
                group=core.ROOT_UID, mode=0o600, maximum=64 * 1024)
            archive = core._projection_file(core.RESOURCES_CAS / (record["artifact_sha256"] + ".zip"),
                owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
        except (OSError, KeyError, ValueError, TypeError):
            return {"resources_state": "stale"}
        if (record.get("core_source_generation") != core_source_generation
                or record.get("core_ownership_sha256") != hashlib.sha256(journal_raw).hexdigest()
                or hashlib.sha256(archive).hexdigest() != record.get("artifact_sha256")
                or record.get("state") != "discovered"):
            return {"resources_state": "stale"}
        from hermes_installer.registry import manual_jarvis_skills as native
        manifest, _files = native._read_artifact(archive, record["artifact_sha256"])
        source = manifest.get("source")
        if (not isinstance(source, dict)
                or record.get("resources_revision") != source.get("revision")
                or record.get("resources_tree") != source.get("git_tree")):
            return {"resources_state": "stale"}
        try:
            # Before a cohort is committed, the active owner overlay is still
            # anchored to the installed A0 base.  The incoming helper source
            # builds A1, so the strict overlay reader correctly refuses to
            # resolve that old record against A1.  Public discovery reports
            # this transition window as stale; keep the fixture projection
            # aligned with that contract rather than treating the refusal as
            # a malformed journal.
            overlay_record, overlay_contents, overlay_raw = core._resources_skill_overlay_read()
            effective_archive, effective_sha = core._current_resources_overlay_artifact(
                native.build_manual_jarvis_skills_artifact(), overlay_record,
                overlay_contents, overlay_raw)
        except core.CoreRuntimeError:
            return {"resources_state": "stale"}
        if effective_sha != record["artifact_sha256"] or effective_archive != archive:
            return {"resources_state": "stale"}
        return {"resources_state": "discovered", "artifact_sha256": record["artifact_sha256"],
                "resources_revision": source["revision"],
                "resource_counts": record["resource_counts"]}

    monkeypatch.setattr(core, "read_current_resources_discovery", read_fixture_resources_discovery)

    calls = []
    enabled = {"value": False}
    failure = {"pending": fail_enable_once}

    def fake_run(argv, check=True):
        calls.append((tuple(argv), core.UNIT.exists()))
        out = ""
        if argv[:2] == ["systemctl", "is-active"]:
            out = "active" if enabled["value"] else "inactive"
        elif argv[:2] == ["systemctl", "show"] and "FragmentPath" in argv[2]:
            out = str(core.UNIT) if core.UNIT.exists() else ""
        elif argv[:2] == ["systemctl", "show"] and "MainPID" in argv[2]:
            out = "0"
        elif argv[:2] == ["systemctl", "enable"]:
            if failure["pending"]:
                failure["pending"] = False
                if check:
                    raise core.CoreRuntimeError("injected service start failure")
            enabled["value"] = True
        elif argv[:2] == ["systemctl", "disable"]:
            enabled["value"] = False
        elif argv[:2] == ["systemctl", "stop"]:
            enabled["value"] = False
        elif argv[:2] in (["systemctl", "start"], ["systemctl", "restart"]):
            enabled["value"] = True
        return SimpleNamespace(stdout=out, returncode=0)

    monkeypatch.setattr(core, "_run", fake_run)
    monkeypatch.setattr(core, "_wait_for_listener", lambda: None)
    return calls, enabled


def test_install_resume_and_rollback_use_only_fixed_owned_paths(tmp_path, monkeypatch):
    calls, enabled = _fake_runtime(tmp_path, monkeypatch)
    recovery_lock_states = []
    original_locked_recovery = core._recover_interrupted_adapter_update_locked
    def observe_locked_recovery():
        recovery_lock_states.append(core._ADAPTER_UPDATE_LOCK_HELD.get())
        return original_locked_recovery()
    monkeypatch.setattr(core, "_recover_interrupted_adapter_update_locked",
                        observe_locked_recovery)
    preserve = core.HERMES_HOME / "auth.json"
    preserve.write_text("user credential")
    first = core.install_or_resume()
    token = core.TOKEN.read_bytes()
    second = core.install_or_resume()
    assert token == core.TOKEN.read_bytes()
    assert enabled["value"]
    assert recovery_lock_states == [True, True]
    assert "listener verified" in first and "listener verified" in second
    assert preserve.read_text() == "user credential"
    monkeypatch.setattr(core, "_owned_listener", lambda: False)
    assert core.rollback().startswith("journal-owned core service files removed")
    assert not core.UNIT.exists() and not core.LAUNCHER.exists()
    assert preserve.read_text() == "user credential"
    assert any(argv == ("systemctl", "daemon-reload") and not unit_exists
               for argv, unit_exists in calls)


def test_interrupted_recovery_reuses_an_already_held_lock(tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch)
    _prepare_adapter_lock_state_fixture()
    def fail_if_nested_lock():
        raise AssertionError("held recovery attempted a nested adapter lock")

    def fail_during_protected_read(*, allow_absent=False):
        assert allow_absent is True
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        raise core.CoreRuntimeError("injected protected cohort read failure")

    with core._adapter_update_lock():
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        monkeypatch.setattr(core, "_adapter_update_lock", fail_if_nested_lock)
        monkeypatch.setattr(core, "_read_adapter_update_cohort", fail_during_protected_read)
        with pytest.raises(core.CoreRuntimeError, match="injected protected cohort read failure"):
            core._recover_interrupted_adapter_update()
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
    assert not core._ADAPTER_UPDATE_LOCK_HELD.get()


def test_interrupted_recovery_locks_before_cohort_read_and_releases_on_failure(
        tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch)
    _prepare_adapter_lock_state_fixture()
    events = []
    original_lock = core._adapter_update_lock

    @contextlib.contextmanager
    def observed_lock():
        events.append("lock-enter")
        try:
            with original_lock():
                assert core._ADAPTER_UPDATE_LOCK_HELD.get()
                yield
        finally:
            assert not core._ADAPTER_UPDATE_LOCK_HELD.get()
            events.append("lock-exit")

    def fail_during_protected_read(*, allow_absent=False):
        assert allow_absent is True
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        events.append("cohort-read")
        raise core.CoreRuntimeError("injected protected cohort read failure")

    monkeypatch.setattr(core, "_adapter_update_lock", observed_lock)
    monkeypatch.setattr(core, "_read_adapter_update_cohort", fail_during_protected_read)
    with pytest.raises(core.CoreRuntimeError, match="injected protected cohort read failure"):
        core._recover_interrupted_adapter_update()
    assert events == ["lock-enter", "cohort-read", "lock-exit"]
    assert not core._ADAPTER_UPDATE_LOCK_HELD.get()


def _prepare_adapter_lock_state_fixture():
    """Create the pre-existing protected state parent expected by real lock setup."""
    for state_dir in (core.VAR_LIB_INSTALLER, core.JOURNAL.parent):
        state_dir.mkdir(mode=0o700)
        os.chown(state_dir, core.ROOT_UID, core.ROOT_UID)
        os.chmod(state_dir, 0o700)


def test_interrupted_recovery_rejects_non_root_before_lock_or_reads(monkeypatch):
    def forbidden_lock():
        raise AssertionError("non-root recovery attempted to acquire the Core update lock")

    monkeypatch.setattr(core.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(core, "_adapter_update_lock", forbidden_lock)
    with pytest.raises(core.CoreRuntimeError, match="requires Root"):
        core._recover_interrupted_adapter_update()


def test_launcher_uses_only_pinned_hermes_and_installer_adapter_paths():
    import shlex

    launcher = core._launcher().decode("ascii")
    expected = shlex.quote(f"{core.SOURCE}:{core.ADAPTER_SOURCE}")
    assert f"export PYTHONPATH={expected}" in launcher
    assert "python -P -m hermes_cli.main" in launcher


def test_generated_core_launcher_has_valid_shell_syntax():
    result = subprocess.run(
        ["sh", "-n"], input=core._launcher(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=5,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_native_plugin_bootstrap_embedded_scripts_parse_on_target_runtime():
    from hermes_installer.remote import native_plugin_bootstrap as bootstrap

    scripts = (
        bootstrap._OFFICIAL_ENABLE_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_READ_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_BACKUP_SCRIPT,
        bootstrap._OFFICIAL_SELECTION_RESTORE_SCRIPT,
    )
    for index, source in enumerate(scripts):
        compile(source, f"native-plugin-bootstrap-script-{index}", "exec")


def _install_legacy_service_fixture(tmp_path, monkeypatch, *, journal_state="active",
                                    public_service_files=False, request=None):
    if journal_state not in {"installed", "active"}:
        raise ValueError("legacy fixture journal state must be installed or active")
    calls, enabled = _fake_runtime(tmp_path, monkeypatch,
        public_service_files=public_service_files, request=request)
    # Establish a complete temporary owned install using the same fixture actor
    # and fixed temp paths; do not manufacture a journal fragment by hand.
    core.install_or_resume()
    launcher_bytes = core._legacy_launcher()
    core.LAUNCHER.write_bytes(launcher_bytes)
    core.LAUNCHER.chmod(0o755)
    record = json.loads(core.JOURNAL.read_text())
    record.update({"state": journal_state,
                   "launcher_sha256": hashlib.sha256(launcher_bytes).hexdigest(),
                   "unit_sha256": hashlib.sha256(core._unit()).hexdigest()})
    core.JOURNAL.write_text(json.dumps(record, sort_keys=True) + "\n")
    core.JOURNAL.chmod(0o600)
    if public_service_files:
        service_root = core.UNIT.parents[3]
        expected_files = {core.UNIT.resolve(), core.LAUNCHER.resolve()}
        actual_files = {path.resolve() for path in service_root.rglob("*") if path.is_file()}
        expected_directories = {
            service_root.resolve(),
            (service_root / "etc").resolve(),
            (service_root / "etc" / "systemd").resolve(),
            core.UNIT.parent.resolve(),
            (service_root / "usr").resolve(),
            (service_root / "usr" / "local").resolve(),
            core.LAUNCHER.parent.resolve(),
        }
        actual_directories = {
            path.resolve() for path in service_root.rglob("*") if path.is_dir()
        } | {service_root.resolve()}
        root_stat = service_root.stat()
        directory_custody = all(
            not path.is_symlink()
            and stat.S_ISDIR(path.lstat().st_mode)
            and (path.lstat().st_uid, path.lstat().st_gid,
                 stat.S_IMODE(path.lstat().st_mode)) == (core.ROOT_UID, core.ROOT_UID, 0o755)
            for path in (service_root, service_root / "etc", service_root / "etc" / "systemd",
                         core.UNIT.parent, service_root / "usr", service_root / "usr" / "local",
                         core.LAUNCHER.parent)
        )
        if (actual_files != expected_files or actual_directories != expected_directories
                or not directory_custody
                or (root_stat.st_uid, root_stat.st_gid, stat.S_IMODE(root_stat.st_mode))
                    != (core.ROOT_UID, core.ROOT_UID, 0o755)):
            raise AssertionError(
                "public fixture tree must retain only the two owned service files and "
                "root-only-to-admin traversal ancestors")
    # The production recipe is the post-migration comparator. The on-disk
    # legacy launcher and journal hashes above remain the migration input.
    monkeypatch.setattr(core, "_launcher", _REAL_CORE_LAUNCHER)
    monkeypatch.setattr(core, "ADAPTER_MIGRATION_BACKUP",
                        core.JOURNAL.parent / "adapter-migration-backup")
    monkeypatch.setattr(core, "_core_source_generation", lambda: "c" * 64)
    monkeypatch.setattr(core, "_identity", lambda **_kwargs: {
        "commit": core.COMMIT, "lock_sha256": core.LOCK_SHA256,
        "python_sha256": "a" * 64, "python_link": "pinned-link",
        "python_uid": 1000, "python_gid": 1000, "python_mode": 0o755,
    })
    bootstrap = ModuleType("hermes_installer.remote.native_plugin_bootstrap")
    native_plugin_files = ("plugin.yaml", "__init__.py")
    plugin_bundles = {
        "old": {"plugin.yaml": b"manifest-v1\n", "__init__.py": b"old native tools\n"},
        "new": {"plugin.yaml": b"manifest-v1\n", "__init__.py": b"new native tools\n"},
    }
    installed_plugin = {name: value for name, value in plugin_bundles["old"].items()}
    member_inodes = {name: 200 + index for index, name in enumerate(native_plugin_files)}
    def plugin_snapshot():
        signatures = {name: (1, member_inodes[name], 0o444, 0, 0, 1,
                             len(installed_plugin[name]), 1, member_inodes[name])
                     for name in native_plugin_files}
        return NativeResourcesPluginMemberSnapshot(MappingProxyType(dict(installed_plugin)),
                                                   MappingProxyType(signatures))
    class NativeResourcesPluginMemberSnapshot:
        def __init__(self, members, signatures):
            self.members = members
            self.signatures = signatures
    bootstrap.NativeResourcesPluginMemberSnapshot = NativeResourcesPluginMemberSnapshot
    bootstrap.NativeResourcesPluginTransitionReceipt = type("NativeResourcesPluginTransitionReceipt", (), {})
    bootstrap.read_installed_native_resources_plugin_members = plugin_snapshot
    def transition_receipt(operation):
        context = core._current_native_resources_plugin_transition()
        calls.append((("native-plugin", operation), core._run(
            ["systemctl", "is-active", core.SERVICE], False).stdout.strip()))
        if operation == "install":
            installed_plugin.update(context.new_members)
            member_inodes["__init__.py"] += 1
        elif operation == "restore":
            installed_plugin.update(context.old_members)
            member_inodes["__init__.py"] += 1
        if operation in {"install", "restore"}:
            plugin_directory = core.HERMES_HOME / "plugins" / "hermes-installer-resources-delegation"
            for name, content in installed_plugin.items():
                member = plugin_directory / name
                member.write_bytes(content)
                os.chown(member, core.ROOT_UID, core.ROOT_UID)
                os.chmod(member, 0o444)
        installed = dict(installed_plugin)
        signatures = dict(plugin_snapshot().signatures)
        hashes = lambda members: {name: hashlib.sha256(members[name]).hexdigest()
                                  for name in native_plugin_files}
        metadata = {"schema": 1, "operation": operation,
            "cohort_transaction_id": context.cohort_transaction_id,
            "old_adapter_generation": context.old_adapter_generation,
            "new_adapter_generation": context.new_adapter_generation,
            "plugin_selection_sha256": context.plugin_selection_sha256,
            "old_member_sha256": hashes(dict(context.old_members)),
            "new_member_sha256": hashes(dict(context.new_members)),
            "installed_member_sha256": hashes(installed),
            "installed_member_signatures": {name: list(signatures[name])
                for name in native_plugin_files}}
        receipt = bootstrap.NativeResourcesPluginTransitionReceipt()
        for key, value in metadata.items():
            if key == "installed_member_signatures":
                value = MappingProxyType({name: tuple(signature) for name, signature in value.items()})
            elif key in {"old_member_sha256", "new_member_sha256", "installed_member_sha256"}:
                value = MappingProxyType(value)
            setattr(receipt, key, value)
        receipt.receipt_sha256 = hashlib.sha256(
            json.dumps(metadata, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("ascii")).hexdigest()
        return receipt
    bootstrap.prepare_native_resources_plugin_transition = lambda: transition_receipt("prepare")
    bootstrap.install_native_resources_plugin_transition = lambda: transition_receipt("install")
    bootstrap.restore_native_resources_plugin_transition = lambda: transition_receipt("restore")
    def enable_plugin():
        calls.append((("bridge", "enable"), core.UNIT.exists()))
        return SimpleNamespace(plugin_key="hermes-installer-resources-delegation")
    bootstrap.enable_native_resources_plugin = enable_plugin
    selection = {"value": "d" * 64}
    bootstrap.verify_native_resources_plugin_selection = lambda: SimpleNamespace(
        plugin_key="hermes-installer-resources-delegation", selection_sha256=selection["value"])
    bootstrap.capture_native_resources_plugin_selection = lambda: SimpleNamespace(
        plugin_key="hermes-installer-resources-delegation", snapshot_json=b'{"schema":1}',
        prior_selection_sha256="e" * 64, migrated_selection_sha256="d" * 64)
    def restore_selection(_snapshot, *, expected_current_sha256):
        assert expected_current_sha256 == "d" * 64
        selection["value"] = "e" * 64
        return "e" * 64
    bootstrap.restore_native_resources_plugin_selection = restore_selection
    inspector = ModuleType("hermes_installer.remote.core_gateway_inspector")
    inspector._current_native_adapter_generation = lambda *, deadline: "a" * 64
    inspector.verify_staged_native_resources_plugin = lambda *, deadline: "b" * 64
    inspector.CORE_NATIVE_ADAPTER_SOURCE_FILES = {
        "hermes_installer/components/resources_native_plugin_bundle/" + name:
            hashlib.sha256(plugin_bundles["new"][name]).hexdigest()
        for name in native_plugin_files}
    monkeypatch.setitem(sys.modules,
                        "hermes_installer.remote.native_plugin_bootstrap", bootstrap)
    monkeypatch.setitem(sys.modules,
                        "hermes_installer.remote.core_gateway_inspector", inspector)
    # Core uses `from .remote import ...`, which can resolve an already cached
    # package attribute instead of the replacement sys.modules entries above.
    # Keep both import routes bound to these same explicit fixture adapters.
    import hermes_installer.remote as remote_package
    monkeypatch.setattr(remote_package, "native_plugin_bootstrap", bootstrap, raising=False)
    monkeypatch.setattr(remote_package, "core_gateway_inspector", inspector, raising=False)
    monkeypatch.setattr(core, "_native_plugin_source_members",
        lambda source: dict(plugin_bundles["new" if Path(source) == core.ADAPTER_SOURCE else "old"]))
    return calls, enabled, launcher_bytes, selection


@pytest.mark.skipif(os.geteuid() != 0 or not hasattr(os, "pidfd_open"),
                    reason="native plugin transition scope requires the real Root actor and PIDFD")
def test_core_native_plugin_prepare_scope_drives_real_bootstrap_receipt(tmp_path, monkeypatch):
    from hermes_installer.remote import native_plugin_bootstrap as bootstrap

    plugin_directory = tmp_path / "fixed-native-plugin"
    plugin_directory.mkdir(mode=0o700)
    old_members = {"plugin.yaml": b"fixed manifest\n", "__init__.py": b"old native module\n"}
    new_members = {"plugin.yaml": b"fixed manifest\n", "__init__.py": b"new native module\n"}
    assert old_members["plugin.yaml"] == new_members["plugin.yaml"]
    assert old_members["__init__.py"] != new_members["__init__.py"]
    for name, content in old_members.items():
        member = plugin_directory / name
        member.write_bytes(content)
        member.chmod(0o444)
    plugin_directory.chmod(0o555)
    monkeypatch.setattr(bootstrap, "_transition_plugin_directory_fd",
                        lambda: os.open(plugin_directory, os.O_RDONLY | os.O_DIRECTORY))
    selection_sha = "d" * 64
    monkeypatch.setattr(bootstrap, "verify_native_resources_plugin_selection",
                        lambda: SimpleNamespace(selection_sha256=selection_sha))
    inspector = ModuleType("hermes_installer.remote.core_gateway_inspector")
    inspector._current_native_adapter_generation = lambda *, deadline: "b" * 64
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_gateway_inspector", inspector)
    monkeypatch.setattr(core, "_core_source_generation", lambda: "c" * 64)
    monkeypatch.setattr(core, "_owned_listener_pidfd", lambda **_kwargs: True)
    snapshot = bootstrap.read_installed_native_resources_plugin_members()
    pidfd = os.pidfd_open(os.getpid(), 0)
    lock_token = core._ADAPTER_UPDATE_LOCK_HELD.set(True)
    state_token = core._NATIVE_PLUGIN_TRANSITION_STATE.set({
        "old_source": str(core.SOURCE), "new_source": str(core.ADAPTER_SOURCE),
        "old_adapter_generation": "a" * 64, "new_adapter_generation": "b" * 64,
        "old_core_source_generation": "c" * 64, "plugin_selection_sha256": selection_sha,
        "old_members": old_members, "new_members": new_members,
        "old_signatures": dict(snapshot.signatures), "old_pidfd": pidfd,
        "cohort_raw": None,
    })
    try:
        receipt = core._run_native_plugin_transition("prepare")
        assert receipt.operation == "prepare"
        assert dict(receipt.old_member_sha256) == core._native_plugin_member_hashes(old_members)
        assert dict(receipt.new_member_sha256) == core._native_plugin_member_hashes(new_members)
        assert dict(receipt.installed_member_sha256) == core._native_plugin_member_hashes(old_members)
        assert dict(bootstrap.read_installed_native_resources_plugin_members().members) == old_members
    finally:
        core._NATIVE_PLUGIN_TRANSITION_STATE.reset(state_token)
        core._ADAPTER_UPDATE_LOCK_HELD.reset(lock_token)
        os.close(pidfd)


@pytest.mark.skipif(os.geteuid() != 0, reason="source custody fixture requires Root-owned files")
def test_native_plugin_source_accepts_root_0644_but_rejects_group_write(tmp_path):
    member = tmp_path / "plugin-module.py"
    member.write_bytes(b"bounded module\n")
    member.chmod(0o644)
    assert core._native_plugin_source_member_metadata_matches(member.stat())
    member.chmod(0o664)
    assert not core._native_plugin_source_member_metadata_matches(member.stat())


_REAL_CORE_LAUNCHER = core._launcher


def _fixture_prior_adapter_source():
    """Return the historical source alias only inside Root's private /opt view."""
    if os.environ.get("HERMES_PI_FIXTURE_PRIVATE_OPT") != "1":
        raise AssertionError("adapter-generation fixture requires Root's private /opt namespace")
    mount_types = set()
    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = row.split()
        if len(fields) > 6 and fields[4] == "/opt" and "-" in fields:
            separator = fields.index("-")
            if separator + 1 < len(fields):
                mount_types.add(fields[separator + 1])
    if mount_types != {"tmpfs"}:
        raise AssertionError("fixture /opt must be a private tmpfs mount")
    source = Path("/opt/hermes-installer-core-fffffffff/src")
    core._validate_adapter_generation_path(source)
    return source


def _rebind_migrated_fixture_to_prior_generation():
    """Give migration tests a distinct, custody-valid historical generation."""
    source = _fixture_prior_adapter_source()
    record, raw, _files = core._read_active_adapter_runtime()
    generation = "9" * 64
    launcher = _REAL_CORE_LAUNCHER(adapter_source=source)
    unit = core._unit(adapter_source=source)
    core._atomic_replace(core.UNIT, unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    core._atomic_replace(core.LAUNCHER, launcher, 0o755, core.ROOT_UID, core.ROOT_UID)
    updated = dict(record)
    updated.update({
        "adapter_source": str(source),
        "adapter_generation": generation,
        "unit_sha256": hashlib.sha256(unit).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
    })
    core._replace_journal(updated)
    # The controlled discovery projection follows the exact migrated journal;
    # it is not left bound to the pre-migration service snapshot.
    resources_raw = core._projection_file(
        core.RESOURCES_RECORD, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o600, maximum=16 * 1024)
    resources = json.loads(resources_raw)
    current_journal = core._projection_file(
        core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o600, maximum=64 * 1024)
    resources["core_source_generation"] = core._core_source_generation()
    resources["core_ownership_sha256"] = hashlib.sha256(current_journal).hexdigest()
    core._atomic_replace(
        core.RESOURCES_RECORD,
        (json.dumps(resources, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
        0o600, core.ROOT_UID, core.ROOT_UID)
    return source


def _rebind_fixture_resources_to_current_journal():
    """Refresh only the fixture receipt join after a deliberate journal rewrite."""
    resources_raw = core._projection_file(
        core.RESOURCES_RECORD, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o600, maximum=16 * 1024)
    resources = json.loads(resources_raw)
    current_journal = core._projection_file(
        core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o600, maximum=64 * 1024)
    resources["core_source_generation"] = core._core_source_generation()
    resources["core_ownership_sha256"] = hashlib.sha256(current_journal).hexdigest()
    core._atomic_replace(
        core.RESOURCES_RECORD,
        (json.dumps(resources, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
        0o600, core.ROOT_UID, core.ROOT_UID)
    assert core.read_current_resources_discovery(
        core_source_generation=resources["core_source_generation"]
    )["resources_state"] == "stale"


def _fake_update_pidfd(monkeypatch, enabled, request):
    """Model one live PIDFD per fake service incarnation."""
    fixture_pipe_fds = set()
    writers = {}
    latest = {"pidfd": None}
    # The real PIDFD listener verifier must observe a live OS process. Model
    # the fake systemd MainPID as this test process while keeping Core's held
    # incarnation PIDFDs as independently stoppable pipes below.
    pid = os.getpid()

    def cleanup_pipe():
        for fd in tuple(fixture_pipe_fds):
            fixture_pipe_fds.discard(fd)
            try:
                os.close(fd)
            except OSError:
                pass

    request.addfinalizer(cleanup_pipe)

    def close_writer(pidfd):
        writer = writers.pop(pidfd, None)
        if writer is not None:
            fixture_pipe_fds.discard(writer)
            os.close(writer)

    def identity(source, adapter_generation, core_generation, actual_pid):
        assert actual_pid == pid
        evidence = {"boot_id": "fixture-boot", "pid": pid, "start_ticks": "1",
                    "adapter_source": str(source), "adapter_generation": adapter_generation,
                    "core_source_generation": core_generation, "invocation_id": "1" * 32,
                    "cgroup_sha256": "2" * 64, "argv_sha256": "3" * 64}
        return evidence, hashlib.sha256(core._canonical_json(evidence)).hexdigest()

    def capture(source, adapter_generation, core_generation):
        evidence, digest = identity(source, adapter_generation, core_generation, pid)
        # A restarted fake service gets a new unread pipe. Reusing the old
        # pipe would leave the new process's pseudo-PIDFD readable at EOF.
        pipe_read_fd, write_fd = os.pipe()
        fixture_pipe_fds.update((pipe_read_fd, write_fd))
        pidfd = os.dup(pipe_read_fd)
        writers[pidfd] = write_fd
        latest["pidfd"] = pidfd
        # Core owns and closes the returned duplicate; fixture cleanup retains
        # only its original endpoints, so descriptor reuse cannot close an
        # unrelated process FD in the finalizer.
        return pidfd, pid, evidence, digest

    def stop(pidfd, actual_pid, source, adapter_generation, core_generation, expected):
        _evidence, actual = identity(source, adapter_generation, core_generation, actual_pid)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP)
        assert actual == expected and not poller.poll(0)
        core._run(["systemctl", "stop", core.SERVICE])
        close_writer(pidfd)
        enabled["value"] = False
        assert poller.poll(0)
        assert core._run(["systemctl", "is-active", core.SERVICE], False).stdout.strip() != "active"

    def stop_owned(allowed_sources):
        if enabled["value"]:
            assert any(core._owned_listener(adapter_source=source) for source in allowed_sources)
        core._run(["systemctl", "stop", core.SERVICE])
        enabled["value"] = False
        if latest["pidfd"] is not None:
            close_writer(latest["pidfd"])

    real_run = core._run

    def fake_service_main_pid(argv, check=True):
        if argv == ["systemctl", "show", "--property=MainPID", "--value", core.SERVICE]:
            return SimpleNamespace(stdout=(f"{pid}\n" if enabled["value"] else "0\n"),
                                   returncode=0)
        return real_run(argv, check)

    def fake_owned_listener(*, adapter_source=core.ADAPTER_SOURCE):
        if not enabled["value"]:
            return False
        try:
            journal = json.loads(core.JOURNAL.read_bytes())
        except (OSError, ValueError, TypeError):
            return False
        return journal.get("adapter_source") == str(adapter_source)

    monkeypatch.setattr(core, "_adapter_process_identity", identity)
    monkeypatch.setattr(core, "_capture_adapter_service_process", capture)
    monkeypatch.setattr(core, "_stop_captured_adapter_process", stop)
    monkeypatch.setattr(core, "_stop_owned_core_for_adapter_update", stop_owned)
    monkeypatch.setattr(core, "_owned_listener", fake_owned_listener)
    monkeypatch.setattr(core, "_run", fake_service_main_pid)


def _prepare_cohort_resource_materialization(
        tmp_path, monkeypatch, request, *, registered_obsidian=False, owner_overlay=False):
    """Install a real old-helper generation and bind its receipt to the current journal."""
    from hermes_installer.registry import manual_jarvis_skills as native
    from hermes_installer.remote import obsidian_owner_lifecycle as obsidian

    # read_registration() opens a fixed root-owned absolute directory through
    # directory FDs. Keep this fixture hermetic by replacing that reader and
    # its selected paths; never inspect a host registration or vault.
    monkeypatch.setattr(obsidian, "OWNER_REGISTRATION",
                        core.JOURNAL.parent / "obsidian-registration.json")
    obsidian_fixture = None
    if registered_obsidian:
        account = core.pwd.getpwnam("admin")
        owner_root = tmp_path / "registered-owner-data"
        vault = owner_root / "obsidian-vault"
        vault.mkdir(parents=True, mode=0o700)
        vault_file = vault / "index.md"
        vault_file.write_bytes(b"private owner vault fixture\n")
        vault_file.chmod(0o600)
        os.chown(vault_file, account.pw_uid, account.pw_gid)
        os.chown(vault, account.pw_uid, account.pw_gid)
        os.chown(owner_root, account.pw_uid, account.pw_gid)
        owner_root.chmod(0o700)
        subject_sha = "9" * 64
        registration_raw = json.dumps({
            "schema": 1, "core_uid": 1000, "data_root": str(owner_root),
            "owner_subject_sha256": subject_sha,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        registration_path = obsidian.OWNER_REGISTRATION
        registration_path.write_bytes(registration_raw)
        registration_path.chmod(0o600)
        os.chown(registration_path, core.ROOT_UID, core.ROOT_UID)
        monkeypatch.setattr(obsidian, "OWNER_DATA_ROOT", owner_root)

        def fixture_read_registration():
            info = registration_path.lstat()
            current = registration_path.read_bytes()
            value = json.loads(current, object_pairs_hook=obsidian._unique_pairs)
            if (not stat.S_ISREG(info.st_mode)
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
                    != (core.ROOT_UID, core.ROOT_UID, 0o600, 1)
                    or info.st_size != len(current) or current != registration_raw
                    or json.dumps(value, sort_keys=True, separators=(",", ":"),
                                  allow_nan=False).encode("utf-8") != current
                    or value != {
                    "schema": 1, "core_uid": 1000, "data_root": str(owner_root),
                    "owner_subject_sha256": subject_sha}):
                raise RuntimeError("controlled Obsidian registration changed")
            return owner_root, subject_sha, hashlib.sha256(current).hexdigest()

        monkeypatch.setattr(obsidian, "read_registration", fixture_read_registration)
        obsidian_fixture = {
            "registration_path": registration_path,
            "registration_bytes": registration_raw,
            "vault_root": vault,
            "vault_files": {"index.md": b"private owner vault fixture\n"},
        }
    else:
        def fixture_registration_absent():
            raise FileNotFoundError

        monkeypatch.setattr(obsidian, "read_registration", fixture_registration_absent)

    archive = native.build_manual_jarvis_skills_artifact()
    artifact_sha = hashlib.sha256(archive).hexdigest()
    manifest, files = native._read_artifact(archive, artifact_sha)
    previous_helper = b"retained helper from the controlled prior generation\n"
    manifest["installer"] = {
        "archive_path": "manual_stage_jarvis_skills.py",
        "size_bytes": len(previous_helper),
        "sha256": hashlib.sha256(previous_helper).hexdigest(),
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as package:
        native._zip_write(package, "manifest.json", native._canonical_json(manifest))
        for name, content in sorted(files.items()):
            native._zip_write(package, name, content)
        native._zip_write(package, "manual_stage_jarvis_skills.py", previous_helper)
    old_archive = stream.getvalue()
    old_sha = hashlib.sha256(old_archive).hexdigest()
    old_base_archive, old_base_sha = old_archive, old_sha
    if owner_overlay:
        from hermes_installer.registry import resources_skill_overlay as transform

        overlay_rows = {}
        overlay_payloads = {}
        selected_skills = sorted(manifest["skill_members"], key=lambda row: row["skill_id"])[:2]
        for index, row in enumerate(selected_skills):
            skill_id = row["skill_id"]
            overlay_content = (
                f"---\nname: {skill_id}\n---\ncontrolled owner overlay {index + 1}\n"
            ).encode("utf-8")
            old_archive, old_sha = transform.build_effective_artifact(
                old_archive, skill_id, overlay_content)
            content_sha = hashlib.sha256(overlay_content).hexdigest()
            overlay_payloads[skill_id] = overlay_content
            overlay_rows[skill_id] = {
                "content_sha256": content_sha,
                "archive_sha256": old_sha,
            }
        manifest, files = native._read_artifact(old_archive, old_sha)
        overlay_record = {
            "schema": 1,
            "base_artifact_sha256": old_base_sha,
            "skills": overlay_rows,
        }
        overlay_root = core.RESOURCES_SKILL_OVERLAYS
        overlay_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        overlay_raw = native._canonical_json(overlay_record)
        core._atomic_replace(overlay_root / "active.json", overlay_raw,
            0o600, core.ROOT_UID, core.ROOT_UID)
        for content_sha, overlay_content in (
                (hashlib.sha256(payload).hexdigest(), payload)
                for payload in overlay_payloads.values()):
            core._atomic_replace(overlay_root / (content_sha + ".bin"), overlay_content,
                0o600, core.ROOT_UID, core.ROOT_UID)

    # _hash_generation_tree enforces real root-owned ancestors and the exact
    # admin-owned .hermes subtree; keep the fixture inside a private root path.
    sandbox = Path(tempfile.mkdtemp(prefix="hermes-adapter-home-", dir="/root"))
    sandbox.chmod(0o700)
    request.addfinalizer(lambda: shutil.rmtree(sandbox, ignore_errors=True))
    admin_home = sandbox / "admin"
    home = admin_home / ".hermes"
    admin_home.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    # The generated systemd guard reads this installed pair through the
    # private HOME bind; model the actual root-owned files, not only receipts.
    plugin_directory = home / "plugins" / "hermes-installer-resources-delegation"
    plugin_directory.mkdir(parents=True, mode=0o700)
    (plugin_directory / "plugin.yaml").write_bytes(b"manifest-v1\n")
    (plugin_directory / "__init__.py").write_bytes(b"old native tools\n")
    prior_soul = b"# Existing owner instructions\nKeep these bytes before adoption.\n"
    (home / "SOUL.md").write_bytes(prior_soul)
    (home / "SOUL.md").chmod(0o600)
    # Capture while the migrated unit still matches the original HOME recipe.
    active_record = core._journal()
    monkeypatch.setattr(core, "HOME", admin_home)
    monkeypatch.setattr(core, "HERMES_HOME", home)
    monkeypatch.setattr(native, "_JARVIS_HOME", home)
    native.install_manual_jarvis_skills(
        old_archive, hermes_home=home, expected_sha256=old_sha)

    account = core.pwd.getpwnam("admin")
    for root, directories, filenames in os.walk(home, topdown=False, followlinks=False):
        for filename in filenames:
            os.chown(Path(root) / filename, account.pw_uid, account.pw_gid,
                     follow_symlinks=False)
        for dirname in directories:
            os.chown(Path(root) / dirname, account.pw_uid, account.pw_gid,
                     follow_symlinks=False)
    os.chown(home, account.pw_uid, account.pw_gid)
    os.chown(admin_home, account.pw_uid, account.pw_gid)
    os.chmod(home, 0o700)
    os.chmod(admin_home, 0o700)
    os.chown(plugin_directory, core.ROOT_UID, core.ROOT_UID)
    os.chmod(plugin_directory, 0o555)
    for plugin_member in (plugin_directory / "plugin.yaml",
                          plugin_directory / "__init__.py"):
        os.chown(plugin_member, core.ROOT_UID, core.ROOT_UID)
        os.chmod(plugin_member, 0o444)
    _bind_private_fixed_hermes_home(home, request)
    fixed_home = Path("/home/admin")
    fixed_hermes_home = fixed_home / ".hermes"
    monkeypatch.setattr(core, "HOME", fixed_home)
    monkeypatch.setattr(core, "HERMES_HOME", fixed_hermes_home)
    monkeypatch.setattr(native, "_JARVIS_HOME", fixed_hermes_home)

    # The migrated adapter recipe embeds HOME paths. Rebuild its complete
    # journaled service files after selecting the isolated fixture home, before
    # the later helper rebind asks the production reader to verify that recipe.
    active_source = Path(active_record["adapter_source"])
    active_unit = core._unit(adapter_source=active_source)
    active_launcher = core._launcher(adapter_source=active_source)
    core._atomic_replace(core.UNIT, active_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    core._atomic_replace(core.LAUNCHER, active_launcher, 0o755, core.ROOT_UID, core.ROOT_UID)
    active_record.update({
        "unit_sha256": hashlib.sha256(active_unit).hexdigest(),
        "launcher_sha256": hashlib.sha256(active_launcher).hexdigest(),
    })
    core._replace_journal(active_record)

    # Keep the receipt and immutable CAS tied to the actual prior-helper bytes.
    current_record = core._write_resources_discovery()
    ownership_sha = core._hash_generation_tree(home, manifest, files, old_sha)
    skill_inventory = native._canonical_json([
        {"skill_id": row["skill_id"],
         "sha256": hashlib.sha256(files[row["archive_path"]]).hexdigest()}
        for row in sorted(manifest["skill_members"], key=lambda item: item["skill_id"])
    ])
    active_prompt_sha = hashlib.sha256(prior_soul).hexdigest()
    bundled_prompt_sha = hashlib.sha256(files["registry/profiles/hermes/SOUL.md"]).hexdigest()
    effective_overlay = manifest["effective_overlay"]
    current_record.update({
        "artifact_sha256": old_sha,
        "ownership_manifest_sha256": ownership_sha,
        "loaded_skill_inventory_sha256": hashlib.sha256(skill_inventory).hexdigest(),
        "active_primary_prompt_sha256": active_prompt_sha,
        "bundled_primary_prompt_sha256": bundled_prompt_sha,
        "active_prompt_matches_bundled_primary": active_prompt_sha == bundled_prompt_sha,
        "effective_overlay": {key: effective_overlay.get(key) for key in (
            "overlay_id", "approval_commit", "sha256", "upstream_revision", "upstream_tree",
            "source_declarations", "compiled_profiles", "compiled_bundle")},
    })
    core._atomic_replace(core.RESOURCES_CAS / (old_sha + ".zip"), old_archive,
                         0o600, core.ROOT_UID, core.ROOT_UID)
    if owner_overlay:
        core._atomic_replace(core.RESOURCES_CAS / (old_base_sha + ".zip"), old_base_archive,
                             0o600, core.ROOT_UID, core.ROOT_UID)
    core._atomic_replace(
        core.RESOURCES_RECORD,
        (json.dumps(current_record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
        0o600, core.ROOT_UID, core.ROOT_UID)
    if os.geteuid() != account.pw_uid:
        # The importer verifier is intentionally bound to its current admin
        # process. Root must use Core's explicit UID-1000 descriptor verifier.
        with pytest.raises(native.ManualJarvisSkillsError, match="not owned by this Hermes user"):
            native._verify_owned_generation(home / "skills" / native._GENERATION,
                                            files, old_sha)
    assert core._hash_generation_tree(home, manifest, files, old_sha)
    fixture_discovery = core.read_current_resources_discovery(
        core_source_generation=current_record["core_source_generation"]
    )
    # Normal discovery uses the incoming helper and must stay strict: the
    # previous A0 helper differs, so only the locked migration verifier may
    # admit this exact old receipt during the transition.
    assert fixture_discovery["resources_state"] == "stale"
    assert current_record["resources_tree"] == manifest["source"]["git_tree"]

    # Cohort unit tests cover the filesystem/journal effects, while native
    # Hermes-loader and Core-provider proofs are qualified separately. Keep
    # those calls explicit and local to this controlled fixture; never contact
    # the host admin environment, a live provider, or the running Core service.
    readback_calls = []

    def fixture_native_readback(manifest, generation_files, active_prompt,
                                 *, expected_managed_block_sha256=None):
        from hermes_installer.registry.primary_prompt import render_managed_block

        bundled_prompt = generation_files["registry/profiles/hermes/SOUL.md"]
        managed_block = render_managed_block(bundled_prompt)
        active_sha = hashlib.sha256(active_prompt).hexdigest()
        bundled_sha = hashlib.sha256(bundled_prompt).hexdigest()
        contains_managed_block = managed_block in active_prompt
        actual_managed_block_sha256 = (
            hashlib.sha256(managed_block).hexdigest() if contains_managed_block else None
        )
        if expected_managed_block_sha256 is not None:
            assert actual_managed_block_sha256 == expected_managed_block_sha256
            assert contains_managed_block
        readback_calls.append((active_sha, actual_managed_block_sha256))
        return {
            "hermes_revision": core.COMMIT,
            "python_version": "3.14.7",
            "profile_id": "default",
            "profile_identity_loaded": True,
            "loaded_skill_count": len(manifest["skill_members"]),
            "loaded_skill_inventory_sha256": hashlib.sha256(
                core.native_inventory_bytes(manifest, generation_files)).hexdigest(),
            "active_primary_prompt_sha256": active_sha,
            "native_loaded_primary_prompt_sha256": active_sha,
            "bundled_primary_prompt_sha256": bundled_sha,
            "active_prompt_matches_bundled_primary": active_sha == bundled_sha,
            "managed_prompt_block_sha256": actual_managed_block_sha256,
            "effective_prompt_contains_managed_block": contains_managed_block,
            "effective_prompt_truncated": False,
            "native_effective_prompt_sha256": active_sha,
            "native_effective_prompt_chars": len(active_prompt.decode("utf-8")),
        }

    def fixture_startup_proof():
        context = core._ADAPTER_STARTUP_COHORT_CONTEXT.get()
        assert isinstance(context, dict)
        assert context["cohort"].get("phase") == "source-starting"
        assert context["pidfd"] is not None and context["pid"] == os.getpid()
        assert context.get("new_read") is not None
        assert core._validate_guarded_new_read(context["new_read"])
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        readback_calls.append(("startup-provider-fixture", context["cohort"]["cohort_transaction_id"]))
        return SimpleNamespace(state="fixture-provider-proof-not-live-evidence")

    def deny_host_subprocess(*_args, **_kwargs):
        raise AssertionError("cohort fixture attempted an unapproved host subprocess")

    monkeypatch.setattr(core, "_root_native_readback", fixture_native_readback)
    monkeypatch.setattr(core, "_prove_new_cohort_startup_chat", fixture_startup_proof)
    monkeypatch.setattr(core.subprocess, "run", deny_host_subprocess)
    return readback_calls, obsidian_fixture


def _assert_registered_obsidian_fixture_preserved(fixture):
    if fixture is None:
        return
    assert fixture["registration_path"].read_bytes() == fixture["registration_bytes"]
    actual_files = {
        path.relative_to(fixture["vault_root"]).as_posix(): path.read_bytes()
        for path in fixture["vault_root"].rglob("*") if path.is_file()
    }
    assert actual_files == fixture["vault_files"]


def _adapter_a0_migration_proof_inputs():
    """Build the real protected A0/A1 proof inputs without invoking migration."""
    from hermes_installer.registry import manual_jarvis_skills as native

    record, journal_raw, _files = core._read_active_adapter_runtime()
    journal_before, journal_identity = core._projection_file_snapshot(
        core.JOURNAL, owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600,
        maximum=64 * 1024)
    assert journal_before == journal_raw
    snapshots = core._snapshot_adapter_update_bindings(
        core_source_generation=record["core_source_generation"])
    old_discovery = json.loads(snapshots["resources_record"])
    old_artifact = old_discovery["artifact_sha256"]
    old_archive, old_archive_identity = core._projection_file_snapshot(
        core.RESOURCES_CAS / (old_artifact + ".zip"), owner=core.ROOT_UID,
        group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    overlay_record, overlay_contents, overlay_raw, overlay_identity, content_identities = (
        core._read_adapter_overlay_snapshot(with_identity=True))
    if overlay_raw is None:
        old_base, old_base_identity = old_archive, old_archive_identity
    else:
        base_sha = overlay_record["base_artifact_sha256"]
        old_base, old_base_identity = core._projection_file_snapshot(
            core.RESOURCES_CAS / (base_sha + ".zip"), owner=core.ROOT_UID,
            group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    marker = core._projection_file(
        core.HERMES_HOME / "skills" / native._GENERATION / native._OWNER_FILE,
        owner=1000, group=1000, mode=0o600, maximum=2 * 1024 * 1024)
    new_base = native.build_manual_jarvis_skills_artifact()
    if overlay_raw is not None:
        old_base_manifest, old_base_files = native._read_artifact(
            old_base, hashlib.sha256(old_base).hexdigest())
        _new_base_manifest, _new_base_files, _new_base_helper = native._read_transition_archive(
            new_base, hashlib.sha256(new_base).hexdigest())
        old_composed_manifest, old_composed_files = native._read_artifact(
            old_archive, old_artifact)
        # A real two-skill owner composition differs from pristine B1, while
        # the approved B0→B1 and derived A0→A1 transitions stay helper-only.
        assert len(overlay_contents) == 2
        assert native.verify_same_materialization_transition(
            old_base_manifest, old_base_files, _new_base_manifest, _new_base_files)
        assert not native.verify_same_materialization_transition(
            old_composed_manifest, old_composed_files, _new_base_manifest, _new_base_files)
    reconstruction = core._make_adapter_update_reconstruction(
        old_base, new_base, old_archive, overlay_record, overlay_contents, overlay_raw,
        marker, snapshots["resources_record"])
    old_manifest, old_files, old_helper = native._read_transition_archive(
        old_archive, old_artifact)
    _new_manifest, _new_files, new_helper = native._read_transition_archive(
        new_base, hashlib.sha256(new_base).hexdigest())
    assert old_helper != new_helper
    assert reconstruction.new_composed_artifact_sha256 != old_artifact
    new_composed_manifest, new_composed_files, _ = native._read_transition_archive(
        reconstruction.new_composed_archive, reconstruction.new_composed_artifact_sha256)
    assert native.verify_same_materialization_transition(
        old_manifest, old_files, new_composed_manifest, new_composed_files)
    return ({
        "core_source_generation": record["core_source_generation"],
        "journal_raw": journal_raw,
        "journal_identity": journal_identity,
        "snapshots": snapshots,
        "overlay_record": overlay_record,
        "overlay_contents": overlay_contents,
        "overlay_raw": overlay_raw,
        "overlay_identity": overlay_identity,
        "overlay_content_identities": content_identities,
        "old_artifact": old_artifact,
        "old_archive": old_archive,
        "old_archive_identity": old_archive_identity,
        "old_base_archive": old_base,
        "old_base_identity": old_base_identity,
        "reconstruction": reconstruction,
        "old_manifest": old_manifest,
        "old_files": old_files,
    }, core.read_current_resources_discovery(
        core_source_generation=record["core_source_generation"])["resources_state"])


def _verify_adapter_a0_migration_proof(inputs):
    return core._verify_migration_old_resources_snapshot(
        core_source_generation=inputs["core_source_generation"],
        journal_raw=inputs["journal_raw"], journal_identity=inputs["journal_identity"],
        snapshots=inputs["snapshots"], overlay_record=inputs["overlay_record"],
        overlay_contents=inputs["overlay_contents"], overlay_raw=inputs["overlay_raw"],
        overlay_identity=inputs["overlay_identity"],
        overlay_content_identities=inputs["overlay_content_identities"],
        old_artifact=inputs["old_artifact"], old_archive=inputs["old_archive"],
        old_archive_identity=inputs["old_archive_identity"],
        old_base_archive=inputs["old_base_archive"],
        old_base_identity=inputs["old_base_identity"],
        reconstruction=inputs["reconstruction"])


def _assert_registered_obsidian_snapshot(fixture):
    if fixture is None:
        return
    journal = core._journal()
    snapshot = core._snapshot_adapter_update_bindings(
        core_source_generation=journal["core_source_generation"])
    assert snapshot["obsidian_registration_state"] == "registered"
    assert snapshot["obsidian_registration"] == fixture["registration_bytes"]
    assert snapshot["obsidian_registration_sha256"] == hashlib.sha256(
        fixture["registration_bytes"]).hexdigest()
    assert snapshot["obsidian_vault_tree_sha256"] == core._obsidian_vault_tree_sha256(
        fixture["vault_root"])


def _fixed_service_path_identity():
    """Read the Pi-owned targets that the generated guard treats as fixed."""
    paths = ((Path("/etc/systemd/system/hermes-jarvis-core.service"), 0o644),
             (Path("/usr/local/libexec/hermes-jarvis-core-launcher"), 0o755))
    identity = []
    for path, expected_mode in paths:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                != (0, 0, expected_mode)):
            raise AssertionError(f"fixed Core service path custody differs: {path}")
        identity.append((str(path), info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                         stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size,
                         info.st_mtime_ns, info.st_ctime_ns,
                         hashlib.sha256(path.read_bytes()).hexdigest()))
    return tuple(identity)


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update proof requires the real root actor")
@pytest.mark.parametrize("owner_overlay", [False, True])
def test_incoming_adapter_verifies_old_a0_without_relaxing_public_discovery(
        tmp_path, monkeypatch, request, owner_overlay):
    calls, enabled, _launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    _prepare_cohort_resource_materialization(
        tmp_path, monkeypatch, request, owner_overlay=owner_overlay)
    # The production A0 verifier reads a complete active runtime, including a
    # current MainPID/PIDFD listener proof. Reuse the same controlled listener
    # fixture as the full update tests; do not bypass _read_active_adapter_runtime.
    _fake_update_pidfd(monkeypatch, enabled, request)
    _rebind_migrated_fixture_to_prior_generation()
    calls_before = list(calls)
    enabled_before = enabled["value"]
    unit_present_before = core.UNIT.exists()

    with core._adapter_update_lock():
        inputs, public_state = _adapter_a0_migration_proof_inputs()
        assert public_state == "stale"
        from hermes_installer.registry import manual_jarvis_skills as native
        watched_paths = {
            core.JOURNAL,
            core.UNIT,
            core.LAUNCHER,
            core.RESOURCES_RECORD,
            core.RESOURCES_CAS / (inputs["old_artifact"] + ".zip"),
            core.RESOURCES_CAS / (hashlib.sha256(inputs["old_base_archive"]).hexdigest() + ".zip"),
            core.HERMES_HOME / "skills" / native._GENERATION / native._OWNER_FILE,
            core.ADAPTER_UPDATE_BACKUPS / "cohort.lock",
            core.RESOURCES_SKILL_OVERLAYS / "lock",
        }
        if inputs["overlay_raw"] is not None:
            watched_paths.add(core.RESOURCES_SKILL_OVERLAYS / "active.json")
            watched_paths.update(
                core.RESOURCES_SKILL_OVERLAYS / (hashlib.sha256(data).hexdigest() + ".bin")
                for data in inputs["overlay_contents"].values())
        if inputs["snapshots"]["primary_record"]:
            watched_paths.add(core.PRIMARY_PROMPT_JOURNAL)
        bytes_before = {path: path.read_bytes() for path in watched_paths}
        manifest, files, ownership_sha = _verify_adapter_a0_migration_proof(inputs)
        assert manifest == inputs["old_manifest"]
        assert files == inputs["old_files"]
        assert re.fullmatch(r"[0-9a-f]{64}", ownership_sha)

    # The active runtime reader proves the loaded fixed unit and rejects
    # drop-ins with these ordered, read-only queries. No service mutation,
    # enablement change, or protected-byte change is allowed.
    fragment_query = ("systemctl", "show", "--property=FragmentPath", "--value", core.SERVICE)
    dropins_query = ("systemctl", "show", "--property=DropInPaths", "--value", core.SERVICE)
    new_calls = calls[len(calls_before):]
    assert [call[0] for call in new_calls] == [fragment_query, dropins_query]
    assert all(call[1] is unit_present_before for call in new_calls)
    assert enabled["value"] is enabled_before
    assert {path: path.read_bytes() for path in watched_paths} == bytes_before


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update proof requires the real root actor")
@pytest.mark.parametrize("tamper", [
    "receipt", "inventory", "tree", "soul", "aba", "cas", "cas-custody", "owner",
    "journal", "overlay", "overlay-content", "overlay-appearance",
])
def test_incoming_adapter_old_a0_proof_denies_tamper_before_effects(
        tmp_path, monkeypatch, request, tamper):
    calls, enabled, _launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    _prepare_cohort_resource_materialization(
        tmp_path, monkeypatch, request,
        owner_overlay=tamper in {"overlay", "overlay-content"})
    # Keep the real active-runtime/PIDFD verifier exercised on every tamper
    # case, as in the effectful cohort tests.
    _fake_update_pidfd(monkeypatch, enabled, request)
    _rebind_migrated_fixture_to_prior_generation()
    calls_before = list(calls)
    enabled_before = enabled["value"]
    unit_present_before = core.UNIT.exists()
    unit_bytes_before = core.UNIT.read_bytes() if unit_present_before else None
    launcher_bytes_before = core.LAUNCHER.read_bytes()
    receipt_path = core.RESOURCES_RECORD
    original_receipt = receipt_path.read_bytes()
    changed_path = None
    changed_bytes = None
    changed_mode = None
    changed_identity_path = None
    changed_identity_bytes = None

    if tamper in {"receipt", "inventory"}:
        row = json.loads(original_receipt)
        key = "resources_tree" if tamper == "receipt" else "loaded_skill_inventory_sha256"
        row[key] = "a" * (40 if tamper == "receipt" else 64)
        core._atomic_replace(receipt_path,
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600, core.ROOT_UID, core.ROOT_UID)

    with core._adapter_update_lock():
        inputs, public_state = _adapter_a0_migration_proof_inputs()
        assert public_state == "stale"
        if tamper == "tree":
            from hermes_installer.registry import manual_jarvis_skills as native
            relative = next(iter(inputs["old_files"]))
            changed_path = core.HERMES_HOME / "skills" / native._GENERATION / relative
            changed_bytes = changed_path.read_bytes()
            changed_path.write_bytes(changed_bytes + b"foreign")
        elif tamper == "soul":
            changed_path = core.HERMES_HOME / "SOUL.md"
            changed_bytes = changed_path.read_bytes()
            changed_path.write_bytes(changed_bytes + b"foreign")
        elif tamper == "aba":
            # Restore identical bytes through a new inode after a transient
            # different receipt; the captured protected identity must still fail.
            core._atomic_replace(receipt_path, original_receipt + b" ",
                0o600, core.ROOT_UID, core.ROOT_UID)
            core._atomic_replace(receipt_path, original_receipt,
                0o600, core.ROOT_UID, core.ROOT_UID)
        elif tamper == "cas":
            changed_path = core.RESOURCES_CAS / (inputs["old_artifact"] + ".zip")
            changed_bytes = changed_path.read_bytes()
            changed_path.write_bytes(changed_bytes + b"foreign")
        elif tamper == "cas-custody":
            changed_path = core.RESOURCES_CAS / (inputs["old_artifact"] + ".zip")
            changed_mode = stat.S_IMODE(changed_path.stat(follow_symlinks=False).st_mode)
            changed_path.chmod(0o644)
        elif tamper == "owner":
            from hermes_installer.registry import manual_jarvis_skills as native
            changed_path = (core.HERMES_HOME / "skills" / native._GENERATION /
                            native._OWNER_FILE)
            changed_bytes = changed_path.read_bytes()
            changed_path.write_bytes(changed_bytes + b"foreign")
        elif tamper == "journal":
            changed_path = core.JOURNAL
            changed_bytes = changed_path.read_bytes()
            core._atomic_replace(changed_path, changed_bytes + b" ",
                0o600, core.ROOT_UID, core.ROOT_UID)
        elif tamper == "overlay":
            changed_identity_path = core.RESOURCES_SKILL_OVERLAYS / "active.json"
            changed_identity_bytes = changed_identity_path.read_bytes()
            changed_identity_path.write_bytes(changed_identity_bytes + b" ")
        elif tamper == "overlay-content":
            assert inputs["overlay_contents"]
            from hermes_installer.registry import manual_jarvis_skills as native
            skill_id = sorted(inputs["overlay_contents"])[0]
            digest = inputs["overlay_record"]["skills"][skill_id]["content_sha256"]
            changed_identity_path = core.RESOURCES_SKILL_OVERLAYS / (digest + ".bin")
            changed_identity_bytes = changed_identity_path.read_bytes()
            changed_identity_path.write_bytes(changed_identity_bytes + b"foreign")
        elif tamper == "overlay-appearance":
            overlay_root = core.RESOURCES_SKILL_OVERLAYS
            overlay_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            changed_identity_path = overlay_root / "active.json"
            changed_identity_bytes = None
            core._atomic_replace(changed_identity_path, core._canonical_json({
                "schema": 1,
                "base_artifact_sha256": inputs["old_artifact"],
                "skills": {},
            }), 0o600, core.ROOT_UID, core.ROOT_UID)
        from hermes_installer.registry import manual_jarvis_skills as native
        protected_paths = {
            core.JOURNAL,
            core.UNIT,
            core.LAUNCHER,
            core.TOKEN,
            receipt_path,
            core.RESOURCES_MIGRATION_RECORD,
            core.ADAPTER_UPDATE_COHORT,
            core.RESOURCES_CAS / (inputs["old_artifact"] + ".zip"),
            core.RESOURCES_CAS / (hashlib.sha256(inputs["old_base_archive"]).hexdigest() + ".zip"),
            core.HERMES_HOME / "skills" / native._GENERATION / native._OWNER_FILE,
            core.HERMES_HOME / "SOUL.md",
            core.ADAPTER_MIGRATION_BACKUP / "journal.json",
            core.ADAPTER_MIGRATION_BACKUP / "unit",
            core.ADAPTER_MIGRATION_BACKUP / "launcher",
            core.ADAPTER_MIGRATION_BACKUP / "plugin-selection.json",
            core.ADAPTER_MIGRATION_BACKUP / "manifest.json",
            core.RESOURCES_SKILL_OVERLAYS / "lock",
        }
        if inputs["snapshots"]["primary_record"]:
            protected_paths.add(core.PRIMARY_PROMPT_JOURNAL)
        if inputs["overlay_raw"] is not None or tamper == "overlay-appearance":
            protected_paths.add(core.RESOURCES_SKILL_OVERLAYS / "active.json")
            protected_paths.update(
                core.RESOURCES_SKILL_OVERLAYS / (hashlib.sha256(data).hexdigest() + ".bin")
                for data in inputs["overlay_contents"].values())

        def protected_snapshot(paths):
            snapshot = {}
            for path in paths:
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    snapshot[path] = None
                    continue
                signature = (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                             metadata.st_uid, metadata.st_gid, metadata.st_nlink,
                             metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
                content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
                snapshot[path] = (signature, content)
            return snapshot

        verifier_state_before = protected_snapshot(protected_paths)
        with pytest.raises(core.CoreRuntimeError):
            _verify_adapter_a0_migration_proof(inputs)
        assert protected_snapshot(protected_paths) == verifier_state_before
        if changed_path is not None and changed_bytes is not None:
            changed_path.write_bytes(changed_bytes)
        if changed_mode is not None:
            changed_path.chmod(changed_mode)
        if changed_identity_path is not None and changed_identity_bytes is not None:
            changed_identity_path.write_bytes(changed_identity_bytes)
    core._atomic_replace(receipt_path, original_receipt,
        0o600, core.ROOT_UID, core.ROOT_UID)
    fragment_query = ("systemctl", "show", "--property=FragmentPath", "--value", core.SERVICE)
    dropins_query = ("systemctl", "show", "--property=DropInPaths", "--value", core.SERVICE)
    new_calls = calls[len(calls_before):]
    assert [call[0] for call in new_calls] in ([], [fragment_query, dropins_query])
    assert all(call[1] is unit_present_before for call in new_calls)
    assert enabled["value"] is enabled_before
    assert core.UNIT.exists() is unit_present_before
    assert (core.UNIT.read_bytes() if unit_present_before else None) == unit_bytes_before
    assert core.LAUNCHER.read_bytes() == launcher_bytes_before


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_adapter_migration_activates_bridge_before_owned_core_restart(tmp_path, monkeypatch):
    calls, _enabled, old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    token = core.TOKEN.read_bytes()
    old_unit = core.UNIT.read_bytes()

    result = core.install_or_resume()

    assert "migrated to the immutable installer adapter generation" in result
    record = json.loads(core.JOURNAL.read_text())
    assert record["adapter_migration_state"] == "active"
    assert record["launcher_sha256"] == hashlib.sha256(core.LAUNCHER.read_bytes()).hexdigest()
    assert core.LAUNCHER.read_bytes() != old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert core.TOKEN.read_bytes() == token
    assert (core.ADAPTER_MIGRATION_BACKUP / "launcher").read_bytes() == old_launcher
    ordered = [call[0] for call in calls]
    assert ordered.index(("bridge", "enable")) < ordered.index(("systemctl", "restart", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_adapter_migration_restores_exact_owned_files_after_restart_failure(tmp_path, monkeypatch):
    calls, _enabled, old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    token = core.TOKEN.read_bytes()
    old_unit = core.UNIT.read_bytes()
    old_journal = core.JOURNAL.read_bytes()
    monkeypatch.setattr(core, "_wait_for_listener",
                        lambda: (_ for _ in ()).throw(core.CoreRuntimeError("injected post-restart failure")))

    with pytest.raises(core.CoreRuntimeError, match="injected post-restart failure"):
        core.migrate_owned_core_to_adapter_path()

    assert core.LAUNCHER.read_bytes() == old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert core.JOURNAL.read_bytes() == old_journal
    assert core.TOKEN.read_bytes() == token
    assert [call[0] for call in calls].count(("systemctl", "restart", core.SERVICE)) == 2


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_post_migration_recovery_restores_exact_legacy_files_and_selection(tmp_path, monkeypatch):
    calls, enabled, old_launcher, selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    bootstrap = sys.modules["hermes_installer.remote.native_plugin_bootstrap"]
    restore_selection = bootstrap.restore_native_resources_plugin_selection
    def tracked_restore_selection(*args, **kwargs):
        calls.append((("native-plugin", "restore-selection"),
                      core._run(["systemctl", "is-active", core.SERVICE], False).stdout.strip()))
        return restore_selection(*args, **kwargs)
    monkeypatch.setattr(bootstrap, "restore_native_resources_plugin_selection",
                        tracked_restore_selection)
    old_unit = core.UNIT.read_bytes()
    core.migrate_owned_core_to_adapter_path()
    assert core.LAUNCHER.read_bytes() != old_launcher
    assert selection["value"] == "d" * 64

    def current_listener(*, legacy_launcher=False):
        return enabled["value"] and (
            legacy_launcher == (core.LAUNCHER.read_bytes() == old_launcher))
    monkeypatch.setattr(core, "_owned_listener", current_listener)
    result = core.recover_owned_core_from_adapter_migration()

    assert "exact prior Hermes core and plugin selection restored" in result
    assert core.LAUNCHER.read_bytes() == old_launcher
    assert core.UNIT.read_bytes() == old_unit
    assert json.loads(core.JOURNAL.read_text())["state"] == "active"
    assert selection["value"] == "e" * 64
    ordered = [call[0] for call in calls]
    assert ordered.index(("systemctl", "stop", core.SERVICE)) < ordered.index(
        ("systemctl", "start", core.SERVICE))
    assert ordered.index(("systemctl", "stop", core.SERVICE)) < ordered.index(
        ("native-plugin", "restore-selection")) < ordered.index(("systemctl", "start", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="legacy core migration requires the real root actor")
def test_post_migration_recovery_refuses_changed_current_launcher_before_touching_state(tmp_path, monkeypatch):
    calls, _enabled, _old_launcher, _selection = _install_legacy_service_fixture(tmp_path, monkeypatch)
    core.migrate_owned_core_to_adapter_path()
    before_journal = core.JOURNAL.read_bytes()
    before_unit = core.UNIT.read_bytes()
    core.LAUNCHER.write_bytes(b"unrecognized changed launcher")
    with pytest.raises(core.CoreRuntimeError, match="owned service file changed|recipe"):
        core.recover_owned_core_from_adapter_migration()
    assert core.JOURNAL.read_bytes() == before_journal
    assert core.UNIT.read_bytes() == before_unit
    assert not any(call[0] == ("systemctl", "stop", core.SERVICE) for call in calls)


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
@pytest.mark.parametrize("registered_obsidian", [False, True])
def test_native_adapter_update_stops_before_restart_on_failure_can_launch_new_launcher(
        tmp_path, monkeypatch, request, registered_obsidian):
    guard_runner = subprocess.run
    calls, enabled, _old_launcher, selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed",
        public_service_files=True, request=request)
    core.migrate_owned_core_to_adapter_path()
    prepared = _prepare_cohort_resource_materialization(
        tmp_path, monkeypatch, request, registered_obsidian=registered_obsidian)
    _readback_calls, obsidian_fixture = prepared
    _assert_registered_obsidian_snapshot(obsidian_fixture)
    memory = core.HERMES_HOME / "memories" / "owner.md"
    memory.parent.mkdir(parents=True)
    memory.write_text("existing owner memory")
    _fake_update_pidfd(monkeypatch, enabled, request)
    old_source = _rebind_migrated_fixture_to_prior_generation()
    prior = json.loads(core.JOURNAL.read_text())
    assert prior["state"] == "installed"
    prior_launcher = core.LAUNCHER.read_bytes()
    prior_unit = core.UNIT.read_bytes()
    token = core.TOKEN.read_bytes()
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    real_run = core._run
    reload_service_states = []
    automatic_restarts = []
    guard_denials = []
    def model_restart_on_failure(argv, check=True):
        result = real_run(argv, check)
        if argv == ["systemctl", "daemon-reload"]:
            reload_service_states.append(enabled["value"])
            # Model an old process failing in the ExecStart replacement window.
            # Restart=on-failure tries the just-read launcher, subject to the
            # actual generated root-side guard and still-prior preparing journal.
            if (enabled["value"] and "Restart=on-failure" in core.UNIT.read_text()
                    and core.LAUNCHER.read_bytes() == core._launcher()):
                enabled["value"] = False
                current_unit = core.UNIT.read_bytes()
                status = _exec_start_pre(
                    current_unit, expect_success=True,
                    systemd_argv=_systemd_decoded_exec_start_pre(
                        current_unit, runner=guard_runner),
                    credential_projection=True)
                if status:
                    guard_denials.append(status)
                else:
                    enabled["value"] = True
                    journal = json.loads(core.JOURNAL.read_text())
                    automatic_restarts.append({
                        "state": journal["state"],
                        "adapter_source": journal["adapter_source"],
                        "update_state": journal["adapter_update_state"],
                        "launcher_sha256": hashlib.sha256(core.LAUNCHER.read_bytes()).hexdigest(),
                    })
        return result
    monkeypatch.setattr(core, "_run", model_restart_on_failure)

    original_proc_snapshot = core._root_runuser_proc_snapshot
    runuser_identity_mismatches = []

    def observe_runuser_proc_snapshot(process, identity, pipe_fd):
        try:
            return original_proc_snapshot(process, identity, pipe_fd)
        except core.CoreRuntimeError:
            tb = sys.exc_info()[2]
            while tb is not None:
                frame = tb.tb_frame
                if frame.f_code is original_proc_snapshot.__code__:
                    values = frame.f_locals
                    pipe = values.get("pipe")
                    stdin_stat = values.get("stdin_stat")
                    status = values.get("values", {})
                    checks = {
                        "process_state": values.get("state") not in {"Z", "X"},
                        "root_parent": values.get("ppid") == identity["root_pid"],
                        "process_group": values.get("process_group") == identity["pid"],
                        "session": values.get("session") == identity["pid"],
                        "start_ticks": str(values.get("start_ticks", "")).isdecimal(),
                        "root_uids": status.get("Uid") == ["0"] * 4,
                        "root_gids": status.get("Gid") == ["0"] * 4,
                        "runuser_comm": values.get("comm") == "runuser",
                        "argv": tuple(values.get("actual_argv", ())) == identity["argv"],
                        "executable": (pipe is not None and
                            (values.get("exe").st_dev, values.get("exe").st_ino,
                             values.get("exe").st_uid) ==
                            (identity["exe_dev"], identity["exe_ino"], core.ROOT_UID)),
                        "stdin_fifo": stdin_stat is not None and stat.S_ISFIFO(stdin_stat.st_mode),
                        "stdin_owner": stdin_stat is not None and stdin_stat.st_uid == core.ROOT_UID,
                        "stdin_inode": (stdin_stat is not None and pipe is not None and
                            (stdin_stat.st_dev, stdin_stat.st_ino) == (pipe.st_dev, pipe.st_ino)),
                        "stdin_target": values.get("stdin_target") ==
                            (f"pipe:[{pipe.st_ino}]" if pipe is not None else None),
                        "pipe_identity": (pipe is not None and
                            (pipe.st_dev, pipe.st_ino, pipe.st_uid) ==
                            (identity["pipe_dev"], identity["pipe_ino"], core.ROOT_UID)),
                    }
                    failed = tuple(name for name, ok in checks.items() if not ok)
                    runuser_identity_mismatches.append(failed)
                    print("bounded runuser identity predicates failed: " + repr(failed))
                    break
                tb = tb.tb_next
            raise

    monkeypatch.setattr(core, "_root_runuser_proc_snapshot", observe_runuser_proc_snapshot)
    original_initial_primary_current = core._initial_primary_current
    original_issue_initial_primary_custody = core._issue_initial_primary_adoption_custody
    original_run_same_materialization_import = core._run_same_materialization_import
    original_require_bounded_import_output = core._require_bounded_helper_import_output
    initial_primary_early_guard_failures = []
    initial_primary_custody_issued = {}
    initial_primary_stage_seconds = {"import": []}
    importer_outcomes = []
    from hermes_installer import primary_prompt_manager as primary_manager
    original_primary_adoption = primary_manager.adopt_primary_prompt_for_starting_cohort

    def observe_primary_adoption(custody):
        started = core.time.monotonic()
        try:
            return original_primary_adoption(custody)
        finally:
            initial_primary_stage_seconds.setdefault("primary_adoption", []).append(
                round(max(0.0, core.time.monotonic() - started), 2))

    def observe_same_materialization_import(*args, **kwargs):
        started = core.time.monotonic()
        try:
            return original_run_same_materialization_import(*args, **kwargs)
        finally:
            initial_primary_stage_seconds["import"].append(
                round(max(0.0, core.time.monotonic() - started), 2))

    def observe_initial_primary_custody_issue(*args, **kwargs):
        custody = original_issue_initial_primary_custody(*args, **kwargs)
        initial_primary_custody_issued[id(custody)] = core.time.monotonic()
        return custody

    def observe_bounded_import_output(returncode, stdout, stderr):
        # Keep the production validator first and unchanged. Retain the genuine
        # bounded receipt only in this private fixture for its existing size
        # and oversize-refusal assertions; diagnostics never print its bytes.
        result = original_require_bounded_import_output(returncode, stdout, stderr)
        importer_outcomes.append({
            "returncode": returncode,
            "stdout": stdout,
            "stderr_bytes": len(stderr) if isinstance(stderr, bytes) else -1,
        })
        return result

    monkeypatch.setattr(core, "_run_same_materialization_import",
                        observe_same_materialization_import)
    monkeypatch.setattr(core, "_issue_initial_primary_adoption_custody",
                        observe_initial_primary_custody_issue)
    monkeypatch.setattr(core, "_require_bounded_helper_import_output",
                        observe_bounded_import_output)
    monkeypatch.setattr(primary_manager, "adopt_primary_prompt_for_starting_cohort",
                        observe_primary_adoption)

    def observe_initial_primary_current(custody, **kwargs):
        def failed_early_checks(now):
            failed = []
            if type(custody) is not core.InitialPrimaryAdoptionCustody:
                failed.append("custody_type")
            elif custody._seal is not core._INITIAL_PRIMARY_ADOPTION_SEAL:
                failed.append("custody_seal")
            if os.geteuid() != core.ROOT_UID:
                failed.append("root_actor")
            if not core._ADAPTER_UPDATE_LOCK_HELD.get():
                failed.append("update_lock")
            if now >= getattr(custody, "expires_monotonic", float("inf")):
                failed.append("custody_expiry")
            if now >= getattr(custody, "deadline_monotonic", float("inf")):
                failed.append("custody_deadline")
            return tuple(failed)

        before = failed_early_checks(core.time.monotonic())
        result = original_initial_primary_current(custody, **kwargs)
        checked_at = core.time.monotonic()
        after = failed_early_checks(checked_at)
        if result is False:
            issued_at = initial_primary_custody_issued.get(id(custody))
            elapsed = (round(max(0.0, checked_at - issued_at), 2)
                       if issued_at is not None else None)
            initial_primary_early_guard_failures.append({
                "before": before, "after": after,
                "seconds_since_issue": elapsed,
            })
            if len(initial_primary_early_guard_failures) > 12:
                del initial_primary_early_guard_failures[0]
        return result

    monkeypatch.setattr(core, "_initial_primary_current", observe_initial_primary_current)
    try:
        # This real effect path has a fixed 110-second primary-adoption
        # custody. Avoid sys.settrace here so instrumentation cannot distort
        # that deadline; other failure-oriented tests retain the full tracer.
        result = core.update_owned_core_adapter()
    except BaseException:
        print("bounded initial-primary early custody predicate failures: " +
              repr(initial_primary_early_guard_failures[-12:]))
        print("bounded untraced update stage seconds: " +
              repr({name: values[-4:] for name, values in initial_primary_stage_seconds.items()}))
        raise

    updated = json.loads(core.JOURNAL.read_text())
    assert "updated to the verified adapter generation" in result
    cohort, _cohort_raw = core._read_adapter_update_cohort()
    # The old A0 receipt is intentionally stale to ordinary incoming
    # discovery; after the guarded exchange, that reader must validate A1.
    assert _PRODUCTION_READ_CURRENT_RESOURCES_DISCOVERY(
        core_source_generation=updated["core_source_generation"]
    )["resources_state"] == "discovered"
    resources_raw = core.RESOURCES_RECORD.read_bytes()
    resources_record = json.loads(resources_raw)
    reconstruction = cohort["reconstruction"]
    assert cohort["phase"] == "committed"
    assert reconstruction["new_composed_artifact_sha256"] == cohort["new_artifact_sha256"]
    assert resources_record["artifact_sha256"] == cohort["new_artifact_sha256"]
    assert hashlib.sha256(resources_raw).hexdigest() == cohort["new_resources_record_sha256"]
    if obsidian_fixture is not None:
        assert cohort["phase"] == "committed"
        assert cohort["obsidian_registration_state"] == "registered"
        assert cohort["obsidian_registration_sha256"] == hashlib.sha256(
            obsidian_fixture["registration_bytes"]).hexdigest()
        assert cohort["obsidian_vault_tree_sha256"] == core._obsidian_vault_tree_sha256(
            obsidian_fixture["vault_root"])
    assert updated["adapter_source"] == str(core.ADAPTER_SOURCE)
    assert updated["state"] == "installed"
    assert updated["adapter_generation"] == "a" * 64
    assert updated["plugin_selection_sha256"] == prior["plugin_selection_sha256"]
    assert core.LAUNCHER.read_bytes() != prior_launcher
    expected_new_unit = core._unit(
        adapter_source=Path(updated["adapter_source"]), cohort_gate=True,
        backup_generation=prior["adapter_generation"], native_plugin_transition=True,
        failure_diagnostics=True, whole_guard_encoding=True,
        credential_projection=True)
    expected_new_unit_argv = _systemd_decoded_exec_start_pre(
        expected_new_unit, runner=guard_runner)
    backup_credentials = [row for row in expected_new_unit.decode().splitlines()
        if row.startswith("LoadCredential=adapter-backup-")]
    assert len(backup_credentials) == len(core._ADAPTER_UPDATE_BACKUP_MEMBERS) + 3
    assert {row.partition(":")[0] for row in backup_credentials} >= {
        "LoadCredential=adapter-backup-native-plugin-plugin-yaml",
        "LoadCredential=adapter-backup-native-plugin-__init__-py",
    }
    assert core.UNIT.read_bytes() == expected_new_unit
    assert hashlib.sha256(expected_new_unit).hexdigest() == updated["unit_sha256"]
    assert _exec_start_pre(expected_new_unit, expect_success=True,
                           runner=guard_runner, diagnostic=True,
                           systemd_argv=expected_new_unit_argv,
                           credential_projection=True) == 0
    assert _exec_start_pre(expected_new_unit,
        credential_mutations={"adapter-backup-native-plugin-__init__-py": ("remove",)},
        expect_success=False, runner=guard_runner,
        systemd_argv=expected_new_unit_argv, credential_projection=True) != 0
    assert _exec_start_pre(prior_unit, expect_success=False,
                           runner=guard_runner) != 0
    installed_plugin_module = (core.HERMES_HOME / "plugins" /
        "hermes-installer-resources-delegation" / "__init__.py")
    installed_plugin_module.write_bytes(b"foreign plugin bytes\n")
    os.chown(installed_plugin_module, core.ROOT_UID, core.ROOT_UID)
    os.chmod(installed_plugin_module, 0o444)
    assert _exec_start_pre(expected_new_unit, expect_success=False,
                           runner=guard_runner, systemd_argv=expected_new_unit_argv,
                           credential_projection=True) != 0
    installed_plugin_module.write_bytes(b"new native tools\n")
    os.chown(installed_plugin_module, core.ROOT_UID, core.ROOT_UID)
    os.chmod(installed_plugin_module, 0o444)
    assert _exec_start_pre(expected_new_unit, expect_success=True,
                           runner=guard_runner, systemd_argv=expected_new_unit_argv,
                           credential_projection=True) == 0
    assert core.TOKEN.read_bytes() == token
    assert memory.read_text() == "existing owner memory"
    backup = core.ADAPTER_UPDATE_BACKUPS / prior["adapter_generation"]
    if obsidian_fixture is not None:
        assert (backup / "obsidian-registration.json").read_bytes() == (
            obsidian_fixture["registration_bytes"])
    assert (backup / "launcher").read_bytes() == prior_launcher
    assert (backup / "unit").read_bytes() == prior_unit
    assert json.loads((backup / "journal.json").read_bytes()) == prior
    backup_manifest = json.loads((backup / "manifest.json").read_bytes())
    assert {"native-plugin-plugin.yaml", "native-plugin-__init__.py"} <= set(backup_manifest)
    assert (backup / "native-plugin-plugin.yaml").read_bytes() == b"manifest-v1\n"
    assert (backup / "native-plugin-__init__.py").read_bytes() == b"old native tools\n"
    assert selection["value"] == prior["plugin_selection_sha256"]
    assert reload_service_states == [True, False]
    assert automatic_restarts == []
    assert guard_denials == []
    assert len(importer_outcomes) == 1
    importer = importer_outcomes[0]
    assert importer["returncode"] == 0
    assert importer["stderr_bytes"] <= core._HELPER_IMPORT_STDERR_LIMIT
    _assert_registered_obsidian_fixture_preserved(obsidian_fixture)
    receipt = importer["stdout"]
    assert type(receipt) is bytes
    assert 16 * 1024 < len(receipt) <= core._HELPER_IMPORT_STDOUT_LIMIT
    before_oversize_check = (core.JOURNAL.read_bytes(),
                             (backup / "manifest.json").read_bytes(),
                             core.TOKEN.read_bytes())
    oversized_receipt = receipt + b" " * (core._HELPER_IMPORT_STDOUT_LIMIT + 1 - len(receipt))
    with pytest.raises(core.CoreRuntimeError, match="importer refused"):
        core._require_bounded_helper_import_output(0, oversized_receipt, b"")
    assert before_oversize_check == (core.JOURNAL.read_bytes(),
                                     (backup / "manifest.json").read_bytes(),
                                     core.TOKEN.read_bytes())
    ordered = [call[0] for call in calls]
    assert ordered.index(("systemctl", "stop", core.SERVICE)) < ordered.index(
        ("systemctl", "start", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
@pytest.mark.parametrize("registered_obsidian", [False, True])
def test_native_adapter_update_restart_failure_restores_exact_prior_generation(
        tmp_path, monkeypatch, request, registered_obsidian):
    real_wait_for_listener = core._wait_for_listener
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    prepared = _prepare_cohort_resource_materialization(
        tmp_path, monkeypatch, request, registered_obsidian=registered_obsidian)
    _readback_calls, obsidian_fixture = prepared
    _assert_registered_obsidian_snapshot(obsidian_fixture)
    _fake_update_pidfd(monkeypatch, enabled, request)
    old_source = _rebind_migrated_fixture_to_prior_generation()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated_record = json.loads(migrated_raw)
    prior_unguarded_unit = core._unit(startup_guard=False, adapter_source=old_source)
    core._atomic_replace(core.UNIT, prior_unguarded_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated_record["unit_sha256"] = hashlib.sha256(prior_unguarded_unit).hexdigest()
    core._replace_journal(migrated_record)
    _rebind_fixture_resources_to_current_journal()
    prior = core.JOURNAL.read_bytes()
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    token = core.TOKEN.read_bytes()
    from hermes_installer import primary_prompt_manager as primary_manager
    original_soul, _original_soul_signature = primary_manager._read_soul(core)
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    def current_journal_listener(*, adapter_source=core.ADAPTER_SOURCE, legacy_launcher=False):
        if not enabled["value"]:
            return False
        try:
            record = json.loads(core.JOURNAL.read_bytes())
        except (OSError, ValueError, TypeError):
            return False
        return (not legacy_launcher
                and record.get("adapter_source") == str(adapter_source))
    monkeypatch.setattr(core, "_owned_listener", current_journal_listener)
    attempts = {"wait": 0}
    listener_sources = []
    def fail_first_restart(*, adapter_source=core.ADAPTER_SOURCE):
        attempts["wait"] += 1
        listener_sources.append(Path(adapter_source))
        if attempts["wait"] == 1:
            assert Path(adapter_source) == core.ADAPTER_SOURCE
            attempts["starting_cohort"], _cohort_raw = core._read_adapter_update_cohort()
            raise core.CoreRuntimeError("injected adapter update restart failure")
        assert Path(adapter_source) == old_source
        real_wait_for_listener(adapter_source=Path(adapter_source))
    monkeypatch.setattr(core, "_wait_for_listener", fail_first_restart)
    update_call_start = len(_calls)

    interrupted_restore = {"done": False, "cohort": None, "stage": None}
    restore_owner_generation = core._restore_adapter_update_owner_generation
    if registered_obsidian:
        def interrupt_after_primary_unlink(cohort):
            if not interrupted_restore["done"]:
                parsed, _raw = core._read_adapter_update_cohort()
                transition = parsed["initial_primary_transition"]
                assert parsed["phase"] == transition["state"] == "rolling-back"
                assert transition["prior_record_state"] == "absent"
                assert not core.PRIMARY_PROMPT_JOURNAL.exists()
                current_soul, signature = primary_manager._read_soul(core)
                assert hashlib.sha256(current_soul).hexdigest() == transition[
                    "prior_soul_sha256"]
                assert core._restored_soul_signature_matches(
                    signature, transition["prior_soul_signature"])
                selected_digest = next(transition[key] for key in (
                    "adopted_record_sha256", "writing_record_sha256",
                    "preparing_record_sha256") if transition[key] is not None)
                stage = (core.ADAPTER_UPDATE_BACKUPS /
                         ("initial-primary-" + parsed["cohort_transaction_id"]) /
                         (selected_digest + ".json"))
                interrupted_restore.update({"done": True, "cohort": parsed,
                                            "stage": stage})
                raise KeyboardInterrupt("injected after offline primary rollback")
            return restore_owner_generation(cohort)

        monkeypatch.setattr(core, "_restore_adapter_update_owner_generation",
                            interrupt_after_primary_unlink)
        with pytest.raises(KeyboardInterrupt, match="injected after offline primary rollback"):
            core.update_owned_core_adapter()
        assert interrupted_restore["done"]
        interrupted_cohort = interrupted_restore["cohort"]
        interrupted_transition = interrupted_cohort["initial_primary_transition"]
        assert core.PRIMARY_PROMPT_JOURNAL.exists() is False
        assert primary_manager._read_soul(core)[0] == original_soul
        assert interrupted_restore["stage"].is_file()
        reference = core._adapter_update_backup_reference(interrupted_cohort)
        _prior_snapshot, backup_contents = core._read_adapter_update_backup(reference)
        assert hashlib.sha256(backup_contents["primary-record.json"]).hexdigest() == core._ABSENT_DIGEST

        def recovery_snapshot():
            return (core.JOURNAL.read_bytes(), core.RESOURCES_RECORD.read_bytes(),
                    core.UNIT.read_bytes(), core.LAUNCHER.read_bytes(),
                    core.ADAPTER_UPDATE_COHORT.read_bytes(),
                    core.TOKEN.read_bytes())
        protected_before_refusals = recovery_snapshot()

        # Currentness failures happen before stop/restore effects. Exercise
        # owner-byte, retained-stage, and immutable-backup drift independently.
        calls_before_refusals = list(_calls)
        soul_path = core.HERMES_HOME / "SOUL.md"
        changed_soul = bytes([original_soul[0] ^ 1]) + original_soul[1:]
        soul_path.write_bytes(changed_soul)
        with pytest.raises(core.CoreRuntimeError):
            core._recover_interrupted_adapter_update()
        soul_path.write_bytes(original_soul)
        assert _calls == calls_before_refusals

        stage_path = interrupted_restore["stage"]
        stage_raw = stage_path.read_bytes()
        stage_path.write_bytes(b"{}\n")
        stage_path.chmod(0o400)
        with pytest.raises(core.CoreRuntimeError):
            core._recover_interrupted_adapter_update()
        stage_path.write_bytes(stage_raw)
        stage_path.chmod(0o400)
        assert _calls == calls_before_refusals

        stage_directory = stage_path.parent
        held_directory = stage_directory.with_name(stage_directory.name + ".held")
        assert not held_directory.exists() and not held_directory.is_symlink()
        stage_directory.rename(held_directory)
        try:
            stage_directory.symlink_to(held_directory, target_is_directory=True)
            with pytest.raises(core.CoreRuntimeError):
                core._recover_interrupted_adapter_update()
        finally:
            if stage_directory.is_symlink():
                stage_directory.unlink()
            held_directory.rename(stage_directory)
        assert _calls == calls_before_refusals

        backup_path = core.PRIMARY_PROMPT_BACKUPS / (
            interrupted_transition["owner_backup_sha256"] + ".bin")
        backup_raw = backup_path.read_bytes()
        backup_path.write_bytes(bytes([backup_raw[0] ^ 1]) + backup_raw[1:])
        with pytest.raises(core.CoreRuntimeError):
            core._recover_interrupted_adapter_update()
        backup_path.write_bytes(backup_raw)
        assert _calls == calls_before_refusals
        assert core.PRIMARY_PROMPT_JOURNAL.exists() is False
        assert primary_manager._read_soul(core)[0] == original_soul
        assert recovery_snapshot() == protected_before_refusals

        monkeypatch.setattr(core, "_restore_adapter_update_owner_generation",
                            restore_owner_generation)
        core._recover_interrupted_adapter_update()
    else:
        with _bounded_owner_generation_restore_failure():
            with pytest.raises(core.CoreRuntimeError, match="injected adapter update restart failure"):
                core.update_owned_core_adapter()

    assert listener_sources == [core.ADAPTER_SOURCE, old_source]

    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert core.TOKEN.read_bytes() == token
    assert enabled["value"]
    if obsidian_fixture is not None:
        cohort = attempts["starting_cohort"]
        assert cohort["phase"] in {"source-starting", "bindings-verified"}
        assert cohort["obsidian_registration_sha256"] == hashlib.sha256(
            obsidian_fixture["registration_bytes"]).hexdigest()
        assert cohort["obsidian_vault_tree_sha256"] == core._obsidian_vault_tree_sha256(
            obsidian_fixture["vault_root"])
    _assert_registered_obsidian_fixture_preserved(obsidian_fixture)
    if obsidian_fixture is not None:
        backup = core.ADAPTER_UPDATE_BACKUPS / json.loads(prior)["adapter_generation"]
        assert (backup / "obsidian-registration.json").read_bytes() == (
            obsidian_fixture["registration_bytes"])
    assert attempts["wait"] == 2
    ordered = [call[0] for call in _calls[update_call_start:]]
    restore_index = ordered.index(("native-plugin", "restore"))
    assert ordered.index(("native-plugin", "install")) < restore_index
    assert any(index > restore_index and call == ("systemctl", "start", core.SERVICE)
               for index, call in enumerate(ordered))


def test_wait_for_listener_checks_the_requested_journaled_source(monkeypatch):
    prior_source = Path("/opt/hermes-installer-core-prior/src")
    observed = []

    def owned_listener(*, adapter_source=core.ADAPTER_SOURCE):
        observed.append(Path(adapter_source))
        return Path(adapter_source) == prior_source

    monkeypatch.setattr(core, "_owned_listener", owned_listener)
    core._wait_for_listener(adapter_source=prior_source)
    assert observed == [prior_source]


def test_wait_for_listener_keeps_default_source_and_refuses_mismatch(monkeypatch):
    observed = []
    monotonic = {"value": 0.0}

    def only_candidate_is_current(*, adapter_source=core.ADAPTER_SOURCE):
        observed.append(Path(adapter_source))
        return Path(adapter_source) == core.ADAPTER_SOURCE

    monkeypatch.setattr(core, "_owned_listener", only_candidate_is_current)
    core._wait_for_listener()
    assert observed == [core.ADAPTER_SOURCE]

    observed.clear()
    prior_source = Path("/opt/hermes-installer-core-prior/src")
    monkeypatch.setattr(core.time, "monotonic", lambda: monotonic["value"])
    monkeypatch.setattr(core.time, "sleep", lambda seconds: monotonic.__setitem__(
        "value", monotonic["value"] + seconds))
    with pytest.raises(core.CoreRuntimeError, match="did not prove its isolated loopback listener"):
        core._wait_for_listener(adapter_source=prior_source)
    assert observed == [prior_source] * 30


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
def test_interrupted_adapter_update_recovers_from_journaled_generation_backup(tmp_path, monkeypatch, request):
    guard_runner = subprocess.run
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    _prepare_cohort_resource_materialization(tmp_path, monkeypatch, request)
    _fake_update_pidfd(monkeypatch, enabled, request)
    old_source = _rebind_migrated_fixture_to_prior_generation()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated_record = json.loads(migrated_raw)
    prior_unguarded_unit = core._unit(startup_guard=False, adapter_source=old_source)
    core._atomic_replace(core.UNIT, prior_unguarded_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated_record["unit_sha256"] = hashlib.sha256(prior_unguarded_unit).hexdigest()
    core._replace_journal(migrated_record)
    _rebind_fixture_resources_to_current_journal()
    prior = core.JOURNAL.read_bytes()
    prior_resources = core.RESOURCES_RECORD.read_bytes()
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    replace_atomic = core._atomic_replace
    interrupted = {"starting_journal": None}
    def interrupt_starting_journal(path, data, *args, **kwargs):
        if (path == core.JOURNAL and isinstance(data, bytes)
                and b'"adapter_update_state":"starting"' in data
                and interrupted["starting_journal"] is None):
            interrupted["starting_journal"] = data
            raise KeyboardInterrupt()
        return replace_atomic(path, data, *args, **kwargs)
    monkeypatch.setattr(core, "_atomic_replace", interrupt_starting_journal)

    with pytest.raises(KeyboardInterrupt):
        core.update_owned_core_adapter()
    assert core.JOURNAL.read_bytes() == prior  # J0 remains intact until the exact J_s CAS.
    attempted_starting = interrupted["starting_journal"]
    assert attempted_starting is not None
    interrupted_record = json.loads(attempted_starting)
    interrupted_cohort, _cohort_raw = core._read_adapter_update_cohort()
    assert interrupted_record["adapter_update_state"] == "starting"
    assert interrupted_record["adapter_source"] == str(core.ADAPTER_SOURCE)
    assert interrupted_cohort["phase"] == "source-starting"
    assert interrupted_cohort["starting_journal_sha256"] == hashlib.sha256(
        attempted_starting).hexdigest()
    staged_resources = core.RESOURCES_RECORD.read_bytes()
    assert hashlib.sha256(staged_resources).hexdigest() == interrupted_cohort[
        "starting_resources_record_sha256"]
    assert json.loads(staged_resources)["core_ownership_sha256"] == hashlib.sha256(
        attempted_starting).hexdigest()
    assert core.LAUNCHER.read_bytes() != launcher
    assert core.UNIT.read_bytes() != unit
    interrupted_unit = core.UNIT.read_bytes()
    assert _exec_start_pre(interrupted_unit, expect_success=False,
                           runner=guard_runner,
                           systemd_argv=_systemd_decoded_exec_start_pre(
                               interrupted_unit, runner=guard_runner),
                           credential_projection=True) != 0

    monkeypatch.setattr(core, "_atomic_replace", replace_atomic)
    with _bounded_cohort_exception_sites():
        core._recover_interrupted_adapter_update()

    assert core.JOURNAL.read_bytes() == prior
    assert core.RESOURCES_RECORD.read_bytes() == prior_resources
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert enabled["value"]
    assert _exec_start_pre(core.UNIT.read_bytes()) is None  # exact prior unit is guardless


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update recovery needs the real root actor")
def test_starting_and_partial_rollback_interruption_fail_closed_in_exec_start_pre(tmp_path, monkeypatch, request):
    guard_runner = subprocess.run
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed",
        public_service_files=True, request=request)
    core.migrate_owned_core_to_adapter_path()
    _prepare_cohort_resource_materialization(tmp_path, monkeypatch, request)
    _fake_update_pidfd(monkeypatch, enabled, request)
    old_source = _rebind_migrated_fixture_to_prior_generation()
    migrated_raw = core.JOURNAL.read_bytes()
    migrated = json.loads(migrated_raw)
    prior_unit = core._unit(startup_guard=False, adapter_source=old_source)
    core._atomic_replace(core.UNIT, prior_unit, 0o644, core.ROOT_UID, core.ROOT_UID)
    migrated["unit_sha256"] = hashlib.sha256(prior_unit).hexdigest()
    core._replace_journal(migrated)
    _rebind_fixture_resources_to_current_journal()
    prior = core.JOURNAL.read_bytes()
    prior_launcher = core.LAUNCHER.read_bytes()
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")

    real_run = core._run
    def interrupt_after_starting_recipe(argv, check=True):
        if argv == ["systemctl", "start", core.SERVICE]:
            starting_unit = core.UNIT.read_bytes()
            assert _exec_start_pre(starting_unit, expect_success=True,
                                   runner=guard_runner, diagnostic=True,
                                   systemd_argv=_systemd_decoded_exec_start_pre(
                                       starting_unit, runner=guard_runner),
                                   credential_projection=True) == 0
            raise KeyboardInterrupt()
        return real_run(argv, check)
    monkeypatch.setattr(core, "_run", interrupt_after_starting_recipe)
    with _bounded_cohort_exception_sites():
        with pytest.raises(KeyboardInterrupt):
            core.update_owned_core_adapter()
    starting = json.loads(core.JOURNAL.read_bytes())
    assert starting["adapter_update_state"] == "starting"
    assert starting["adapter_source"] == str(core.ADAPTER_SOURCE)

    atomic_replace = core._atomic_replace
    def interrupt_after_prior_launcher(path, *args, **kwargs):
        if Path(path) == core.JOURNAL:
            raise KeyboardInterrupt()
        return atomic_replace(path, *args, **kwargs)
    monkeypatch.setattr(core, "_atomic_replace", interrupt_after_prior_launcher)
    with pytest.raises(KeyboardInterrupt):
        core._recover_interrupted_adapter_update()
    assert core.LAUNCHER.read_bytes() == prior_launcher
    partial_unit = core.UNIT.read_bytes()
    assert _exec_start_pre(partial_unit, expect_success=False,
                           runner=guard_runner,
                           systemd_argv=_systemd_decoded_exec_start_pre(
                               partial_unit, runner=guard_runner),
                           credential_projection=True) != 0

    monkeypatch.setattr(core, "_atomic_replace", atomic_replace)
    monkeypatch.setattr(core, "_run", real_run)
    with _bounded_cohort_exception_sites():
        core._recover_interrupted_adapter_update()
    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == prior_launcher
    assert core.UNIT.read_bytes() == prior_unit
    assert enabled["value"]


@pytest.fixture
def committed_adapter_update_recovery(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("fixed Core update recovery requires the root actor")
    old_source = "/opt/hermes-installer-core-aaaaaaaaa/src"
    new_source_root = tmp_path / "hermes-installer-core-bbbbbbbbb"
    new_source_root.mkdir()
    (new_source_root / "src").mkdir()
    new_source = str(new_source_root / "src")
    provenance = {"schema": 1, "source_commit": "b" * 40,
                  "archive_sha256": "f" * 64}
    (new_source_root / ".source-provenance.json").write_bytes(core._canonical_json(provenance))
    (new_source_root / ".source-provenance.json").chmod(0o444)
    old_generation, new_generation = "a" * 64, "b" * 64
    core_generation, cohort_id = "c" * 64, "d" * 32
    prior = {"schema": 1, "service": core.SERVICE, "state": "active",
             "adapter_migration_state": "active",
             "adapter_source": old_source, "adapter_generation": old_generation,
             "core_source_generation": core_generation}
    prior_raw = core._canonical_json(prior)
    current = {"schema": 1, "state": "active", "adapter_migration_state": "active",
               "adapter_source": new_source, "adapter_generation": new_generation,
               "core_source_generation": core_generation, "adapter_update_state": "active",
               "adapter_update_previous_source": old_source,
               "adapter_update_target_source": new_source,
               "adapter_update_target_generation": new_generation,
               "adapter_update_cohort_transaction_id": cohort_id}
    cohort = {"phase": "committed", "cohort_transaction_id": cohort_id,
              "old_source": old_source, "old_adapter_generation": old_generation,
              "old_core_source_generation": core_generation,
              "old_journal_sha256": hashlib.sha256(prior_raw).hexdigest(),
              "new_source": new_source, "new_adapter_generation": new_generation,
              "new_core_source_generation": core_generation,
              "reconstruction": {"phase": "committed", "new_discovery_sha256": "e" * 64}}
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(cohort["reconstruction"])).hexdigest()
    cohort_raw = core._canonical_json(cohort)
    backup_path = tmp_path / "adapter-update-backups" / old_generation
    reference = {"path": str(backup_path), "source_generation": old_generation,
                 "files": {"journal.json": hashlib.sha256(prior_raw).hexdigest()}}
    current["adapter_update_backup"] = reference
    current_raw = core._canonical_json(current)
    contents = {"journal.json": prior_raw}
    refresh = {"schema": 1, "purpose": "adapter-refresh",
        "old_core_journal_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "old_core_adapter_source": old_source, "old_core_adapter_generation": old_generation,
        "old_core_source_generation": core_generation,
        "old_inspector_process_identity_sha256": "e" * 64,
        "old_observer_state": "absent", "old_observer_device": None,
        "old_observer_inode": None, "core_update_backup_reference": reference,
        "core_update_cohort_transaction_id": cohort_id,
        "core_update_cohort_sha256": hashlib.sha256(cohort_raw).hexdigest()}
    ingress = {"schema": 1, "state": "recovery-required",
               "candidate_sha": "b" * 40, "adapter_refresh": refresh}
    ingress_path = tmp_path / "native-adoption-ingress-backup.json"
    ingress_path.write_bytes(core._canonical_json(ingress)); ingress_path.chmod(0o600)
    journal_path = tmp_path / "ownership.json"
    journal_path.write_bytes(current_raw); journal_path.chmod(0o600)
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", tmp_path / "adapter-update-backups")
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS", tmp_path / "overlays")
    monkeypatch.setattr(core, "PRIMARY_PROMPT_BACKUPS", tmp_path / "primary-backups")
    monkeypatch.setattr(core, "NATIVE_ADOPTION_INGRESS_BACKUP", ingress_path)
    monkeypatch.setattr(core, "JOURNAL", journal_path)
    monkeypatch.setattr(core, "ADAPTER_SOURCE", Path(new_source))
    monkeypatch.setattr(core, "_read_adapter_update_cohort", lambda: (cohort, cohort_raw))
    monkeypatch.setattr(core, "_adapter_update_backup_reference", lambda _cohort: reference)
    monkeypatch.setattr(core, "_read_adapter_update_backup", lambda _reference: (prior, contents))

    def read_active():
        raw = journal_path.read_bytes()
        return json.loads(raw), raw, {}

    monkeypatch.setattr(core, "_read_active_adapter_runtime", read_active)
    monkeypatch.setattr(core, "_run", lambda argv, check=True:
        SimpleNamespace(stdout="inactive"))
    effects = []

    def restore(received, *, allowed_sources):
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        assert received == reference
        assert tuple(map(str, allowed_sources)) == (old_source, new_source)
        effects.append("restore")
        journal_path.write_bytes(prior_raw)
        os.chmod(journal_path, 0o600)
        return prior

    monkeypatch.setattr(core, "_restore_adapter_update_backup", restore)
    return SimpleNamespace(refresh=refresh, ingress=ingress, ingress_path=ingress_path,
        cohort=cohort, reference=reference, prior=prior, effects=effects,
        current_raw=current_raw, restore=restore)


@pytest.mark.parametrize("joins", ["absent", "exact"])
def test_owned_adapter_update_recovery_derives_exact_committed_join(
        committed_adapter_update_recovery, joins):
    fixture = committed_adapter_update_recovery
    if joins == "absent":
        fixture.refresh["core_update_backup_reference"] = None
        fixture.refresh["core_update_cohort_transaction_id"] = None
        fixture.refresh["core_update_cohort_sha256"] = None
    fixture.ingress_path.write_bytes(core._canonical_json(fixture.ingress))
    assert "exact prior journal-owned Core adapter" in core.restore_owned_core_adapter_update()
    assert fixture.effects == ["restore"]
    assert core.JOURNAL.read_bytes() == core._canonical_json(fixture.prior)


@pytest.mark.parametrize("phase", ["source-starting"])
def test_owned_adapter_update_recovery_restores_exact_interrupted_cohort(
        committed_adapter_update_recovery, monkeypatch, phase):
    fixture = committed_adapter_update_recovery
    fixture.cohort["phase"] = phase
    reconstruction = dict(fixture.cohort["reconstruction"])
    reconstruction["phase"] = phase
    fixture.cohort["reconstruction"] = reconstruction
    fixture.cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    cohort_raw = core._canonical_json(fixture.cohort)
    # The adopter cannot persist Core joins before the update runner returns;
    # an interrupted source-starting phase therefore retains all three null.
    fixture.refresh["core_update_backup_reference"] = None
    fixture.refresh["core_update_cohort_transaction_id"] = None
    fixture.refresh["core_update_cohort_sha256"] = None
    fixture.ingress_path.write_bytes(core._canonical_json(fixture.ingress))
    monkeypatch.setattr(core, "_read_adapter_update_cohort",
        lambda: (fixture.cohort, cohort_raw))

    def recover():
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        fixture.effects.append("recover-interrupted")
        core.JOURNAL.write_bytes(core._canonical_json(fixture.prior))

    monkeypatch.setattr(core, "_recover_interrupted_adapter_update", recover)
    result = core.restore_owned_core_adapter_update()
    assert "interrupted Core cohort restored" in result
    assert fixture.effects == ["recover-interrupted"]
    assert core.JOURNAL.read_bytes() == core._canonical_json(fixture.prior)


def test_owned_adapter_update_restart_accepts_only_exact_committed_to_rollback_transform(
        committed_adapter_update_recovery, monkeypatch):
    fixture = committed_adapter_update_recovery
    committed_row = core._canonical_json(fixture.cohort)
    committed_sha = hashlib.sha256(committed_row).hexdigest()
    assert fixture.refresh["core_update_cohort_sha256"] == committed_sha
    fixture.cohort["phase"] = "rolling-back"
    reconstruction = dict(fixture.cohort["reconstruction"])
    reconstruction["phase"] = "rolling-back"
    fixture.cohort["reconstruction"] = reconstruction
    fixture.cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    rolling_raw = core._canonical_json(fixture.cohort)
    monkeypatch.setattr(core, "_read_adapter_update_cohort",
        lambda: (fixture.cohort, rolling_raw))
    ingress_before = fixture.ingress_path.read_bytes()

    def recover():
        assert core._ADAPTER_UPDATE_LOCK_HELD.get()
        fixture.effects.append("recover-interrupted")
        core.JOURNAL.write_bytes(core._canonical_json(fixture.prior))

    monkeypatch.setattr(core, "_recover_interrupted_adapter_update", recover)
    result = core.restore_owned_core_adapter_update()
    assert "interrupted Core cohort restored" in result
    assert fixture.effects == ["recover-interrupted"]
    assert fixture.ingress_path.read_bytes() == ingress_before


def test_owned_adapter_update_restart_denies_mutated_rollback_transform(
        committed_adapter_update_recovery, monkeypatch):
    fixture = committed_adapter_update_recovery
    fixture.cohort["phase"] = "rolling-back"
    reconstruction = dict(fixture.cohort["reconstruction"])
    reconstruction["phase"] = "rolling-back"
    reconstruction["new_discovery_sha256"] = "f" * 64
    fixture.cohort["reconstruction"] = reconstruction
    fixture.cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    rolling_raw = core._canonical_json(fixture.cohort)
    monkeypatch.setattr(core, "_read_adapter_update_cohort",
        lambda: (fixture.cohort, rolling_raw))
    fixture.ingress_path.write_bytes(core._canonical_json(fixture.ingress))
    with pytest.raises(core.CoreRuntimeError):
        core.restore_owned_core_adapter_update()
    assert fixture.effects == []


@pytest.mark.parametrize("change", ["partial-join", "old-generation", "old-core-source",
                                    "wrong-candidate", "bad-cohort-digest", "wrong-cohort",
                                    "public-ingress"])
def test_owned_adapter_update_recovery_denies_unjoined_state_before_restore(
        committed_adapter_update_recovery, monkeypatch, change):
    fixture = committed_adapter_update_recovery
    if change == "partial-join":
        fixture.refresh["core_update_cohort_sha256"] = None
    elif change == "old-generation":
        fixture.refresh["old_core_adapter_generation"] = "f" * 64
    elif change == "old-core-source":
        fixture.refresh["old_core_source_generation"] = "f" * 64
    elif change == "wrong-candidate":
        fixture.ingress["candidate_sha"] = "f" * 40
    elif change == "bad-cohort-digest":
        fixture.refresh["core_update_cohort_sha256"] = "not-a-digest"
    elif change == "wrong-cohort":
        fixture.cohort["cohort_transaction_id"] = "e" * 32
        cohort_raw = core._canonical_json(fixture.cohort)
        monkeypatch.setattr(core, "_read_adapter_update_cohort",
            lambda: (fixture.cohort, cohort_raw))
        fixture.refresh["core_update_cohort_sha256"] = hashlib.sha256(cohort_raw).hexdigest()
    else:
        monkeypatch.setattr(core, "_run", lambda argv, check=True:
            SimpleNamespace(stdout="active" if "tunnel" in argv[-1] else "inactive"))
    fixture.ingress_path.write_bytes(core._canonical_json(fixture.ingress))
    with pytest.raises(core.CoreRuntimeError):
        core.restore_owned_core_adapter_update()
    assert fixture.effects == []


def test_atomic_primary_restore_accepts_new_inode_but_keeps_original_owner_metadata():
    original = (1, 20, stat.S_IFREG | 0o600, 1000, 1000, 1, 64, 100, 101)
    restored = (1, 93, stat.S_IFREG | 0o600, 1000, 1000, 1, 64, 200, 201)
    assert core._restored_soul_signature_matches(restored, original)
    for index, changed in ((2, stat.S_IFREG | 0o640), (3, 0), (4, 981), (6, 65), (5, 2)):
        tampered = list(restored)
        tampered[index] = changed
        assert not core._restored_soul_signature_matches(tampered, original)


def _adapter_cohort_starting_fixture(tmp_path, monkeypatch, request, *, empty_optional_backups=False,
                                     empty_required_backup=None,
                                     credential_projection=False):
    """Build the exact on-disk systemd inputs used by the M1 source-start gate."""
    from hermes_installer.remote import obsidian_owner_lifecycle as obsidian

    runtime = tmp_path / "runtime"
    home = tmp_path / "home" / "admin" / ".hermes"
    # The real guard runs as UID 1000 and reads its generated UNIT/LAUNCHER
    # paths directly. Pytest's private tmp_path ancestors are root-only, so
    # keep these two synthetic service files in an isolated traversable /tmp
    # fixture tree; the journal, backup, and credential sources stay private.
    service_root = Path(tempfile.mkdtemp(prefix="core-m1-service-", dir="/tmp"))
    service_root.chmod(0o755)
    request.addfinalizer(lambda: shutil.rmtree(service_root))
    unit_dir = service_root / "etc" / "systemd" / "system"
    libexec = service_root / "usr" / "local" / "libexec"
    token_path = tmp_path / "etc" / "hermes-installer" / "session-token"
    for directory in (runtime, home, unit_dir, libexec, token_path.parent,
                      tmp_path / "backups", tmp_path / "overlays"):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700 if directory not in {unit_dir, libexec} else 0o755)
    # The unmodified guard stats these original service paths as admin. Keep
    # traversal public only in this disposable two-file service tree; its
    # credentials, journal, and recovery backups remain private under tmp_path.
    for directory in (service_root / "etc", service_root / "etc" / "systemd",
                      service_root / "usr", service_root / "usr" / "local"):
        directory.chmod(0o755)
    monkeypatch.setattr(core, "PYTHON", Path(sys.executable))
    monkeypatch.setattr(core, "JOURNAL", runtime / "ownership.json")
    monkeypatch.setattr(core, "RESOURCES_RECORD", runtime / "resources.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_COHORT", runtime / "cohort.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(core, "RESOURCES_SKILL_OVERLAYS", tmp_path / "overlays")
    monkeypatch.setattr(core, "UNIT", unit_dir / core.SERVICE)
    monkeypatch.setattr(core, "LAUNCHER", libexec / "launcher")
    monkeypatch.setattr(core, "TOKEN", token_path)
    monkeypatch.setattr(obsidian, "OWNER_REGISTRATION", runtime / "obsidian-registration.json")
    # read_registration deliberately opens its fixed root-owned directory via
    # directory FDs, so changing OWNER_REGISTRATION alone does not redirect
    # that lookup. Keep this cohort fixture hermetic and match its closed
    # `obsidian_registration_state=absent` row instead of hashing the Pi's
    # real registered vault after /home/admin/.hermes is privately bind-mounted.
    def fixture_registration_absent():
        raise FileNotFoundError

    monkeypatch.setattr(obsidian, "read_registration", fixture_registration_absent)
    token = b"test-session-token\n"
    token_path.write_bytes(token)

    old_source = tmp_path / "adapter-old" / "src"
    new_source = tmp_path / "adapter-new" / "src"
    old_adapter, new_adapter = "a" * 64, "b" * 64
    core_generation = "c" * 64
    artifact_old, artifact_new = "d" * 64, "e" * 64
    old_launcher = core._launcher(adapter_source=old_source)
    new_launcher = core._launcher(adapter_source=new_source)
    old_unit = core._unit(adapter_source=old_source, cohort_gate=True,
                          backup_generation=old_adapter)
    new_unit = core._unit(adapter_source=new_source, cohort_gate=True,
                          backup_generation=old_adapter,
                          failure_diagnostics=True, whole_guard_encoding=True,
                          credential_projection=credential_projection)
    core.LAUNCHER.write_bytes(new_launcher)
    core.LAUNCHER.chmod(0o755)
    core.UNIT.write_bytes(new_unit)
    core.UNIT.chmod(0o644)
    expected_service_files = {core.UNIT.resolve(), core.LAUNCHER.resolve()}
    actual_service_files = {
        path.resolve() for path in service_root.rglob("*") if path.is_file()
    }
    expected_service_directories = {
        service_root.resolve(), (service_root / "etc").resolve(),
        (service_root / "etc" / "systemd").resolve(), unit_dir.resolve(),
        (service_root / "usr").resolve(), (service_root / "usr" / "local").resolve(),
        libexec.resolve(),
    }
    actual_service_directories = {
        path.resolve() for path in service_root.rglob("*") if path.is_dir()
    } | {service_root.resolve()}
    actual_service_entries = {path.resolve() for path in service_root.rglob("*")}
    service_directory_custody = all(
        not path.is_symlink()
        and stat.S_ISDIR(path.lstat().st_mode)
        and (path.lstat().st_uid, path.lstat().st_gid,
             stat.S_IMODE(path.lstat().st_mode)) == (core.ROOT_UID, core.ROOT_UID, 0o755)
        for path in (service_root, service_root / "etc", service_root / "etc" / "systemd",
                     unit_dir, service_root / "usr", service_root / "usr" / "local", libexec)
    )
    service_file_custody = (
        not core.UNIT.is_symlink() and not core.LAUNCHER.is_symlink()
        and (core.UNIT.stat().st_uid, core.UNIT.stat().st_gid,
             stat.S_IMODE(core.UNIT.stat().st_mode), core.UNIT.stat().st_nlink)
            == (core.ROOT_UID, core.ROOT_UID, 0o644, 1)
        and (core.LAUNCHER.stat().st_uid, core.LAUNCHER.stat().st_gid,
             stat.S_IMODE(core.LAUNCHER.stat().st_mode), core.LAUNCHER.stat().st_nlink)
            == (core.ROOT_UID, core.ROOT_UID, 0o755, 1)
    )
    if (actual_service_files != expected_service_files
            or actual_service_directories != expected_service_directories
            or actual_service_entries != expected_service_files | (expected_service_directories - {service_root.resolve()})
            or any(path.is_symlink() for path in service_root.rglob("*"))
            or not service_directory_custody or not service_file_custody):
        raise AssertionError(
            "public fixture tree must contain only the two root-owned service files "
            "and root-owned 0755 traversal directories")
    new_recipe = core._adapter_recipe_sha256(
        str(new_source), new_adapter, hashlib.sha256(new_unit).hexdigest(),
        hashlib.sha256(new_launcher).hexdigest())
    old_recipe = core._adapter_recipe_sha256(
        str(old_source), old_adapter, hashlib.sha256(old_unit).hexdigest(),
        hashlib.sha256(old_launcher).hexdigest())
    token_sha = hashlib.sha256(token).hexdigest()
    backup_directory = core.ADAPTER_UPDATE_BACKUPS / old_adapter
    backup_directory.mkdir(mode=0o700)
    optional_empty = set(core._ADAPTER_UPDATE_OPTIONAL_EMPTY_BACKUP_MEMBERS)
    empty_members = optional_empty if empty_optional_backups else set()
    if empty_required_backup is not None:
        assert empty_required_backup in core._ADAPTER_UPDATE_BACKUP_MEMBERS
        assert empty_required_backup not in optional_empty
        empty_members.add(empty_required_backup)
    backup_contents = {
        name: (b"" if name in empty_members
               else ("proof:" + name + "\n").encode())
        for name in core._ADAPTER_UPDATE_BACKUP_MEMBERS}
    backup_files = {name: hashlib.sha256(content).hexdigest()
                    for name, content in backup_contents.items()}
    for name, content in backup_contents.items():
        path = backup_directory / name
        path.write_bytes(content)
        path.chmod(0o600)
    manifest_raw = core._canonical_json(backup_files)
    (backup_directory / "manifest.json").write_bytes(manifest_raw)
    (backup_directory / "manifest.json").chmod(0o600)
    backup = {"path": str(backup_directory),
              "source_generation": old_adapter, "files": backup_files}
    journal = {
        "schema": 1, "state": "installed", "service": core.SERVICE,
        "adapter_migration_state": "active", "adapter_source": str(new_source),
        "adapter_generation": new_adapter, "core_source_generation": core_generation,
        "plugin_selection_sha256": "f" * 64, "token_sha256": token_sha,
        "unit_sha256": hashlib.sha256(new_unit).hexdigest(),
        "launcher_sha256": hashlib.sha256(new_launcher).hexdigest(),
        "adapter_update_state": "starting", "adapter_update_backup": backup,
        "adapter_update_previous_source": str(old_source),
        "adapter_update_target_source": str(new_source),
        "adapter_update_target_generation": new_adapter,
        "adapter_update_staged_plugin_sha256": "1" * 64,
        "adapter_update_cohort_transaction_id": "2" * 32,
    }
    journal_raw = core._canonical_json(journal)
    core.JOURNAL.write_bytes(journal_raw)
    core.JOURNAL.chmod(0o600)
    resources = {"core_source_generation": core_generation,
                 "core_ownership_sha256": hashlib.sha256(journal_raw).hexdigest(),
                 "artifact_sha256": artifact_new}
    resources_raw = core._canonical_json(resources)
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    core.RESOURCES_RECORD.chmod(0o600)
    old_journal_sha = hashlib.sha256(b"prior-journal\n").hexdigest()
    old_resources_sha = hashlib.sha256(b"prior-resources\n").hexdigest()
    recon = {
        "schema": 1, "purpose": "helper-only-base-reconstruction",
        "cohort_transaction_id": "2" * 32, "owner_uid": 1000,
        "home_role": "jarvis-primary-home", "phase": "source-starting",
        "old_base_artifact_sha256": artifact_old,
        "new_base_artifact_sha256": artifact_new,
        "old_composed_artifact_sha256": artifact_old,
        "new_composed_artifact_sha256": artifact_new,
        "overlay_journal_sha256": core._ABSENT_DIGEST, "overlay_contents": [],
        "base_non_installer_manifest_sha256": "3" * 64,
        "composed_non_installer_manifest_sha256": "3" * 64,
        "materialized_tree_sha256": "4" * 64,
        "old_installed_journal_sha256": "5" * 64,
        "new_installed_journal_sha256": "6" * 64,
        "old_discovery_sha256": old_resources_sha,
        "new_discovery_sha256": hashlib.sha256(resources_raw).hexdigest(),
        "old_core_source_generation": core_generation,
        "new_core_source_generation": core_generation,
        "old_source_recipe_sha256": old_recipe,
        "new_source_recipe_sha256": new_recipe,
    }
    cohort = {
        "schema": 1, "purpose": core._ADAPTER_COHORT_PURPOSE,
        "cohort_transaction_id": "2" * 32, "owner_uid": 1000,
        "home_role": "jarvis-primary-home", "phase": "source-starting",
        "old_source": str(old_source), "new_source": str(new_source),
        "old_adapter_generation": old_adapter, "new_adapter_generation": new_adapter,
        "old_core_source_generation": core_generation,
        "new_core_source_generation": core_generation,
        "old_source_recipe_sha256": old_recipe, "new_source_recipe_sha256": new_recipe,
        "old_unit_sha256": hashlib.sha256(old_unit).hexdigest(),
        "old_launcher_sha256": hashlib.sha256(old_launcher).hexdigest(),
        "new_unit_sha256": hashlib.sha256(new_unit).hexdigest(),
        "new_launcher_sha256": hashlib.sha256(new_launcher).hexdigest(),
        "guarded_old_unit_sha256": hashlib.sha256(old_unit).hexdigest(),
        "guarded_old_recipe_sha256": old_recipe,
        "old_process_identity_sha256": "7" * 64,
        "old_journal_sha256": old_journal_sha,
        "new_journal_sha256": None,
        "old_resources_record_sha256": old_resources_sha,
        "pre_switch_resources_record_sha256": old_resources_sha,
        "starting_journal_sha256": hashlib.sha256(journal_raw).hexdigest(),
        "starting_resources_record_sha256": hashlib.sha256(resources_raw).hexdigest(),
        "new_resources_record_sha256": None,
        "old_artifact_sha256": artifact_old, "new_artifact_sha256": artifact_new,
        "owner_generation_backup_name": ".jarvis-resources-skills-helper-transition-" + "2" * 32,
        "primary_record_sha256": core._ABSENT_DIGEST,
        "initial_primary_transition": None,
        "native_plugin_transition": None,
        "obsidian_registration_state": "absent",
        "obsidian_registration_sha256": core._ABSENT_DIGEST,
        "obsidian_vault_tree_sha256": core._ABSENT_DIGEST,
        "reconstruction": recon,
        "reconstruction_sha256": hashlib.sha256(core._canonical_json(recon)).hexdigest(),
    }
    core._write_adapter_update_cohort(cohort, expected_raw=None)
    assert core._read_adapter_update_cohort()[0] == cohort
    return new_unit, cohort, journal_raw, resources_raw


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort journal requires the enrolled Pi root actor")
def test_unwritten_initial_primary_rollback_is_closed_and_partial_without_backup_is_denied(
        tmp_path, monkeypatch, request):
    _unit_bytes, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    current_raw = core._projection_file(
        core.ADAPTER_UPDATE_COHORT, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o400, maximum=128 * 1024)
    transition = {
        "schema": 1, "purpose": "initial-primary-adoption", "state": "rolling-back",
        "prior_record_state": "absent", "prior_soul_sha256": "a" * 64,
        "prior_soul_signature": [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 42, 1, 1],
        "source_prompt_sha256": "b" * 64, "managed_block_sha256": "c" * 64,
        "desired_soul_sha256": "d" * 64, "owner_separator_hex": "0a",
        "owner_backup_sha256": None, "preparing_record_sha256": None,
        "writing_record_sha256": None, "adopted_record_sha256": None,
        "before_resources_record_sha256": cohort["old_resources_record_sha256"],
        "after_resources_record_sha256": None,
    }
    cohort["phase"] = "rolling-back"
    cohort["initial_primary_transition"] = transition
    reconstruction = dict(cohort["reconstruction"])
    reconstruction["phase"] = "rolling-back"
    cohort["reconstruction"] = reconstruction
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    raw = core._write_adapter_update_cohort(cohort, expected_raw=current_raw)
    parsed, parsed_raw = core._read_adapter_update_cohort()
    assert parsed_raw == raw
    assert parsed["primary_record_sha256"] == core._ABSENT_DIGEST
    assert parsed["initial_primary_transition"] == transition

    partial = dict(parsed)
    partial_transition = dict(transition)
    partial_transition["preparing_record_sha256"] = "e" * 64
    partial["initial_primary_transition"] = partial_transition
    raw = core._write_adapter_update_cohort(partial, expected_raw=parsed_raw)
    with pytest.raises(core.CoreRuntimeError, match="malformed or foreign"):
        core._read_adapter_update_cohort()
    parsed_raw = raw

    foreign = dict(parsed)
    foreign["primary_record_sha256"] = "f" * 64
    raw = core._write_adapter_update_cohort(foreign, expected_raw=parsed_raw)
    with pytest.raises(core.CoreRuntimeError, match="malformed or foreign"):
        core._read_adapter_update_cohort()


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort journal requires the enrolled Pi root actor")
def test_initial_primary_cohort_joins_each_recorded_manager_digest_exactly(
        tmp_path, monkeypatch, request):
    _unit, cohort, _journal, _resources = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    prior_soul = "a" * 64
    transition = {
        "schema": 1, "purpose": "initial-primary-adoption", "state": "pending",
        "prior_record_state": "absent", "prior_soul_sha256": prior_soul,
        "prior_soul_signature": [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 42, 1, 1],
        "source_prompt_sha256": "b" * 64, "managed_block_sha256": "c" * 64,
        "desired_soul_sha256": "d" * 64, "owner_separator_hex": "0a",
        "owner_backup_sha256": None, "preparing_record_sha256": None,
        "writing_record_sha256": None, "adopted_record_sha256": None,
        "before_resources_record_sha256": cohort["old_resources_record_sha256"],
        "after_resources_record_sha256": None,
    }
    raw = core._projection_file(
        core.ADAPTER_UPDATE_COHORT, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o400, maximum=128 * 1024)

    def store(candidate, *, accepted):
        nonlocal raw
        raw = core._write_adapter_update_cohort(candidate, expected_raw=raw)
        if accepted:
            parsed, parsed_raw = core._read_adapter_update_cohort()
            assert parsed_raw == raw
            assert parsed["initial_primary_transition"] == candidate["initial_primary_transition"]
        else:
            with pytest.raises(core.CoreRuntimeError, match="malformed or foreign"):
                core._read_adapter_update_cohort()

    candidate = dict(cohort, initial_primary_transition=dict(transition),
                     primary_record_sha256=core._ABSENT_DIGEST)
    store(candidate, accepted=True)  # pending has no manager journal or backup claim

    armed = dict(transition, state="preparing")
    candidate = dict(candidate, initial_primary_transition=armed)
    store(candidate, accepted=True)  # armed prepare still has no persisted manager digest

    preparing_digest = "e" * 64
    preparing = dict(armed, owner_backup_sha256=prior_soul,
                     preparing_record_sha256=preparing_digest)
    candidate = dict(candidate, initial_primary_transition=preparing,
                     primary_record_sha256=preparing_digest)
    store(candidate, accepted=True)

    wrong_preparing = dict(candidate, primary_record_sha256="f" * 64)
    store(wrong_preparing, accepted=False)
    missing_backup = dict(candidate,
        initial_primary_transition=dict(preparing, owner_backup_sha256=None))
    store(missing_backup, accepted=False)

    writing_digest = "9" * 64
    writing = dict(preparing, state="writing", writing_record_sha256=writing_digest)
    candidate = dict(candidate, initial_primary_transition=writing,
                     primary_record_sha256=writing_digest)
    store(candidate, accepted=True)
    store(dict(candidate, primary_record_sha256=preparing_digest), accepted=False)


def test_initial_primary_writing_snapshot_requires_exact_stage_metadata_and_fresh_soul():
    desired = b"owner prefix\nmanaged Jarvis block\n"
    prior_sha = "a" * 64
    source_sha = "b" * 64
    block_sha = "c" * 64
    artifact_sha = "d" * 64
    core_generation = "e" * 64
    separator = "0a"
    prior_signature = (9, 10, stat.S_IFREG | 0o600, 1000, 1000, 1, 14, 1, 1)
    fresh_signature = (9, 11, stat.S_IFREG | 0o600, 1000, 1000, 1, len(desired), 2, 2)
    custody = SimpleNamespace(
        core_source_generation=core_generation, artifact_a1_sha256=artifact_sha,
        prior_soul_sha256=prior_sha, source_prompt_sha256=source_sha,
        managed_block_sha256=block_sha, owner_separator_hex=separator,
        desired_soul_sha256=hashlib.sha256(desired).hexdigest(),
        prior_soul_signature=prior_signature)
    record = {
        "state": "writing", "core_source_generation": core_generation,
        "artifact_sha256": artifact_sha, "prior_soul_sha256": prior_sha,
        "source_prompt_sha256": source_sha, "managed_block_sha256": block_sha,
        "owner_separator_hex": separator, "result_soul_sha256": custody.desired_soul_sha256,
        # The installed signature is captured by Core's fresh read, then saved
        # by the manager only after the A1 Resources readback completes.
        "result_soul_signature": [],
    }
    raw = core._canonical_json(record)
    digest = hashlib.sha256(raw).hexdigest()
    transition = {
        "state": "writing", "writing_record_sha256": digest,
        "prior_soul_sha256": prior_sha, "source_prompt_sha256": source_sha,
        "managed_block_sha256": block_sha, "owner_separator_hex": separator,
        "desired_soul_sha256": custody.desired_soul_sha256,
    }
    cohort = {"primary_record_sha256": digest}

    assert core._initial_primary_writing_snapshot_matches(
        custody, cohort, transition, raw, record, desired, fresh_signature)
    assert not core._initial_primary_writing_snapshot_matches(
        custody, dict(cohort, primary_record_sha256="f" * 64), transition, raw,
        record, desired, fresh_signature)
    assert not core._initial_primary_writing_snapshot_matches(
        custody, cohort, transition, raw, record, b"prior owner bytes", fresh_signature)
    relaxed_mode_signature = (9, 11, stat.S_IFREG | 0o644, 1000, 1000, 1, len(desired), 2, 2)
    assert not core._initial_primary_writing_snapshot_matches(
        custody, cohort, transition, raw, record, desired, relaxed_mode_signature)
    changed_metadata = dict(record, managed_block_sha256="f" * 64)
    assert not core._initial_primary_writing_snapshot_matches(
        custody, cohort, transition, core._canonical_json(changed_metadata),
        changed_metadata, desired, fresh_signature)
    prematurely_signed = dict(record, result_soul_signature=[1, 2, 3])
    assert not core._initial_primary_writing_snapshot_matches(
        custody, cohort, transition, core._canonical_json(prematurely_signed),
        prematurely_signed, desired, fresh_signature)


@pytest.mark.parametrize("failure", ["prewrite", "fresh-soul-read"])
def test_initial_primary_refresh_refuses_before_native_A1_read_on_unwritten_or_unreadable_soul(
        monkeypatch, failure):
    custody = SimpleNamespace()
    transition = {"state": "preparing" if failure == "prewrite" else "writing",
                  "after_resources_record_sha256": None}
    events = []
    monkeypatch.setattr(core, "_initial_primary_current", lambda _custody: True)
    monkeypatch.setattr(core, "_read_adapter_update_cohort", lambda: ({}, b"cohort"))
    monkeypatch.setattr(core, "_initial_primary_transition_row", lambda _cohort: transition)
    monkeypatch.setattr(core, "_initial_primary_record_and_soul",
                        lambda: (_ for _ in ()).throw(OSError("controlled owner read failure")))
    monkeypatch.setattr(core, "_verified_resources_payload",
                        lambda: events.append("native-A1-read"))

    expected = core.CoreRuntimeError if failure == "prewrite" else OSError
    with pytest.raises(expected):
        core.refresh_initial_primary_starting_tuple(custody)
    assert events == []


@pytest.mark.parametrize("drift", ["soul-bytes", "soul-mode"])
def test_initial_primary_refresh_rechecks_soul_after_native_read_before_receipt_write(
        monkeypatch, drift):
    desired = b"exact owner prefix\nmanaged block\n"
    changed_soul = desired + b"concurrent edit\n"
    prior_signature = (1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 12, 1, 1)
    before_signature = (1, 3, stat.S_IFREG | 0o600, 1000, 1000, 1, len(desired), 2, 2)
    after_signature = ((1, 4, stat.S_IFREG | 0o644, 1000, 1000, 1, len(desired), 3, 3)
                       if drift == "soul-mode" else
                       (1, 4, stat.S_IFREG | 0o600, 1000, 1000, 1, len(changed_soul), 3, 3))
    record = {
        "state": "writing", "core_source_generation": "e" * 64,
        "artifact_sha256": "d" * 64, "prior_soul_sha256": "a" * 64,
        "source_prompt_sha256": "b" * 64, "managed_block_sha256": "c" * 64,
        "owner_separator_hex": "0a", "result_soul_sha256": hashlib.sha256(desired).hexdigest(),
        "result_soul_signature": [],
    }
    raw = core._canonical_json(record)
    digest = hashlib.sha256(raw).hexdigest()
    transition = {
        "state": "writing", "after_resources_record_sha256": None,
        "writing_record_sha256": digest, "prior_soul_sha256": record["prior_soul_sha256"],
        "source_prompt_sha256": record["source_prompt_sha256"],
        "managed_block_sha256": record["managed_block_sha256"],
        "owner_separator_hex": record["owner_separator_hex"],
        "desired_soul_sha256": record["result_soul_sha256"],
    }
    cohort = {"primary_record_sha256": digest}
    custody = SimpleNamespace(
        core_source_generation=record["core_source_generation"],
        artifact_a1_sha256=record["artifact_sha256"],
        prior_soul_sha256=record["prior_soul_sha256"],
        prior_soul_signature=prior_signature,
        source_prompt_sha256=record["source_prompt_sha256"],
        managed_block_sha256=record["managed_block_sha256"],
        owner_separator_hex=record["owner_separator_hex"],
        desired_soul_sha256=record["result_soul_sha256"])
    reads = iter(((raw, record, desired, before_signature),
                  (raw, record, changed_soul if drift == "soul-bytes" else desired,
                   after_signature)))
    events = []
    monkeypatch.setattr(core, "_initial_primary_current", lambda _custody: True)
    monkeypatch.setattr(core, "_read_adapter_update_cohort", lambda: (cohort, b"cohort"))
    monkeypatch.setattr(core, "_initial_primary_transition_row", lambda _cohort: transition)
    monkeypatch.setattr(core, "_initial_primary_record_and_soul", lambda: next(reads))
    monkeypatch.setattr(core, "initial_primary_adoption_scope", lambda _custody: contextlib.nullcontext())
    monkeypatch.setattr(core, "verify_initial_primary_adoption_custody", lambda _custody: True)
    monkeypatch.setattr(core, "_verified_resources_payload",
                        lambda: (events.append("native-A1-read") or (b"archive", {})))
    monkeypatch.setattr(core, "_write_adapter_update_cohort",
                        lambda *_args, **_kwargs: events.append("cohort-write"))
    monkeypatch.setattr(core, "_write_resources_record_bytes",
                        lambda *_args, **_kwargs: events.append("Resources-write"))

    with pytest.raises(core.CoreRuntimeError, match="changed during native A1 readback"):
        core.refresh_initial_primary_starting_tuple(custody)
    assert events == ["native-A1-read"]


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort rollback custody requires the enrolled Pi root actor")
def test_unwritten_initial_primary_rollback_requires_original_soul_inode_and_signature(
        tmp_path, monkeypatch, request):
    _unit, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    signature = (1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 42, 1, 1)
    soul = b"original owner SOUL\n"
    transition = {
        "schema": 1, "purpose": "initial-primary-adoption", "state": "rolling-back",
        "prior_record_state": "absent", "prior_soul_sha256": hashlib.sha256(soul).hexdigest(),
        "prior_soul_signature": list(signature), "source_prompt_sha256": "b" * 64,
        "managed_block_sha256": "c" * 64, "desired_soul_sha256": "d" * 64,
        "owner_separator_hex": "0a", "owner_backup_sha256": None,
        "preparing_record_sha256": None, "writing_record_sha256": None,
        "adopted_record_sha256": None,
        "before_resources_record_sha256": cohort["old_resources_record_sha256"],
        "after_resources_record_sha256": None,
    }
    cohort["phase"] = "rolling-back"
    cohort["initial_primary_transition"] = transition
    reconstruction = dict(cohort["reconstruction"])
    reconstruction["phase"] = "rolling-back"
    cohort["reconstruction"] = reconstruction
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    current_raw = core._projection_file(
        core.ADAPTER_UPDATE_COHORT, owner=core.ROOT_UID, group=core.ROOT_UID,
        mode=0o400, maximum=128 * 1024)
    core._write_adapter_update_cohort(cohort, expected_raw=current_raw)
    cohort, _ = core._read_adapter_update_cohort()

    prior = {"adapter_source": cohort["old_source"]}
    contents = {
        "journal.json": b"prior-journal\n", "resources-record.json": b"prior-resources\n",
        "overlay-record.json": b"", "obsidian-registration.json": b"",
        "unit": core._unit(adapter_source=Path(cohort["old_source"]), cohort_gate=True,
                            backup_generation=cohort["old_adapter_generation"]),
        "launcher": core._launcher(adapter_source=Path(cohort["old_source"])),
        "primary-record.json": b"",
    }
    from hermes_installer import primary_prompt_manager as primary
    monkeypatch.setattr(primary, "_read_soul", lambda _core: (soul, signature))
    core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)

    replacement_signature = (1, 3, *signature[2:])
    monkeypatch.setattr(primary, "_read_soul", lambda _core: (soul, replacement_signature))
    with pytest.raises(core.CoreRuntimeError, match="original owner SOUL"):
        core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_exec_start_pre_uses_only_explicit_captured_runner_under_core_subprocess_deny(
        tmp_path, monkeypatch, request):
    guard_runner = subprocess.run
    unit, _cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)

    def deny_core_subprocess(*_args, **_kwargs):
        raise AssertionError("Core cohort attempted an unapproved host subprocess")

    monkeypatch.setattr(core.subprocess, "run", deny_core_subprocess)
    with pytest.raises(AssertionError, match="unapproved host subprocess"):
        core.subprocess.run(["true"])
    assert _exec_start_pre(unit, expect_success=True, runner=guard_runner) == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_final_resources_binding_accepts_only_exact_active_derivative_of_verified_starting_tuple(
        tmp_path, monkeypatch, request):
    _unit, cohort, journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    monkeypatch.setattr(core, "ADAPTER_SOURCE", Path(cohort["new_source"]))
    starting = json.loads(journal_raw)
    cohort["phase"] = "bindings-verified"
    reconstruction = dict(cohort["reconstruction"])
    reconstruction["phase"] = "bindings-verified"
    cohort["reconstruction"] = reconstruction
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    cohort_raw = core._canonical_json(cohort)
    resources = {
        "schema": 3, "state": "discovered", "functional": False,
        "enabled": False, "target_verified": False,
        "core_source_generation": cohort["new_core_source_generation"],
        "core_ownership_sha256": hashlib.sha256(journal_raw).hexdigest(),
        "artifact_sha256": cohort["new_artifact_sha256"],
        "resources_revision": "reviewed-revision", "resources_tree": "a" * 40,
        "inventory": [{"path": "profiles/master.md", "sha256": "1" * 64}],
        "observed_at_utc": "2026-10-13T00:00:00Z",
    }
    resources_raw = core._canonical_json(resources)
    final = dict(starting)
    final["adapter_update_state"] = "active"
    final_raw = core._canonical_json(final)
    guard = SimpleNamespace(
        purpose="resources-readback", phase="bindings-verified",
        cohort_transaction_id=cohort["cohort_transaction_id"],
        cohort_sha256=hashlib.sha256(cohort_raw).hexdigest(),
        starting_journal_sha256=hashlib.sha256(journal_raw).hexdigest(),
        starting_resources_record_sha256=hashlib.sha256(resources_raw).hexdigest(),
    )
    monkeypatch.setattr(core, "_ADAPTER_UPDATE_LOCK_HELD",
                        SimpleNamespace(get=lambda: True))
    monkeypatch.setattr(core, "_GUARDED_NEW_READ_CONTEXT",
                        SimpleNamespace(get=lambda: guard))
    monkeypatch.setattr(core, "_validate_guarded_new_read", lambda value: value is guard)
    monkeypatch.setattr(core, "_read_adapter_update_cohort", lambda: (cohort, cohort_raw))
    monkeypatch.setattr(core, "_projection_file", lambda path, **_kwargs:
                        journal_raw if path == core.JOURNAL else resources_raw)

    readback = dict(resources, observed_at_utc="2026-10-13T00:00:01Z")
    bound = core._bind_resources_record_to_final_journal(readback, final_raw)
    assert bound == dict(readback,
                         core_ownership_sha256=hashlib.sha256(final_raw).hexdigest())
    with pytest.raises(core.CoreRuntimeError, match="starting source journal"):
        core._bind_resources_record_to_starting_journal(readback, final_raw)
    with pytest.raises(core.CoreRuntimeError, match="exact active derivative"):
        altered = dict(final, adapter_update_target_generation="f" * 64)
        core._bind_resources_record_to_final_journal(
            readback, core._canonical_json(altered))
    with pytest.raises(core.CoreRuntimeError, match="A1 Resources readback"):
        altered_readback = dict(readback, inventory=[])
        core._bind_resources_record_to_final_journal(altered_readback, final_raw)
    monkeypatch.setattr(core, "_validate_guarded_new_read", lambda _value: False)
    with pytest.raises(core.CoreRuntimeError, match="current guarded new-source read"):
        core._bind_resources_record_to_final_journal(readback, final_raw)


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_boot_gate_admits_only_the_exact_source_starting_journal_and_resources(
        tmp_path, monkeypatch, request):
    unit, cohort, journal_raw, resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    backup_credentials = [row for row in unit.decode().splitlines()
        if row.startswith("LoadCredential=adapter-backup-")]
    assert len(backup_credentials) == len(core._ADAPTER_UPDATE_BACKUP_MEMBERS) + 1
    assert not any("native-plugin" in row for row in backup_credentials)
    systemd_argv = _systemd_decoded_exec_start_pre(unit)
    compile(systemd_argv[4], "<systemd-decoded-source-cohort-guard>", "exec")
    assert systemd_argv[4].startswith("exec(bytes.fromhex(")
    expected_program = core._core_start_guard_code(
        adapter_source=Path(cohort["new_source"]), cohort_gate=True,
        backup_generation=cohort["old_adapter_generation"],
        native_plugin_transition=False, failure_diagnostics=True)
    expected_wrapper = "exec(bytes.fromhex(" + repr(
        expected_program.encode("utf-8").hex()) + ").decode('utf-8'))"
    assert systemd_argv[4] == expected_wrapper
    assert _exec_start_pre(unit, expect_success=True, systemd_argv=systemd_argv) == 0
    # A reboot during any incomplete phase must fail closed even when the
    # systemd unit and launcher already contain the new source recipe.
    for phase in ("prepared", "resources-rebound", "rolling-back"):
        changed = dict(cohort)
        changed["phase"] = phase
        changed_reconstruction = dict(changed["reconstruction"])
        changed_reconstruction["phase"] = phase
        changed["reconstruction"] = changed_reconstruction
        changed["reconstruction_sha256"] = hashlib.sha256(
            core._canonical_json(changed_reconstruction)).hexdigest()
        core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
            core._canonical_json(changed), 0o400, core.ROOT_UID, core.ROOT_UID)
        assert _exec_start_pre(unit, expect_success=False, systemd_argv=systemd_argv) != 0
    core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
        core._canonical_json(cohort), 0o400, core.ROOT_UID, core.ROOT_UID)

    core.JOURNAL.write_bytes(b'{"partial":"journal"}\n')
    assert _exec_start_pre(unit, expect_success=False, systemd_argv=systemd_argv) != 0
    core.JOURNAL.write_bytes(journal_raw)
    core.RESOURCES_RECORD.write_bytes(b'{"partial":"resources"}\n')
    assert _exec_start_pre(unit, expect_success=False, systemd_argv=systemd_argv) != 0
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    assert _exec_start_pre(unit, expect_success=True, systemd_argv=systemd_argv) == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_boot_gate_accepts_only_manifested_empty_optional_legacy_backups(
        tmp_path, monkeypatch, request):
    unit, _cohort, _journal, _resources = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request, empty_optional_backups=True)
    credentials = {row.partition("=")[2].partition(":")[0]: row.partition("=")[2].partition(":")[2]
                   for row in unit.decode().splitlines()
                   if row.startswith("LoadCredential=adapter-backup-")}
    assert len(credentials) == len(core._ADAPTER_UPDATE_BACKUP_MEMBERS) + 1
    assert _exec_start_pre(unit, expect_success=True) == 0

    required = next(name for name in credentials if name.endswith("journal"))
    assert _exec_start_pre(unit, credential_mutations={required: ("bytes", b"")},
                           expect_success=False) != 0
    optional = next(name for name in credentials if name.endswith("overlay-record"))
    assert _exec_start_pre(unit, credential_mutations={optional: ("bytes", b"tampered")},
                           expect_success=False) != 0
    assert _exec_start_pre(unit, credential_mutations={optional: ("remove",)},
                           expect_success=False) != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_boot_gate_rejects_empty_required_backup_even_with_matching_manifest(
        tmp_path, monkeypatch, request):
    unit, _cohort, _journal, _resources = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request, empty_optional_backups=True,
        empty_required_backup="journal.json")
    backup_directory = core.ADAPTER_UPDATE_BACKUPS / ("a" * 64)
    manifest = json.loads((backup_directory / "manifest.json").read_bytes())
    assert (backup_directory / "journal.json").read_bytes() == b""
    assert manifest["journal.json"] == hashlib.sha256(b"").hexdigest()
    assert _exec_start_pre(unit, expect_success=False) != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="credential projection gate requires the enrolled Pi root actor")
def test_m1_fresh_cohort_accepts_only_exact_root_acl_credential_projection(
        tmp_path, monkeypatch, request):
    unit, cohort, _journal, _resources = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request, credential_projection=True)
    source = Path(cohort["new_source"])
    assert core._cohort_guard_unit(cohort, source=source,
        backup_generation=cohort["old_adapter_generation"],
        native_plugin_transition=False) == unit
    credentials = {row.partition("=")[2].partition(":")[0]
                   for row in unit.decode().splitlines()
                   if row.startswith("LoadCredential=")}
    assert credentials == {
        "core-ownership-journal", "hermes-session-token", "adapter-update-cohort",
        "resources-discovery", "adapter-backup-manifest",
        *("adapter-backup-" + name.removesuffix(".json").replace(".", "-")
          for name in core._ADAPTER_UPDATE_BACKUP_MEMBERS),
    }
    argv = _systemd_decoded_exec_start_pre(unit)
    cohort_now, _raw = core._read_adapter_update_cohort()
    expected_program = core._core_start_guard_code(
        adapter_source=source, cohort_gate=True,
        backup_generation=cohort_now["old_adapter_generation"],
        failure_diagnostics=True, credential_projection=True)
    assert argv[4] == "exec(bytes.fromhex(" + repr(
        expected_program.encode("utf-8").hex()) + ").decode('utf-8'))"
    assert _exec_start_pre(unit, expect_success=True, systemd_argv=argv,
                           credential_projection=True) == 0

    required = "adapter-backup-journal"
    optional = "adapter-backup-overlay-record"
    for mutation in (
        {required: ("acl-wrong",)},
        {required: ("mode", 0o400)},
        {required: ("owner", 1000, 1000)},
        {optional: ("remove",)},
    ):
        assert _exec_start_pre(unit, credential_mutations=mutation,
            expect_success=False, systemd_argv=argv,
            credential_projection=True) != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="native start gate requires the enrolled Pi root actor")
def test_m1_boot_gate_accepts_only_manifested_empty_optional_native_backups(
        tmp_path, monkeypatch, request):
    unit, _plugin, _old_members, _new_members = _native_plugin_starting_fixture(
        tmp_path, monkeypatch, request, empty_optional_backups=True)
    credentials = {row.partition("=")[2].partition(":")[0]: row.partition("=")[2].partition(":")[2]
                   for row in unit.decode().splitlines()
                   if row.startswith("LoadCredential=adapter-backup-")}
    assert len(credentials) == len(core._ADAPTER_UPDATE_BACKUP_MEMBERS) + 3
    assert _exec_start_pre(unit, expect_success=True, credential_projection=True) == 0

    required = next(name for name in credentials if name.endswith("unit"))
    optional = next(name for name in credentials if name.endswith("cohort"))
    assert _exec_start_pre(unit, credential_mutations={required: ("bytes", b"")},
                           expect_success=False, credential_projection=True) != 0
    assert _exec_start_pre(unit, credential_mutations={optional: ("bytes", b"wrong hash")},
                           expect_success=False, credential_projection=True) != 0
    wrong_acl = _exec_start_pre(unit,
        credential_mutations={optional: ("acl-wrong",)},
        expect_success=False, return_result=True,
        systemd_argv=_systemd_decoded_exec_start_pre(unit),
        credential_projection=True)
    assert wrong_acl.returncode == 1
    assert wrong_acl.stdout == b"FIXTURE_NAMESPACE_READY\n"
    assert len(wrong_acl.stderr.splitlines()) == 1
    assert wrong_acl.stderr.startswith(b"HERMES_CORE_START_GUARD_FAILURE_V1=")
    wrong_acl_payload = json.loads(wrong_acl.stderr.partition(b"=")[2])
    assert wrong_acl_payload["flags"]["backup_ok"] is False
    assert wrong_acl_payload["flags"]["ok"] is False
    assert wrong_acl.stderr == (
        b"HERMES_CORE_START_GUARD_FAILURE_V1="
        + json.dumps(wrong_acl_payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
        + b"\n")


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_guard_diagnostic_runs_only_after_original_guard_denies(
        tmp_path, monkeypatch, request):
    unit, _cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    token_row = next(row for row in unit.decode().splitlines()
                     if row.startswith("LoadCredential=") and "session-token" in row)
    credential_name = token_row.partition("=")[2].partition(":")[0]
    with pytest.raises(AssertionError, match="generated ExecStartPre should succeed") as caught:
        _exec_start_pre(
            unit, credential_mutations={credential_name: ("bytes", b"invalid fixture token\n")},
            expect_success=True, diagnostic=True,
            systemd_argv=_systemd_decoded_exec_start_pre(unit))
    message = str(caught.value)
    assert "exit=" in message and "guard_flags={" in message
    assert "'namespace_ready': True" in message
    assert "'guard_emitted': True" in message
    assert "invalid fixture token" not in message


@pytest.mark.skipif(os.geteuid() != 0, reason="generated guard effects require the enrolled Pi root actor")
def test_m1_new_cohort_guard_emits_only_closed_failure_flags(tmp_path, monkeypatch, request):
    unit, _plugin, _old_members, _new_members = _native_plugin_starting_fixture(
        tmp_path, monkeypatch, request)
    guard_rows = [row for row in unit.decode().splitlines()
                  if row.startswith("ExecStartPre=")]
    assert len(guard_rows) == 1
    source = Path("/opt/hermes-installer-core-fixture/src")
    legacy_unit = core._unit(adapter_source=source, cohort_gate=True,
        backup_generation="a" * 64, native_plugin_transition=True)
    assert unit != legacy_unit
    assert b"HERMES_CORE_START_GUARD_FAILURE_V1=" not in legacy_unit
    guard_argv = _systemd_decoded_exec_start_pre(unit)
    decoded_guard = guard_argv[4]
    assert decoded_guard.startswith("exec(bytes.fromhex(")
    compile(decoded_guard, "<systemd-decoded-native-guard>", "exec")

    successful = _exec_start_pre(unit, expect_success=True, return_result=True,
                                 systemd_argv=guard_argv, credential_projection=True)
    assert successful.returncode == 0
    assert successful.stdout == b"FIXTURE_NAMESPACE_READY\n"
    assert successful.stderr == b""

    token_row = next(row for row in unit.decode().splitlines()
                     if row.startswith("LoadCredential=") and "session-token" in row)
    token_name = token_row.partition("=")[2].partition(":")[0]
    sentinel = b"guard-telemetry-secret-sentinel"
    denied = _exec_start_pre(unit, credential_mutations={token_name: ("bytes", sentinel)},
        expect_success=False, return_result=True, systemd_argv=guard_argv,
        credential_projection=True)
    assert denied.returncode == 1
    assert denied.stdout == b"FIXTURE_NAMESPACE_READY\n"
    assert sentinel not in denied.stderr
    rows = [line for line in denied.stderr.splitlines()
            if line.startswith(b"HERMES_CORE_START_GUARD_FAILURE_V1=")]
    assert len(rows) == 1 and len(rows[0]) <= 4096
    assert denied.stderr == rows[0] + b"\n"
    payload = json.loads(rows[0].partition(b"=")[2])
    assert set(payload) == {"schema", "flags"} and payload["schema"] == 1
    assert rows[0] + b"\n" == (
        b"HERMES_CORE_START_GUARD_FAILURE_V1="
        + json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
        + b"\n")
    flags = payload["flags"]
    expected_flags = {
        "ok", "source_ok", "native_ok", "service_files", "journal_join",
        "resources_join", "record_identity", "adapter_state_join",
        "generation_recipe_join", "backup_ok", "phase_ok", "starting",
        "starting_ok", "active_update_ok",
    }
    assert set(flags) == expected_flags
    assert all(type(value) is bool or value is None for value in flags.values())
    assert flags["ok"] is False
    assert flags["active_update_ok"] is None
    assert b"guard-telemetry-secret-sentinel" not in rows[0]

    cohort_row = next(row for row in unit.decode().splitlines()
                      if row.startswith("LoadCredential=adapter-update-cohort:"))
    cohort_name = cohort_row.partition("=")[2].partition(":")[0]
    denied_cohort = _exec_start_pre(unit, credential_mutations={
        cohort_name: ("bytes", b"{}\n")}, expect_success=False, return_result=True,
        systemd_argv=guard_argv, credential_projection=True)
    assert denied_cohort.returncode == 1
    assert denied_cohort.stdout == b"FIXTURE_NAMESPACE_READY\n"
    assert len(denied_cohort.stderr.splitlines()) == 1
    assert denied_cohort.stderr.startswith(b"HERMES_CORE_START_GUARD_FAILURE_V1=")
    tampered_payload = json.loads(denied_cohort.stderr.partition(b"=")[2])
    assert set(tampered_payload) == {"schema", "flags"}
    assert tampered_payload["flags"]["ok"] is False
    assert all(type(value) is bool or value is None
               for value in tampered_payload["flags"].values())
    assert denied_cohort.stderr == (
        b"HERMES_CORE_START_GUARD_FAILURE_V1="
        + json.dumps(tampered_payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
        + b"\n")


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort recipe custody is qualified on the enrolled Pi")
def test_m1_cohort_accepts_only_its_exact_legacy_or_diagnostic_guard_recipe(
        tmp_path, monkeypatch, request):
    _unit_bytes, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    source = Path(cohort["new_source"])
    launcher_sha = hashlib.sha256(core._launcher(adapter_source=source)).hexdigest()
    for native_transition in (False, True):
        variants = [(False, False, False), (True, False, False),
                    (True, True, False), (True, True, True)]
        for diagnostic, whole_encoded, projected in variants:
            unit = core._unit(adapter_source=source, cohort_gate=True,
                backup_generation=cohort["old_adapter_generation"],
                native_plugin_transition=native_transition,
                failure_diagnostics=diagnostic,
                whole_guard_encoding=whole_encoded,
                credential_projection=projected)
            unit_sha = hashlib.sha256(unit).hexdigest()
            recipe = core._adapter_recipe_sha256(
                str(source), cohort["new_adapter_generation"], unit_sha, launcher_sha)
            bound = dict(cohort, new_unit_sha256=unit_sha,
                         new_launcher_sha256=launcher_sha,
                         new_source_recipe_sha256=recipe)
            assert core._cohort_guard_unit(bound, source=source,
                backup_generation=cohort["old_adapter_generation"],
                native_plugin_transition=native_transition) == unit
            tampered = dict(bound, new_source_recipe_sha256="f" * 64)
            with pytest.raises(core.CoreRuntimeError, match="exact generated recipes"):
                core._cohort_guard_unit(tampered, source=source,
                    backup_generation=cohort["old_adapter_generation"],
                    native_plugin_transition=native_transition)
            forged_unit_sha = hashlib.sha256(b"forged unit bytes\n").hexdigest()
            forged_recipe = core._adapter_recipe_sha256(
                str(source), cohort["new_adapter_generation"], forged_unit_sha, launcher_sha)
            forged = dict(bound, new_unit_sha256=forged_unit_sha,
                          new_source_recipe_sha256=forged_recipe)
            with pytest.raises(core.CoreRuntimeError, match="exact generated recipes"):
                core._cohort_guard_unit(forged, source=source,
                    backup_generation=cohort["old_adapter_generation"],
                    native_plugin_transition=native_transition)
            if native_transition and whole_encoded and not projected:
                assert unit != core._unit(adapter_source=source, cohort_gate=True,
                    backup_generation=cohort["old_adapter_generation"],
                    native_plugin_transition=True, failure_diagnostics=True)
        with pytest.raises(core.CoreRuntimeError, match="projected credentials"):
            core._unit(adapter_source=source, cohort_gate=True,
                backup_generation=cohort["old_adapter_generation"],
                failure_diagnostics=True, credential_projection=True)
    with pytest.raises(core.CoreRuntimeError, match="source-cohort unit"):
        core._unit(adapter_source=source, failure_diagnostics=True)


@pytest.mark.skipif(os.geteuid() != 0, reason="unit recipe stability is qualified on the enrolled Pi")
def test_m1_historical_core_unit_variants_remain_exact_bytes():
    # Golden output from the Pi-verified Core source SHA-256
    # 0727ee1d5321f868312ecdca738239907aeb458c9467f24f670cae0cd7a412a6.
    # These six recipes remain the exact compatibility set for old cohorts.
    source = Path("/opt/hermes-installer-core-fixture/src")
    expected = {
        (False, False, False): (14059, "86a99448e3ab3bc15cb0bffa1e3ac979119418bcc3f3f997850f20420af0aba2"),
        (False, True, False): (18672, "2b11765f94d5d0cb47bf574624a74051c4cbf795eafaeb8510d6a268859d7c50"),
        (False, True, True): (34264, "3db608b99325c1937a4bd6a6608f382dcd72cde9f7814289f7e9136fb5cedfe3"),
        (True, False, False): (20452, "1fd1876b7b42f8d494ef582c903847f70cdfe6203ad34290c9c4b67615c78b4b"),
        (True, True, False): (25065, "f16696c554d23218adcb3e5eb55568904a1be981f9a668143e040841f0ad3dcb"),
        (True, True, True): (46632, "2d4aea894fccc9c14f05ad8af218e1ea8be9a712ee30546a9be66a8016ad37ac"),
    }
    for (native_transition, diagnostics, whole_encoded), (size, digest) in expected.items():
        unit = core._unit(adapter_source=source, cohort_gate=True,
            backup_generation="a" * 64,
            native_plugin_transition=native_transition,
            failure_diagnostics=diagnostics,
            whole_guard_encoding=whole_encoded)
        assert len(unit) == size
        assert hashlib.sha256(unit).hexdigest() == digest


def _native_plugin_starting_fixture(tmp_path, monkeypatch, request, *, empty_optional_backups=False):
    """Promote the bounded starting fixture to the exact closed 11-member recipe."""
    unit, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request, empty_optional_backups=empty_optional_backups)
    old_members = {"plugin.yaml": b"name: hermes-installer-resources-delegation\n",
                   "__init__.py": b"old reviewed native tools\n"}
    new_members = {"plugin.yaml": old_members["plugin.yaml"],
                   "__init__.py": b"new reviewed native tools\n"}
    member_hashes = lambda rows: {
        name: hashlib.sha256(content).hexdigest() for name, content in rows.items()
    }
    transition = {
        "schema": 1, "purpose": "fixed-native-resources-plugin",
        "old_adapter_generation": cohort["old_adapter_generation"],
        "new_adapter_generation": cohort["new_adapter_generation"],
        "plugin_selection_sha256": "f" * 64,
        "old_members": member_hashes(old_members),
        "new_members": member_hashes(new_members),
    }

    hermes_home = tmp_path / "home" / "admin" / ".hermes"
    plugins = hermes_home / "plugins"
    plugin = plugins / "hermes-installer-resources-delegation"
    plugin.mkdir(parents=True)
    os.chown(hermes_home, 1000, 1000)
    os.chmod(hermes_home, 0o700)
    os.chown(plugins, 1000, 1000)
    os.chmod(plugins, 0o755)
    for name, content in new_members.items():
        path = plugin / name
        path.write_bytes(content)
        os.chown(path, core.ROOT_UID, core.ROOT_UID)
        path.chmod(0o444)
    os.chown(plugin, core.ROOT_UID, core.ROOT_UID)
    plugin.chmod(0o555)
    _bind_private_fixed_hermes_home(hermes_home, request)

    backup_directory = core.ADAPTER_UPDATE_BACKUPS / cohort["old_adapter_generation"]
    backup_files = json.loads((backup_directory / "manifest.json").read_bytes())
    for member_name, backup_name in core._NATIVE_PLUGIN_BACKUP_NAMES.items():
        content = old_members[member_name]
        (backup_directory / backup_name).write_bytes(content)
        (backup_directory / backup_name).chmod(0o600)
        backup_files[backup_name] = hashlib.sha256(content).hexdigest()
    manifest_raw = core._canonical_json(backup_files)
    (backup_directory / "manifest.json").write_bytes(manifest_raw)
    (backup_directory / "manifest.json").chmod(0o600)

    journal = json.loads(core.JOURNAL.read_bytes())
    journal["adapter_update_backup"]["files"] = backup_files
    journal["unit_sha256"] = "0" * 64  # replaced after rendering the closed unit
    previous_journal = {"plugin_selection_sha256": journal["plugin_selection_sha256"]}
    (backup_directory / "journal.json").write_bytes(core._canonical_json(previous_journal))
    (backup_directory / "journal.json").chmod(0o600)
    backup_files["journal.json"] = hashlib.sha256(
        (backup_directory / "journal.json").read_bytes()).hexdigest()
    manifest_raw = core._canonical_json(backup_files)
    (backup_directory / "manifest.json").write_bytes(manifest_raw)
    (backup_directory / "manifest.json").chmod(0o600)
    journal["adapter_update_backup"]["files"] = backup_files

    new_unit = core._unit(adapter_source=Path(cohort["new_source"]), cohort_gate=True,
        backup_generation=cohort["old_adapter_generation"], native_plugin_transition=True,
        failure_diagnostics=True, whole_guard_encoding=True,
        credential_projection=True)
    journal["unit_sha256"] = hashlib.sha256(new_unit).hexdigest()
    journal_raw = core._canonical_json(journal)
    core.JOURNAL.write_bytes(journal_raw)
    core.JOURNAL.chmod(0o600)
    resources = json.loads(core.RESOURCES_RECORD.read_bytes())
    resources["core_ownership_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    resources_raw = core._canonical_json(resources)
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    core.RESOURCES_RECORD.chmod(0o600)
    core.UNIT.write_bytes(new_unit)
    core.UNIT.chmod(0o644)

    launcher_sha = hashlib.sha256(core.LAUNCHER.read_bytes()).hexdigest()
    unit_sha = hashlib.sha256(new_unit).hexdigest()
    recipe = core._adapter_recipe_sha256(
        cohort["new_source"], cohort["new_adapter_generation"], unit_sha, launcher_sha)
    cohort["new_unit_sha256"] = unit_sha
    cohort["new_source_recipe_sha256"] = recipe
    cohort["starting_journal_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    cohort["starting_resources_record_sha256"] = hashlib.sha256(resources_raw).hexdigest()
    cohort["native_plugin_transition"] = transition
    reconstruction = dict(cohort["reconstruction"])
    reconstruction["new_source_recipe_sha256"] = recipe
    cohort["reconstruction"] = reconstruction
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    prior_raw = core._projection_file(core.ADAPTER_UPDATE_COHORT,
        owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o400, maximum=128 * 1024)
    core._write_adapter_update_cohort(cohort, expected_raw=prior_raw)
    return new_unit, plugin, old_members, new_members


@pytest.mark.skipif(os.geteuid() != 0, reason="native start gate requires the enrolled Pi root actor")
def test_m1_boot_gate_checks_typed_native_plugin_transition_quickly(
        tmp_path, monkeypatch, request):
    unit, plugin, _old_members, new_members = _native_plugin_starting_fixture(
        tmp_path, monkeypatch, request)
    credentials = {row.partition(":")[0] for row in unit.decode().splitlines()
                   if row.startswith("LoadCredential=adapter-backup-")}
    assert len(credentials) == len(core._ADAPTER_UPDATE_BACKUP_MEMBERS) + 3
    assert "LoadCredential=adapter-backup-native-plugin-plugin-yaml" in credentials
    assert "LoadCredential=adapter-backup-native-plugin-__init__-py" in credentials
    # The effect test must execute the exact typed argv returned by systemd,
    # not a shlex reconstruction of the ExecStartPre source.
    systemd_argv = _systemd_decoded_exec_start_pre(unit)
    compile(systemd_argv[4], "<systemd-decoded-native-guard>", "exec")
    cohort, _cohort_raw = core._read_adapter_update_cohort()
    expected_program = core._core_start_guard_code(
        adapter_source=Path(cohort["new_source"]),
        cohort_gate=True, backup_generation=cohort["old_adapter_generation"],
        native_plugin_transition=True, failure_diagnostics=True,
        credential_projection=True)
    assert systemd_argv[4] == "exec(bytes.fromhex(" + repr(
        expected_program.encode("utf-8").hex()) + ").decode('utf-8'))"
    # The retained inline diagnostic recipe is intentionally still available
    # for exact old-cohort custody, but systemd's C-unescaping corrupts it.
    # New native-plugin cohorts therefore use the separately recipe-bound
    # whole-program encoded variant above.
    legacy_inline = core._unit(adapter_source=Path("/opt/hermes-installer-core-fixture/src"),
        cohort_gate=True, backup_generation="a" * 64, native_plugin_transition=True,
        failure_diagnostics=True)
    legacy_argv = _systemd_decoded_exec_start_pre(legacy_inline)
    with pytest.raises(SyntaxError):
        compile(legacy_argv[4], "<systemd-decoded-retained-inline-guard>", "exec")
    assert _exec_start_pre(unit, expect_success=True, systemd_argv=systemd_argv,
                           credential_projection=True) == 0
    assert _exec_start_pre(unit, credential_mutations={
        "adapter-backup-native-plugin-__init__-py": ("remove",)},
        expect_success=False, systemd_argv=systemd_argv,
        credential_projection=True) != 0
    module = plugin / "__init__.py"
    module.write_bytes(b"foreign plugin bytes\n")
    os.chown(module, core.ROOT_UID, core.ROOT_UID)
    module.chmod(0o444)
    assert _exec_start_pre(unit, expect_success=False, systemd_argv=systemd_argv,
                           credential_projection=True) != 0
    module.write_bytes(new_members["__init__.py"])
    os.chown(module, core.ROOT_UID, core.ROOT_UID)
    module.chmod(0o444)
    assert _exec_start_pre(unit, expect_success=True, systemd_argv=systemd_argv,
                           credential_projection=True) == 0


def _committed_initial_primary_guard_fixture(tmp_path, monkeypatch, request):
    """Build a committed C/J/R tuple whose primary adoption used starting R."""
    unit, cohort, _starting_journal_raw, starting_resources_raw = (
        _adapter_cohort_starting_fixture(tmp_path, monkeypatch, request))
    journal = json.loads(core.JOURNAL.read_bytes())
    journal["state"] = "active"
    journal["adapter_update_state"] = "active"
    journal_raw = core._canonical_json(journal)
    core.JOURNAL.write_bytes(journal_raw)
    core.JOURNAL.chmod(0o600)
    resources = json.loads(core.RESOURCES_RECORD.read_bytes())
    resources["core_ownership_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    resources_raw = core._canonical_json(resources)
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    core.RESOURCES_RECORD.chmod(0o600)

    adopted_record_sha = "8" * 64
    cohort["phase"] = "committed"
    cohort["new_journal_sha256"] = hashlib.sha256(journal_raw).hexdigest()
    cohort["new_resources_record_sha256"] = hashlib.sha256(resources_raw).hexdigest()
    cohort["primary_record_sha256"] = adopted_record_sha
    cohort["initial_primary_transition"] = {
        "schema": 1, "purpose": "initial-primary-adoption", "state": "adopted",
        "prior_record_state": "absent", "prior_soul_sha256": "1" * 64,
        "prior_soul_signature": [1, 2, stat.S_IFREG | 0o600, 1000, 1000, 1, 10, 1, 1],
        "source_prompt_sha256": "2" * 64, "managed_block_sha256": "3" * 64,
        "desired_soul_sha256": "4" * 64, "owner_separator_hex": "0a",
        "owner_backup_sha256": "1" * 64,
        "preparing_record_sha256": "5" * 64, "writing_record_sha256": "6" * 64,
        "adopted_record_sha256": adopted_record_sha,
        "before_resources_record_sha256": "7" * 64,
        "after_resources_record_sha256": cohort["starting_resources_record_sha256"],
    }
    reconstruction = dict(cohort["reconstruction"])
    reconstruction["phase"] = "committed"
    cohort["reconstruction"] = reconstruction
    cohort["reconstruction_sha256"] = hashlib.sha256(
        core._canonical_json(reconstruction)).hexdigest()
    prior_raw = core._projection_file(core.ADAPTER_UPDATE_COHORT,
        owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o400, maximum=128 * 1024)
    core._write_adapter_update_cohort(cohort, expected_raw=prior_raw)
    return unit, cohort, resources_raw, starting_resources_raw


@pytest.mark.skipif(os.geteuid() != 0, reason="committed guard requires the enrolled Pi root actor")
def test_m1_boot_gate_committed_primary_uses_adoption_starting_resources_digest(
        tmp_path, monkeypatch, request):
    unit, cohort, final_resources_raw, starting_resources_raw = (
        _committed_initial_primary_guard_fixture(tmp_path, monkeypatch, request))
    assert cohort["initial_primary_transition"]["after_resources_record_sha256"] == (
        hashlib.sha256(starting_resources_raw).hexdigest())
    assert final_resources_raw != starting_resources_raw
    assert _exec_start_pre(unit, expect_success=True) == 0

    wrong_transition = dict(cohort)
    wrong_initial = dict(cohort["initial_primary_transition"])
    wrong_initial["after_resources_record_sha256"] = "f" * 64
    wrong_transition["initial_primary_transition"] = wrong_initial
    core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
        core._canonical_json(wrong_transition), 0o400, core.ROOT_UID, core.ROOT_UID)
    assert _exec_start_pre(unit, expect_success=False) != 0
    core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
        core._canonical_json(cohort), 0o400, core.ROOT_UID, core.ROOT_UID)

    resources = json.loads(final_resources_raw)
    resources["fixture_readback_change"] = True
    core.RESOURCES_RECORD.write_bytes(core._canonical_json(resources))
    core.RESOURCES_RECORD.chmod(0o600)
    assert _exec_start_pre(unit, expect_success=False) != 0
    core.RESOURCES_RECORD.write_bytes(final_resources_raw)
    core.RESOURCES_RECORD.chmod(0o600)
    assert _exec_start_pre(unit, expect_success=True) == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="unit recipe stability is qualified on the enrolled Pi")
def test_core_service_unit_bytes_are_stable_across_fresh_hash_seeds():
    source = Path("/opt/hermes-installer-core-fixture/src")
    variants = ((False, False, False), (True, False, False),
                (True, True, False), (True, True, True))
    expected = b"".join(core._unit(adapter_source=source, cohort_gate=True,
        backup_generation="a" * 64, native_plugin_transition=transition,
        failure_diagnostics=diagnostic, whole_guard_encoding=whole,
        credential_projection=projection)
        for transition in (False, True)
        for diagnostic, whole, projection in variants)
    repository = Path(__file__).resolve().parents[2]
    code = (
        "from pathlib import Path; import sys; from hermes_installer import core_runtime as core; "
        "variants=((False,False,False),(True,False,False),(True,True,False),(True,True,True)); "
        "sys.stdout.buffer.write(b''.join(core._unit(adapter_source=Path('/opt/hermes-installer-core-fixture/src'), "
        "cohort_gate=True, backup_generation='a'*64, native_plugin_transition=mode, "
        "failure_diagnostics=diag, whole_guard_encoding=whole, credential_projection=projection) "
        "for mode in (False,True) for diag,whole,projection in variants))"
    )
    for seed in ("1", "2"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(repository / "src")
        result = subprocess.run([sys.executable, "-c", code], cwd=repository,
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        assert result.stdout == expected


@pytest.mark.skipif(os.geteuid() != 0, reason="ExecStartPre cohort gate requires the enrolled Pi root actor")
def test_m1_boot_gate_checks_actual_backup_manifest_members_and_admin_execution(
        tmp_path, monkeypatch, request):
    unit, cohort, _journal_raw, _resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    lines = unit.decode().splitlines()
    assert "User=admin" in lines
    assert not any(line.startswith("ExecStartPre=+") for line in lines)
    assert _exec_start_pre(unit, expect_success=True) == 0
    manifest_credential = "adapter-backup-manifest"
    member_credential = "adapter-backup-journal"
    for mutations in (
        {manifest_credential: ("remove",)},
        {manifest_credential: ("bytes", b"{}\n")},
        {manifest_credential: ("owner", 0, 0)},
        {member_credential: ("remove",)},
        {member_credential: ("bytes", b"corrupt retained journal\n")},
        {member_credential: ("mode", 0o600)},
        {member_credential: ("owner", 0, 0)},
    ):
        assert _exec_start_pre(unit, credential_mutations=mutations,
                               expect_success=False) != 0


@pytest.mark.skipif(os.geteuid() != 0, reason="cohort rollback custody requires the enrolled Pi root actor")
def test_m1_rollback_refuses_owner_resources_edit_before_any_restore_effect(
        tmp_path, monkeypatch, request):
    _unit, cohort, journal_raw, resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    prior = {"adapter_source": cohort["old_source"]}
    contents = {
        "journal.json": b"prior-journal\n",
        "resources-record.json": b"prior-resources\n",
        "overlay-record.json": b"",
        "obsidian-registration.json": b"",
        "unit": core._unit(adapter_source=Path(cohort["old_source"]), cohort_gate=True,
                            backup_generation=cohort["old_adapter_generation"]),
        "launcher": core._launcher(adapter_source=Path(cohort["old_source"])),
        "primary-record.json": b"",
    }
    core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)
    original_journal = core.JOURNAL.read_bytes()
    original_unit = core.UNIT.read_bytes()
    original_launcher = core.LAUNCHER.read_bytes()
    core.RESOURCES_RECORD.write_bytes(b"owner edit after source switch\n")
    with pytest.raises(core.CoreRuntimeError, match="outside the exact source cohort"):
        core._check_adapter_cohort_rollback_currentness(cohort, prior, contents)
    assert core.JOURNAL.read_bytes() == original_journal
    assert core.UNIT.read_bytes() == original_unit
    assert core.LAUNCHER.read_bytes() == original_launcher
    assert journal_raw == original_journal
    assert resources_raw != core.RESOURCES_RECORD.read_bytes()


def test_failed_start_is_resumable_without_rotating_session_credential(tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch, fail_enable_once=True)
    with pytest.raises(core.CoreRuntimeError, match="injected"):
        core.install_or_resume()
    token = core.TOKEN.read_bytes()
    assert json.loads(core.JOURNAL.read_text())["state"] == "installed"
    message = core.install_or_resume()
    assert "listener verified" in message
    assert core.TOKEN.read_bytes() == token


def test_rollback_cleans_journaled_preparing_partial_stage(tmp_path, monkeypatch):
    _fake_runtime(tmp_path, monkeypatch)
    original = core._owned_file
    interrupted = {"done": False}

    def fail_during_launcher(path, body, mode, uid, gid, expected, repair):
        if path == core.LAUNCHER and not interrupted["done"]:
            path.write_bytes(b"partial launcher")
            os.chown(path, uid, gid)
            path.chmod(mode)
            interrupted["done"] = True
            raise core.CoreRuntimeError("injected interruption")
        return original(path, body, mode, uid, gid, expected, repair)

    monkeypatch.setattr(core, "_owned_file", fail_during_launcher)
    with pytest.raises(core.CoreRuntimeError, match="injected"):
        core.install_or_resume()
    monkeypatch.setattr(core, "_owned_file", original)
    assert json.loads(core.JOURNAL.read_text())["state"] == "preparing"
    monkeypatch.setattr(core, "_owned_listener", lambda: False)
    assert core.rollback().startswith("journal-owned core service files removed")
    assert not core.TOKEN.exists() and not core.LAUNCHER.exists()


def test_launcher_uses_isolated_pinned_loopback_without_secret_arguments():
    launcher = core._launcher().decode()
    assert "HERMES_DASHBOARD_SESSION_TOKEN" in launcher
    assert "--isolated --host 127.0.0.1 --port 8766" in launcher
    assert "HERMES_DISABLE_LAZY_INSTALLS=1" in launcher
    assert "PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1" in launcher
    assert "unset PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP VIRTUAL_ENV" in launcher
    assert "auth.json" not in launcher


def test_bundled_resource_import_uses_exact_admin_home_source_and_pm_python(tmp_path, monkeypatch):
    _isolate_resource_import_paths(tmp_path, monkeypatch)
    installer_python = tmp_path / "installer-python"
    interpreter_target = tmp_path / "pm-python-target"
    runuser = tmp_path / "runuser"
    for executable in (interpreter_target, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    installer_python.symlink_to(interpreter_target)
    monkeypatch.setattr(core.sys, "executable", str(installer_python))
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(_resource_receipt()), stderr="")

    monkeypatch.setattr(core.subprocess, "run", fake_run)
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    receipt = core._install_bundled_resources(account)
    argv, kwargs = calls[0]
    assert argv == [str(runuser), "-u", "admin", "--", str(installer_python), "-m",
                    "hermes_installer.registry.manual_jarvis_skills", "import-bundled",
                    "--home", str(core.HERMES_HOME), "--hermes-source", str(core.SOURCE),
                    "--python", str(core.PYTHON)]
    assert kwargs["timeout"] == 600
    assert kwargs["env"]["HOME"] == str(core.HOME)
    assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
    # Importer output is only an attempt signal; root discovery comes from a
    # fresh independently pinned native-loader readback after import.
    assert receipt == {}


def test_admin_import_prompt_claim_is_discarded_for_independent_root_readback(tmp_path, monkeypatch):
    _isolate_resource_import_paths(tmp_path, monkeypatch)
    installer_python = tmp_path / "installer-python"
    runuser = tmp_path / "runuser"
    for executable in (installer_python, runuser):
        executable.write_text("fixed fixture executable")
        executable.chmod(0o755)
    monkeypatch.setattr(core.sys, "executable", str(installer_python))
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(_resource_receipt()), stderr=""))

    receipt = core._install_bundled_resources(SimpleNamespace(pw_uid=os.getuid()))

    assert receipt == {}


def test_root_discards_admin_discovery_booleans_and_uses_separate_readback(tmp_path, monkeypatch):
    _isolate_resource_import_paths(tmp_path, monkeypatch)
    runuser = tmp_path / "runuser"
    runuser.write_text("fixed fixture executable")
    runuser.chmod(0o755)
    monkeypatch.setattr(core, "RUNUSER", runuser)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "_validated_executable", lambda path, _owners: path)
    receipt = _resource_receipt()
    receipt["functional"] = True
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(receipt), stderr=""))

    assert core._install_bundled_resources(SimpleNamespace(pw_uid=os.getuid())) == {}


def test_discovery_refresh_requires_current_owned_listener_and_never_changes_service(monkeypatch):
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.os, "geteuid", lambda: os.getuid())
    monkeypatch.setattr(core, "_identity", lambda **_kwargs: {"commit": core.COMMIT})
    monkeypatch.setattr(core, "_journal", lambda: {"state": "installed", "source_commit": core.COMMIT})
    repairs=[]
    monkeypatch.setattr(core, "_repair_pinned_pm_directory_modes",
                        lambda identity, record: repairs.append((identity,record)))
    writes = []
    monkeypatch.setattr(core, "_write_resources_discovery", lambda **kwargs: writes.append(kwargs) or {
        "resource_counts": {"native_skills": 396}})
    monkeypatch.setattr(core, "_run", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(AssertionError("service action is forbidden")))
    verified = "owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766;"
    monkeypatch.setattr(core, "status", lambda: verified)

    result = core.refresh_resources_discovery()

    assert writes == [{"repair_umask_dirs": True}]
    assert repairs == [({"commit": core.COMMIT}, {"state": "installed", "source_commit": core.COMMIT})]
    assert "service lifecycle unchanged" in result


def test_pm_directory_repair_changes_only_exact_0775_held_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core.os, "geteuid", lambda: os.getuid())
    target = tmp_path / "pm-bin"
    target.mkdir(mode=0o775)
    target.chmod(0o775)
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    target_fd = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        core._repair_verified_pm_directory_fds(
            {target: target_fd}, {target: parent_fd}, {target: (os.getuid(), os.getgid(), 0o775)})
        assert target.stat().st_mode & 0o777 == 0o755
    finally:
        os.close(target_fd)
        os.close(parent_fd)

    unsafe = tmp_path / "unknown-mode"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    target_fd = os.open(unsafe, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(core.CoreRuntimeError, match="changed during metadata repair"):
            core._repair_verified_pm_directory_fds(
                {unsafe: target_fd}, {unsafe: parent_fd}, {unsafe: (os.getuid(), os.getgid(), 0o775)})
        assert unsafe.stat().st_mode & 0o777 == 0o777
    finally:
        os.close(target_fd)
        os.close(parent_fd)


def test_legacy_resources_refresh_requires_pinned_archive_and_identical_materialized_members(
        tmp_path, monkeypatch):
    from hermes_installer.registry import manual_jarvis_skills as native

    archive = b"exact retained legacy artifact fixture"
    digest = hashlib.sha256(archive).hexdigest()
    cas = tmp_path / "cas"
    cas.mkdir(mode=0o700)
    retained = cas / (digest + ".zip")
    retained.write_bytes(archive)
    retained.chmod(0o600)
    old_manifest = {"schema": 1, "source": {"revision": "pinned"},
                    "installer": {"sha256": "old helper"}}
    current_manifest = {**old_manifest, "installer": {"sha256": "new helper"}}
    members = {"skills/example/SKILL.md": b"verified member"}
    monkeypatch.setattr(core, "RESOURCES_CAS", cas)
    monkeypatch.setattr(core, "LEGACY_MATERIALIZED_RESOURCES_ARTIFACT_SHA256", digest)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "HERMES_HOME", tmp_path / "home")
    monkeypatch.setattr(core.os, "geteuid", lambda: core.ROOT_UID)
    monkeypatch.setattr(native, "_read_artifact", lambda _archive, _digest:
                        (old_manifest, dict(members)))
    monkeypatch.setattr(native, "_canonical_json", lambda value:
                        json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    calls = []
    monkeypatch.setattr(core, "_hash_generation_tree", lambda *args, **kwargs:
                        calls.append((args[2], args[3], kwargs)) or "a" * 64)

    result = core._verified_legacy_materialization(native, current_manifest, members,
                                                    repair_umask_dirs=True)

    assert result[0] == archive
    assert result[1] == old_manifest and result[2] == members and result[3] == digest
    assert calls == [(members, digest, {"repair_umask_dirs": True})]
    with pytest.raises(core.CoreRuntimeError, match="byte-compatible"):
        core._verified_legacy_materialization(native, current_manifest,
            {**members, "skills/example/SKILL.md": b"changed"}, repair_umask_dirs=True)
    with pytest.raises(core.CoreRuntimeError, match="not authorized"):
        core._verified_legacy_materialization(native, current_manifest, members,
                                               repair_umask_dirs=False)


def test_root_native_readback_checks_current_loader_results_against_owned_bytes(monkeypatch, tmp_path):
    skills = [f"skill-{index:03d}" for index in range(396)]
    rows = [{"skill_id": name, "archive_path": f"skills/{name}/SKILL.md"} for name in skills]
    files = {row["archive_path"]: f"body-{row['skill_id']}".encode() for row in rows}
    files["registry/profiles/hermes/SOUL.md"] = b"bundled prompt"
    manifest = {"skill_members": rows}
    active_prompt = b"existing active prompt"
    expected_digests = {"profile:default": hashlib.sha256(active_prompt).hexdigest()}
    expected_digests.update({"skill:" + row["skill_id"]: hashlib.sha256(files[row["archive_path"]]).hexdigest()
                             for row in rows})
    payload = {"python_version": "3.14.7", "profile": "default", "skills": skills,
        "loaded": skills, "visible_profiles": ["default"], "profile_display_name": "Default",
        "profile_file_sha256": expected_digests["profile:default"],
        "managed_prompt_block_sha256": None,
        "effective_prompt_contains_managed_block": False,
        "effective_prompt_truncated": False,
        "native_effective_prompt_sha256": expected_digests["profile:default"],
        "native_effective_prompt_chars": len("existing active prompt"),
        "expected_managed_block_sha256": None, "digests": expected_digests}
    monkeypatch.setattr(core.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_uid=1000, pw_gid=1000, pw_dir="/home/admin"))
    monkeypatch.setattr(core, "_validated_executable", lambda path, _owners: path)
    monkeypatch.setattr(core, "SOURCE", tmp_path)
    monkeypatch.setattr(core.subprocess, "run", lambda *_args, **_kwargs:
        SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode()))

    receipt = core._root_native_readback(manifest, files, active_prompt)
    assert receipt["loaded_skill_count"] == 396
    assert receipt["active_prompt_matches_bundled_primary"] is False

    # Hermes strips/filters/truncates SOUL text before returning it. The native
    # digest may differ from raw file bytes; the separate raw-file digest binds
    # the loaded profile to the root-verified file without duplicating loader logic.
    payload["digests"]["profile:default"] = "b" * 64
    payload["native_effective_prompt_sha256"] = "b" * 64
    receipt = core._root_native_readback(manifest, files, active_prompt)
    assert receipt["loaded_skill_count"] == 396
    assert receipt["active_primary_prompt_sha256"] == hashlib.sha256(active_prompt).hexdigest()
    assert receipt["native_loaded_primary_prompt_sha256"] == "b" * 64

    from hermes_installer.registry.primary_prompt import render_managed_block
    managed_block = render_managed_block(files["registry/profiles/hermes/SOUL.md"])
    active_with_block = b"preserved owner prefix\n" + managed_block
    active_with_block_sha = hashlib.sha256(active_with_block).hexdigest()
    block_sha = hashlib.sha256(managed_block).hexdigest()
    payload["loaded"] = skills
    payload["digests"]["profile:default"] = active_with_block_sha
    payload.update({
        "profile_file_sha256": active_with_block_sha,
        "managed_prompt_block_sha256": block_sha,
        "effective_prompt_contains_managed_block": True,
        "native_effective_prompt_sha256": active_with_block_sha,
        "native_effective_prompt_chars": len(active_with_block.decode("utf-8")),
        "expected_managed_block_sha256": block_sha,
    })
    receipt = core._root_native_readback(
        manifest, files, active_with_block, expected_managed_block_sha256=block_sha)
    assert receipt["managed_prompt_block_sha256"] == block_sha
    assert receipt["effective_prompt_contains_managed_block"] is True

    payload["loaded"] = skills[:-1]
    with pytest.raises(core.CoreRuntimeError, match="did not match") as error:
        core._root_native_readback(manifest, files, active_prompt)
    assert '"loaded_mismatch"' in str(error.value)
    assert '"loaded_expected_mismatch_count":1' in str(error.value)
    assert "skill-000" not in str(error.value)
    assert active_prompt.decode() not in str(error.value)


def test_missing_resources_projection_is_explicitly_pending(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "RESOURCES_RECORD", tmp_path / "missing.json")
    result = core.read_current_resources_discovery(core_source_generation="d" * 64)

    assert result == {
        "core_version": None, "provider": None, "model": None, "account_state": "unknown",
        "resources_state": "pending", "resource_counts": None, "resources_revision": None,
        "artifact_sha256": None, "discovery_observed_at_utc": None,
        "active_prompt_matches_bundled_primary": None,
    }


def test_owned_journal_detects_mutated_service_file(tmp_path, monkeypatch):
    unit, launcher, token, journal = (tmp_path / name for name in
                                      ("unit", "launcher", "token", "ownership.json"))
    contents = {unit: b"unit", launcher: b"launch", token: b"credential"}
    for path, body in contents.items():
        path.write_bytes(body)
    unit.chmod(0o644)
    launcher.chmod(0o755)
    token.chmod(0o640)
    record = {"schema": 1, "state": "installed", "service": core.SERVICE,
              "unit_sha256": hashlib.sha256(contents[unit]).hexdigest(),
              "launcher_sha256": hashlib.sha256(contents[launcher]).hexdigest(),
              "token_sha256": hashlib.sha256(contents[token]).hexdigest()}
    journal.write_text(json.dumps(record))
    journal.chmod(0o600)
    monkeypatch.setattr(core, "UNIT", unit)
    monkeypatch.setattr(core, "LAUNCHER", launcher)
    monkeypatch.setattr(core, "TOKEN", token)
    monkeypatch.setattr(core, "JOURNAL", journal)
    monkeypatch.setattr(core, "ROOT_UID", os.getuid())
    monkeypatch.setattr(core, "GATEWAY_GID", os.getgid())
    monkeypatch.setattr(core, "FILE_CONTRACT", (
        (unit, "unit_sha256", os.getuid(), os.getgid(), 0o644),
        (launcher, "launcher_sha256", os.getuid(), os.getgid(), 0o755),
        (token, "token_sha256", os.getuid(), os.getgid(), 0o640)))
    class Account:
        pw_uid = 1000
        pw_dir = "/home/admin"
        pw_gid = 1000
    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    monkeypatch.setattr(
        core, "_unit",
        lambda *, startup_guard=True, adapter_source=None, cohort_gate=False,
        backup_generation=None: contents[unit],
    )
    monkeypatch.setattr(core, "_launcher",
                        lambda adapter_source=None: contents[launcher])
    assert core._journal()["service"] == core.SERVICE
    launcher.write_bytes(b"changed")
    with pytest.raises(core.CoreRuntimeError, match="changed"):
        core._journal()


def test_atomic_refuses_to_replace_existing_path(tmp_path):
    target = tmp_path / "owned"
    target.write_bytes(b"user data")
    with pytest.raises(core.CoreRuntimeError, match="occupied"):
        core._atomic(target, b"replacement", 0o600)
    assert target.read_bytes() == b"user data"


def test_preparing_transaction_repairs_only_partial_owned_file(tmp_path):
    target = tmp_path / "launcher"
    target.write_bytes(b"partial")
    target.chmod(0o700)
    expected = b"fixed root-owned launcher"
    core._owned_file(target, expected, 0o700, os.getuid(), os.getgid(),
                     hashlib.sha256(expected).hexdigest(), repair=True)
    assert target.read_bytes() == expected


def test_unit_binds_service_identity_and_protected_credential(monkeypatch):
    class Account:
        pw_uid = 1000
        pw_dir = "/home/admin"
        pw_gid = 1000

    monkeypatch.setattr(core.pwd, "getpwnam", lambda _: Account())
    unit = core._unit().decode()
    assert "User=admin" in unit
    assert "Group=1000" in unit
    assert "ExecStart=" + str(core.LAUNCHER) in unit
    assert "LoadCredential=hermes-session-token:" + str(core.TOKEN) in unit
    assert f"ExecStartPre={core.PYTHON} -I -S -c" in unit
    assert "ExecStartPre=+" not in unit
    assert "LoadCredential=core-ownership-journal:" + str(core.JOURNAL) in unit
    assert "127.0.0.1" not in unit  # listener is fixed in the verified launcher argv
