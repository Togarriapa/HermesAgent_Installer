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
import select
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from types import MappingProxyType, ModuleType, SimpleNamespace

import pytest

from hermes_installer import core_runtime as core


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


@contextlib.contextmanager
def _bounded_cohort_exception_sites():
    """Expose only code locations/types for a hidden cohort failure on Pi."""
    previous = sys.gettrace()
    sites = []
    first_substantive = []
    importer_outcomes = []
    routine = {"GeneratorExit", "StopIteration", "StopAsyncIteration"}
    allowed = {"core_runtime.py", "manual_jarvis_skills.py", "resources_skill_overlay.py"}
    filename_kinds = {}

    def filename_kind(filename):
        # Trace every line only in the three reviewed modules. Returning None
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
        print("bounded cohort exception sites: " + repr(sites[:30] + sites[-30:]))
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


def _exec_start_pre(unit_bytes, *, credential_mutations=None, expect_success=None):
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
        for name, source in credentials:
            target = cred_dir / name
            try:
                content = source.read_bytes()
            except OSError:
                raise AssertionError(
                    f"generated LoadCredential source is unreadable: {name}"
                ) from None
            target.write_bytes(content)
            target.chmod(0o400)
            os.chown(target, admin.pw_uid, admin.pw_gid)
        for name, mutation in (credential_mutations or {}).items():
            target = cred_dir / name
            if mutation[0] == "remove":
                target.unlink()
            elif mutation[0] == "bytes":
                target.write_bytes(mutation[1])
                target.chmod(0o400)
                os.chown(target, admin.pw_uid, admin.pw_gid)
            elif mutation[0] == "mode":
                target.chmod(mutation[1])
            elif mutation[0] == "owner":
                os.chown(target, mutation[1], mutation[2])
        os.chown(cred_dir, admin.pw_uid, admin.pw_gid)
        os.chmod(cred_dir, 0o500)
        command = shlex.split(line.partition("=")[2])
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
        result = subprocess.run(
            [unshare, "--mount", "--propagation", "private", "--", "sh", "-eu", "-c",
             namespace_script, "core-start-guard", str(core.UNIT), str(core.LAUNCHER),
             str(cred_dir), str(cred_view), runuser, *command],
            cwd="/", env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
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
            raise AssertionError(
                f"generated ExecStartPre should {outcome}; exit={result.returncode}; "
                f"stderr={stderr or '<empty>'}; "
                f"stdout={result.stdout.decode('utf-8', errors='replace').strip() or '<empty>'}"
            )
        return result.returncode
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


def _fake_runtime(tmp_path, monkeypatch, *, fail_enable_once=False):
    etc = tmp_path / "etc" / "hermes-installer"
    var = tmp_path / "var" / "lib" / "hermes-installer"
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    libexec = tmp_path / "usr" / "local" / "libexec"
    home = tmp_path / "home" / "admin" / ".hermes"
    for path in (etc, var.parent, unit_dir, libexec, home):
        path.mkdir(parents=True, exist_ok=True)
    for path in (etc, unit_dir, libexec):
        path.chmod(0o755)
    monkeypatch.setattr(core, "ETC_INSTALLER", etc)
    monkeypatch.setattr(core, "VAR_LIB_INSTALLER", var)
    monkeypatch.setattr(core, "SYSTEMD_UNIT_DIR", unit_dir)
    monkeypatch.setattr(core, "LIBEXEC_DIR", libexec)
    monkeypatch.setattr(core, "TOKEN", etc / "jarvis-core" / "session-token")
    monkeypatch.setattr(core, "JOURNAL", var / "core-runtime" / "ownership.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_COHORT",
                        var / "core-runtime" / "adapter-update-cohort.json")
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS",
                        var / "core-runtime" / "adapter-update-backups")
    monkeypatch.setattr(core, "RESOURCES_RECORD",
                        var / "core-runtime" / "resources-discovery.json")
    monkeypatch.setattr(core, "RESOURCES_CAS",
                        var / "core-runtime" / "resources-cas")
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
        return {"resources_state": "discovered", "artifact_sha256": record["artifact_sha256"],
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
    preserve = core.HERMES_HOME / "auth.json"
    preserve.write_text("user credential")
    first = core.install_or_resume()
    token = core.TOKEN.read_bytes()
    second = core.install_or_resume()
    assert token == core.TOKEN.read_bytes()
    assert enabled["value"]
    assert "listener verified" in first and "listener verified" in second
    assert preserve.read_text() == "user credential"
    monkeypatch.setattr(core, "_owned_listener", lambda: False)
    assert core.rollback().startswith("journal-owned core service files removed")
    assert not core.UNIT.exists() and not core.LAUNCHER.exists()
    assert preserve.read_text() == "user credential"
    assert any(argv == ("systemctl", "daemon-reload") and not unit_exists
               for argv, unit_exists in calls)


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


def _install_legacy_service_fixture(tmp_path, monkeypatch, *, journal_state="active"):
    if journal_state not in {"installed", "active"}:
        raise ValueError("legacy fixture journal state must be installed or active")
    calls, enabled = _fake_runtime(tmp_path, monkeypatch)
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
    )["resources_state"] == "discovered"


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


def _prepare_cohort_resource_materialization(tmp_path, monkeypatch, request):
    """Install a real old-helper generation and bind its receipt to the current journal."""
    from hermes_installer.registry import manual_jarvis_skills as native
    from hermes_installer.remote import obsidian_owner_lifecycle as obsidian

    # This controlled cohort is explicitly unregistered. read_registration()
    # opens the fixed root-owned directory through directory FDs, so redirect
    # its path constant as well as the lookup; never inspect the Pi's live
    # registration or vault while the fixture HOME is privately bind-mounted.
    monkeypatch.setattr(obsidian, "OWNER_REGISTRATION",
                        core.JOURNAL.parent / "obsidian-registration.json")

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

    # _hash_generation_tree enforces real root-owned ancestors and the exact
    # admin-owned .hermes subtree; keep the fixture inside a private root path.
    sandbox = Path(tempfile.mkdtemp(prefix="hermes-adapter-home-", dir="/root"))
    sandbox.chmod(0o700)
    request.addfinalizer(lambda: shutil.rmtree(sandbox, ignore_errors=True))
    admin_home = sandbox / "admin"
    home = admin_home / ".hermes"
    admin_home.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
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
    current_record.update({
        "artifact_sha256": old_sha,
        "ownership_manifest_sha256": hashlib.sha256(
            native._canonical_json(manifest)).hexdigest(),
    })
    core._atomic_replace(core.RESOURCES_CAS / (old_sha + ".zip"), old_archive,
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
    assert core.read_current_resources_discovery(
        core_source_generation=current_record["core_source_generation"]
    )["resources_state"] == "discovered"

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
        if expected_managed_block_sha256 is None:
            assert managed_block not in active_prompt
        else:
            assert hashlib.sha256(managed_block).hexdigest() == expected_managed_block_sha256
            assert managed_block in active_prompt
        readback_calls.append((active_sha, expected_managed_block_sha256))
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
            "managed_prompt_block_sha256": expected_managed_block_sha256,
            "effective_prompt_contains_managed_block": expected_managed_block_sha256 is not None,
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
    return readback_calls


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
        ("native-plugin", "install")) < ordered.index(("systemctl", "start", core.SERVICE))


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
def test_native_adapter_update_stops_before_restart_on_failure_can_launch_new_launcher(tmp_path, monkeypatch, request):
    calls, enabled, _old_launcher, selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
    core.migrate_owned_core_to_adapter_path()
    _prepare_cohort_resource_materialization(tmp_path, monkeypatch, request)
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
                status = _exec_start_pre(core.UNIT.read_bytes(), expect_success=True)
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

    with _bounded_cohort_exception_sites() as importer_outcomes:
        result = core.update_owned_core_adapter()

    updated = json.loads(core.JOURNAL.read_text())
    assert "updated to the verified adapter generation" in result
    assert updated["adapter_source"] == str(core.ADAPTER_SOURCE)
    assert updated["state"] == "installed"
    assert updated["adapter_generation"] == "a" * 64
    assert updated["plugin_selection_sha256"] == prior["plugin_selection_sha256"]
    assert core.LAUNCHER.read_bytes() != prior_launcher
    assert core.UNIT.read_bytes() == prior_unit
    assert core.TOKEN.read_bytes() == token
    assert memory.read_text() == "existing owner memory"
    backup = core.ADAPTER_UPDATE_BACKUPS / prior["adapter_generation"]
    assert (backup / "launcher").read_bytes() == prior_launcher
    assert json.loads((backup / "journal.json").read_bytes()) == prior
    backup_manifest = json.loads((backup / "manifest.json").read_bytes())
    assert {"native-plugin-plugin.yaml", "native-plugin-__init__.py"} <= set(backup_manifest)
    assert (backup / "native-plugin-plugin.yaml").read_bytes() == b"manifest-v1\n"
    assert (backup / "native-plugin-__init__.py").read_bytes() == b"old native tools\n"
    assert selection["value"] == prior["plugin_selection_sha256"]
    assert reload_service_states == [False]
    assert automatic_restarts == []
    assert guard_denials == []
    assert len(importer_outcomes) == 1
    importer = importer_outcomes[0]
    assert importer["returncode"] == 0
    assert importer["stderr_bytes"] <= core._HELPER_IMPORT_STDERR_LIMIT
    receipt = importer["stdout"]
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
def test_native_adapter_update_restart_failure_restores_exact_prior_generation(tmp_path, monkeypatch, request):
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
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    token = core.TOKEN.read_bytes()
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    attempts = {"wait": 0}
    def fail_first_restart():
        attempts["wait"] += 1
        if attempts["wait"] == 1:
            raise core.CoreRuntimeError("injected adapter update restart failure")
    monkeypatch.setattr(core, "_wait_for_listener", fail_first_restart)

    with pytest.raises(core.CoreRuntimeError, match="injected adapter update restart failure"):
        core.update_owned_core_adapter()

    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert core.TOKEN.read_bytes() == token
    assert enabled["value"]
    assert attempts["wait"] == 2
    ordered = [call[0] for call in _calls]
    assert ordered.index(("native-plugin", "install")) < ordered.index(
        ("native-plugin", "restore")) < ordered.index(("systemctl", "start", core.SERVICE))


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update needs the real root actor")
def test_interrupted_adapter_update_recovers_from_journaled_generation_backup(tmp_path, monkeypatch, request):
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
    launcher = core.LAUNCHER.read_bytes()
    unit = core.UNIT.read_bytes()
    monkeypatch.setattr(core, "ADAPTER_UPDATE_BACKUPS", core.JOURNAL.parent / "adapter-update-backups")
    replace_journal = core._replace_journal
    interrupted = {"done": False}
    def interrupt_before_new_journal(record):
        if (record.get("adapter_source")==str(core.ADAPTER_SOURCE)
                and record.get("adapter_update_state")=="preparing"
                and not interrupted["done"]):
            interrupted["done"] = True
            raise KeyboardInterrupt()
        return replace_journal(record)
    monkeypatch.setattr(core, "_replace_journal", interrupt_before_new_journal)

    with pytest.raises(KeyboardInterrupt):
        core.update_owned_core_adapter()
    interrupted_record = json.loads(core.JOURNAL.read_text())
    assert interrupted_record["adapter_update_state"] == "preparing"
    assert interrupted_record["adapter_source"] == str(old_source)
    assert core.LAUNCHER.read_bytes() != launcher
    assert core.UNIT.read_bytes() != unit
    assert _exec_start_pre(core.UNIT.read_bytes(), expect_success=False) != 0

    monkeypatch.setattr(core, "_replace_journal", replace_journal)
    core._recover_interrupted_adapter_update()

    assert core.JOURNAL.read_bytes() == prior
    assert core.LAUNCHER.read_bytes() == launcher
    assert core.UNIT.read_bytes() == unit
    assert enabled["value"]
    assert _exec_start_pre(core.UNIT.read_bytes()) is None  # exact prior unit is guardless


@pytest.mark.skipif(os.geteuid() != 0, reason="adapter update recovery needs the real root actor")
def test_starting_and_partial_rollback_interruption_fail_closed_in_exec_start_pre(tmp_path, monkeypatch, request):
    _calls, enabled, _old_launcher, _selection = _install_legacy_service_fixture(
        tmp_path, monkeypatch, journal_state="installed")
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
            assert _exec_start_pre(core.UNIT.read_bytes(), expect_success=True) == 0
            raise KeyboardInterrupt()
        return real_run(argv, check)
    monkeypatch.setattr(core, "_run", interrupt_after_starting_recipe)
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
    assert _exec_start_pre(core.UNIT.read_bytes(), expect_success=False) != 0

    monkeypatch.setattr(core, "_atomic_replace", atomic_replace)
    monkeypatch.setattr(core, "_run", real_run)
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


def _adapter_cohort_starting_fixture(tmp_path, monkeypatch, request):
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
                          backup_generation=old_adapter)
    core.LAUNCHER.write_bytes(new_launcher)
    core.LAUNCHER.chmod(0o755)
    core.UNIT.write_bytes(new_unit)
    core.UNIT.chmod(0o644)
    new_recipe = core._adapter_recipe_sha256(
        str(new_source), new_adapter, hashlib.sha256(new_unit).hexdigest(),
        hashlib.sha256(new_launcher).hexdigest())
    old_recipe = core._adapter_recipe_sha256(
        str(old_source), old_adapter, hashlib.sha256(old_unit).hexdigest(),
        hashlib.sha256(old_launcher).hexdigest())
    token_sha = hashlib.sha256(token).hexdigest()
    backup_directory = core.ADAPTER_UPDATE_BACKUPS / old_adapter
    backup_directory.mkdir(mode=0o700)
    backup_contents = {name: ("proof:" + name + "\n").encode()
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
def test_m1_boot_gate_admits_only_the_exact_source_starting_journal_and_resources(
        tmp_path, monkeypatch, request):
    unit, cohort, journal_raw, resources_raw = _adapter_cohort_starting_fixture(
        tmp_path, monkeypatch, request)
    assert _exec_start_pre(unit, expect_success=True) == 0
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
        assert _exec_start_pre(unit, expect_success=False) != 0
    core._atomic_replace(core.ADAPTER_UPDATE_COHORT,
        core._canonical_json(cohort), 0o400, core.ROOT_UID, core.ROOT_UID)

    core.JOURNAL.write_bytes(b'{"partial":"journal"}\n')
    assert _exec_start_pre(unit, expect_success=False) != 0
    core.JOURNAL.write_bytes(journal_raw)
    core.RESOURCES_RECORD.write_bytes(b'{"partial":"resources"}\n')
    assert _exec_start_pre(unit, expect_success=False) != 0
    core.RESOURCES_RECORD.write_bytes(resources_raw)
    assert _exec_start_pre(unit, expect_success=True) == 0


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
