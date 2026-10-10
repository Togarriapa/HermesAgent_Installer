from __future__ import annotations

import hashlib
import json
import os
import fcntl
import base64
import pwd
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.build_execution import (
    BuildOutputSpec, ContentAddressedBuildStore, LinuxBuildOutputFactInspector,
    ManagedBuildResult, ProtectedBuildArtifactRootResolver, RootBuildExecutionService,
    managed_process_identity_digest, _resolve_argv_recipe,
)
from hermes_installer.authority.types import (
    AuthorityDenied, EffectAuthorization, HostContext, Sensitivity, canonical_digest,
)
from hermes_installer.managed_process_custodian import ManagedBuildJobRunner


def test_application_only_mount_ids_do_not_expand_generic_build_grammar():
    recipe = (
        {"build_path": {"mount_id": "builder", "relative_path": ""}},
        {"build_path": {"mount_id": "packages", "relative_path": ""}},
    )
    with pytest.raises(AuthorityDenied):
        _resolve_argv_recipe(recipe)
    assert _resolve_argv_recipe(recipe, additional_mount_ids=("packages",)) == recipe
    with pytest.raises(AuthorityDenied):
        _resolve_argv_recipe(recipe, additional_mount_ids=("caller-path",))


def test_application_pm_symlink_closure_requires_in_tree_target_members():
    regular = SimpleNamespace(kind="file", relative_path="lib/python3.14/os.py")
    safe_link = SimpleNamespace(kind="symlink", relative_path="lib64", link_target="lib")
    ManagedBuildJobRunner._validate_application_symlink_closure(
        {regular.relative_path: regular, safe_link.relative_path: safe_link},
        {safe_link.relative_path: safe_link})

    escaping = SimpleNamespace(kind="symlink", relative_path="lib64", link_target="../../outside")
    with pytest.raises(AuthorityDenied):
        ManagedBuildJobRunner._validate_application_symlink_closure(
            {regular.relative_path: regular, escaping.relative_path: escaping},
            {escaping.relative_path: escaping})

    missing = SimpleNamespace(kind="symlink", relative_path="lib64", link_target="missing")
    with pytest.raises(AuthorityDenied):
        ManagedBuildJobRunner._validate_application_symlink_closure(
            {regular.relative_path: regular, missing.relative_path: missing},
            {missing.relative_path: missing})


def test_application_pm_symlink_closure_rejects_cycles_and_symlink_parents():
    left = SimpleNamespace(kind="symlink", relative_path="lib/a", link_target="b")
    right = SimpleNamespace(kind="symlink", relative_path="lib/b", link_target="a")
    with pytest.raises(AuthorityDenied):
        ManagedBuildJobRunner._validate_application_symlink_closure(
            {left.relative_path: left, right.relative_path: right},
            {left.relative_path: left, right.relative_path: right})

    parent = SimpleNamespace(kind="symlink", relative_path="lib", link_target="real")
    child = SimpleNamespace(kind="symlink", relative_path="lib/alias", link_target="target")
    with pytest.raises(AuthorityDenied):
        ManagedBuildJobRunner._validate_application_symlink_closure(
            {parent.relative_path: parent, child.relative_path: child},
            {parent.relative_path: parent, child.relative_path: child})


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned held descriptor staging is required")
def test_application_held_member_staging_rehashes_and_rejects_mutated_bytes(tmp_path):
    source = tmp_path / "held.whl"
    payload = b"root-held application wheel fixture"
    source.write_bytes(payload)
    source.chmod(0o444)
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if info.st_uid != 0:
            pytest.skip("root-owned descriptor fixture is unavailable")
        member = SimpleNamespace(relative_path="wheels/example.whl", fd=fd,
            sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload), executable=False)
        destination = tmp_path / "staged"
        rows = ManagedBuildJobRunner._stage_application_held_members((member,), destination)
        assert rows[0].path == "wheels/example.whl"
        assert (destination / "wheels/example.whl").read_bytes() == payload
        assert (destination / "wheels/example.whl").stat().st_mode & 0o222 == 0

        changed = SimpleNamespace(relative_path="changed.whl", fd=fd,
            sha256="0" * 64, size_bytes=len(payload), executable=False)
        with pytest.raises(AuthorityDenied):
            ManagedBuildJobRunner._stage_application_held_members((changed,), tmp_path / "denied")

        if hasattr(os, "memfd_create") and hasattr(fcntl, "F_ADD_SEALS"):
            memfd = os.memfd_create("sealed-app-member", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(memfd, payload)
                os.fsync(memfd)
                fcntl.fcntl(memfd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
                sealed = SimpleNamespace(relative_path="sealed.whl", fd=memfd,
                    sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload), executable=False)
                sealed_rows = ManagedBuildJobRunner._stage_application_held_members(
                    (sealed,), tmp_path / "staged-sealed")
                assert sealed_rows[0].sha256 == sealed.sha256
            finally:
                os.close(memfd)
    finally:
        os.close(fd)


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0,
                    reason="root-owned O_PATH symlink receipt staging is Linux-only")
def test_application_pm_runtime_stages_only_held_in_tree_symlinks(tmp_path):
    runtime = tmp_path / "runtime"
    (runtime / "lib" / "python3.14").mkdir(parents=True)
    body = b"root-held runtime member"
    member_path = runtime / "lib" / "python3.14" / "os.py"
    member_path.write_bytes(body)
    member_path.chmod(0o444)
    link_path = runtime / "lib64"
    link_path.symlink_to("lib", target_is_directory=True)
    member_fd = os.open(member_path, os.O_RDONLY | os.O_NOFOLLOW)
    link_fd = os.open(link_path, os.O_PATH | os.O_NOFOLLOW)
    try:
        if os.fstat(member_fd).st_uid != 0 or os.fstat(link_fd).st_uid != 0:
            pytest.skip("root-owned runtime members are unavailable")
        file_member = SimpleNamespace(relative_path="lib/python3.14/os.py", fd=member_fd,
            sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body), executable=False,
            receipt_handle="runtime-file-receipt-" + "f" * 32, kind="file", link_target=None)
        link_bytes = b"lib"
        symlink_member = SimpleNamespace(relative_path="lib64", fd=link_fd,
            sha256=hashlib.sha256(link_bytes).hexdigest(), size_bytes=len(link_bytes), executable=False,
            receipt_handle="runtime-link-receipt-" + "e" * 32, kind="symlink", link_target="lib")
        destination = tmp_path / "staged-runtime"
        rows = ManagedBuildJobRunner._stage_application_held_members(
            (file_member, symlink_member), destination, allow_symlinks=True)
        assert (destination / "lib64").is_symlink()
        assert os.readlink(destination / "lib64") == "lib"
        assert (destination / "lib64" / "python3.14" / "os.py").read_bytes() == body
        assert {row.path for row in rows} == {"lib64", "lib/python3.14/os.py"}
    finally:
        os.close(member_fd)
        os.close(link_fd)


def test_application_input_fingerprint_binds_receipt_and_held_inode(tmp_path):
    first_path = tmp_path / "first"
    second_path = tmp_path / "second"
    first_path.write_bytes(b"same bytes, distinct held artifact")
    second_path.write_bytes(first_path.read_bytes())
    first_fd = os.open(first_path, os.O_RDONLY)
    duplicate_fd = os.dup(first_fd)
    second_fd = os.open(second_path, os.O_RDONLY)
    try:
        member = SimpleNamespace(relative_path="runtime/member", sha256="a" * 64,
            size_bytes=4, executable=False, receipt_handle="receipt-" + "a" * 40,
            kind="file", link_target=None)
        scalar_names = (
            "selection_handle application_id build_profile_id target_id operation_id "
            "runtime_preparation_selection_handle plan_sha256 setup_session_id transaction_handle "
            "prepared_generation_id prepared_generation_digest source_receipt_handle source_manifest_sha256 "
            "pm_runtime_closure_sha256 lock_receipt_handle lock_sha256 package_closure_receipt_handle "
            "build_backend_closure_receipt_handle recipe_sha256 builder_receipt_handle builder_sha256 "
            "builder_size_bytes driver_receipt_handle driver_sha256 driver_size_bytes recipe_config_sha256 "
            "output_root_id output_owner_uid output_owner_gid build_service_id build_service_selection_handle "
            "build_service_generation runtime_toolchain_receipt_handles controller_binding_handle "
            "controller_pid controller_start_ticks controller_uid controller_gid uv_sha256 uv_size_bytes "
            "uv_source_receipt_handle uv_artifact_id"
        ).split()

        def projection(fd):
            member.fd = fd
            values = {name: "fixed" for name in scalar_names}
            values.update(recipe_config_bytes=b"config", builder_fd=fd, uv_fd=fd, driver_fd=fd,
                output_root_fd=fd, controller_pidfd=fd, source_members=(member,),
                package_members=(), backend_members=(), python_runtime_members=(),
                recipe_member=member, python_executable_member=member)
            return SimpleNamespace(**values)

        same_artifact = ManagedBuildJobRunner._application_inputs_fingerprint(projection(duplicate_fd))
        first_artifact = ManagedBuildJobRunner._application_inputs_fingerprint(projection(first_fd))
        second_artifact = ManagedBuildJobRunner._application_inputs_fingerprint(projection(second_fd))
        assert same_artifact == first_artifact
        assert first_artifact != second_artifact
    finally:
        os.close(first_fd)
        os.close(duplicate_fd)
        os.close(second_fd)


def _test_temp_parent() -> str:
    # Darwin exposes its root-owned sticky temp directory at /private/tmp; Linux
    # uses /tmp. Never make Linux tests depend on a Darwin-only alias.
    return "/private/tmp" if sys.platform == "darwin" else "/tmp"


@pytest.mark.parametrize(("platform_name", "expected"),
                         [("darwin", "/private/tmp"), ("linux", "/tmp")])
def test_temp_parent_uses_only_the_platform_specific_sticky_root(monkeypatch, platform_name, expected):
    monkeypatch.setattr(sys, "platform", platform_name)
    assert _test_temp_parent() == expected


def _test_builder_uid() -> int:
    # Root-run Linux custody CI must still model the dedicated unprivileged
    # builder identity used by production.
    return 65534 if os.geteuid() == 0 else os.getuid()


def _owned_output_root(path: Path) -> Path:
    path.mkdir(mode=0o700, exist_ok=True)
    owner_uid = _test_builder_uid()
    owner_gid = pwd.getpwuid(owner_uid).pw_gid
    if (path.stat().st_uid, path.stat().st_gid) != (owner_uid, owner_gid):
        os.chown(path, owner_uid, owner_gid)
    path.chmod(0o700)
    return path
def constraints():
    return {
        "bin/colibri": BuildOutputSpec(
            "bin/colibri", "file", 1024 * 1024, "colibri-engine",
            {"elf_class": 64, "elf_machine": "EM_AARCH64", "required_runtime_dependencies": ["libgomp.so.1"]},
        ),
        "runtime/lib/python3.9": BuildOutputSpec(
            "runtime/lib/python3.9", "tree", 1024 * 1024, "cpython-stdlib-and-extension-closure",
            {"python_version": "3.9.25", "target": "linux-aarch64"},
        ),
    }


class Profile:
    target_id = "colibri-source-build:start"
    generation = "generation-1"
    service_generation_digest = "a" * 64
    build_service_enrollment_id = "builder-service-1"
    build_service_generation = "service-generation-1"
    source_artifact_id = "colibri-source"
    source_sha256 = "1" * 64
    toolchain_artifact_id = "aarch64-sysroot"
    toolchain_sha256 = "2" * 64
    builder_artifact_id = "fixed-builder"
    builder_sha256 = "3" * 64
    argv_recipe = (
        {"build_path": {"mount_id": "builder", "relative_path": ""}},
        {"literal": "build"}, {"literal": "--fixed"},
    )
    environment = {"LANG": "C"}
    max_lifetime_seconds = 600
    output_root_id = "build-output"
    output_owner_uid = _test_builder_uid()
    output_owner_gid = pwd.getpwuid(output_owner_uid).pw_gid
    output_specs = constraints()

    def __init__(self, output_root: Path):
        self.output_root = output_root


class FixtureInspector:
    def __init__(self, *, corrupt=False):
        self.corrupt = corrupt

    def inspect(self, profile, spec, path):
        if self.corrupt:
            return {"elf_class": 32}
        if spec.relative_path == "bin/colibri":
            return {"elf_class": 64, "elf_machine": "EM_AARCH64",
                    "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                    "resolved_dependency_closure": [{"name": "libgomp.so.1", "sha256": "f" * 64}]}
        return {"python_version": "3.9.25", "target": "linux-aarch64",
                "native_extension_manifest": []}


def completed(**changes):
    now = time.monotonic()
    row = {
        "process_id": "managed-build-1", "generation": "generation-1", "uid": _test_builder_uid(),
        "pid": 12345, "start_ticks": 55, "exit_code": 0, "timed_out": False,
        "cancelled": False, "cleanup_verified": True, "started_monotonic": now - .25,
        "finished_monotonic": now - .05,
        "kernel_limits": {"PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
                          "NoNewPrivileges": "yes", "ProtectSystem": "strict"},
        "terminal_success_record_id": "terminal:success:1", "process_identity_digest": "",
        "cgroup_id": "cgroup:fixture", "mount_namespace_inode": 101,
        "network_namespace_inode": 102, "bounded_log_digest": "c" * 64, "log_bytes": 16,
    }
    row.update(changes)
    if "process_identity_digest" not in changes:
        row["process_identity_digest"] = managed_process_identity_digest(
            process_id=row["process_id"], generation=row["generation"], uid=row["uid"], pid=row["pid"],
            start_ticks=row["start_ticks"], cgroup_id=row["cgroup_id"],
            mount_namespace_inode=row["mount_namespace_inode"],
            network_namespace_inode=row["network_namespace_inode"])
    return ManagedBuildResult(**row)


def write_file(root: Path, name: str, data: bytes, executable=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent
    while parent != root:
        if parent.stat().st_uid != _test_builder_uid():
            os.chown(parent, _test_builder_uid(), -1)
        parent = parent.parent
    path.write_bytes(data)
    path.chmod(0o700 if executable else 0o600)
    if path.stat().st_uid != _test_builder_uid():
        os.chown(path, _test_builder_uid(), -1)
    return path


def make_store(path: Path):
    return ContentAddressedBuildStore(path, signing_key=b"k" * 32, owner_uid=os.getuid())


def test_fixed_build_handler_materializes_root_pins_runs_terminal_job_and_returns_receipt():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        output_root = base / "outputs"
        _owned_output_root(output_root)
        source = base / "source"
        toolchain = base / "toolchain"
        builder = base / "builder"
        source.mkdir(mode=0o700)
        toolchain.mkdir(mode=0o700)
        builder.write_bytes(b"root-pinned builder")
        builder.chmod(0o700)
        profile = Profile(output_root)
        specs = {
            "colibri-source": SimpleNamespace(sha256=profile.source_sha256, tree_files=False),
            "aarch64-sysroot": SimpleNamespace(sha256=profile.toolchain_sha256, tree_files=False),
            "fixed-builder": SimpleNamespace(sha256=profile.builder_sha256, tree_files=False),
        }
        artifact_paths = {"colibri-source": source, "aarch64-sysroot": toolchain,
                          "fixed-builder": builder}

        class Artifacts:
            artifacts = specs

            def resolve(self, artifact_id, _digest, _staging, *, expected_uid):
                assert expected_uid == os.getuid()
                path = artifact_paths[artifact_id]
                manifest = hashlib.sha256(b"[]").hexdigest()
                return SimpleNamespace(artifact_id=artifact_id, sha256=specs[artifact_id].sha256,
                                       path=path, tree_files=(), tree_manifest_sha256=manifest)

        class Catalog:
            def resolve_service(self, target_id, generation, services):
                assert target_id == profile.target_id and generation == profile.generation
                assert services is service_catalog
                return profile, SimpleNamespace(
                    enrollment_id=profile.build_service_enrollment_id,
                    generation=profile.build_service_generation,
                    service_uid=profile.output_owner_uid, service_gid=profile.output_owner_gid)

        class Launcher:
            seen = False

            def run_selected_build(self, inputs, *, context, authorization, peer_pid,
                                   peer_pidfd, timeout, cancelled):
                self.seen = True
                assert inputs.source_root == source and inputs.toolchain_root == toolchain
                assert inputs.builder_executable == builder and timeout > 0
                assert inputs.enrollment_id == "enrollment-1"
                assert inputs.operation_id == "colibri-source-build-v1"
                assert inputs.selection_digest == authorization.request_digest
                assert inputs.argv_recipe[0] == {"build_path": {"mount_id": "builder", "relative_path": ""}}
                assert peer_pid == 42 and peer_pidfd == 7 and context.enrollment_id == "enrollment-1"
                assert not cancelled()
                filled_output(inputs.output_root)
                return completed()

        payload = json.dumps({"schema": 1, "enrollment_id": "enrollment-1",
                              "generation": profile.generation,
                              "operation_id": "colibri-source-build-v1", "parameters": {}},
                             sort_keys=True, separators=(",", ":")).encode("ascii")
        now = time.monotonic()
        context = HostContext(
            principal_id="principal-1", profile_id="profile-1", namespace_id="namespace-1",
            uid=os.getuid(), purpose="build", intent_id="intent-1", trace_id="trace-1",
            sensitivity=Sensitivity.PRIVATE, lineage_hash="a" * 64, policy_revision="policy-1",
            capabilities=frozenset({"build"}), issued_at_monotonic=now,
            monotonic_expires_at=now + 300, nonce="nonce-1", grant_id="grant-1", signature="sig",
            enrollment_id="enrollment-1", generation=profile.generation, operation="process.start")
        authorization = EffectAuthorization(
            principal_id="principal-1", profile_id="profile-1", namespace_id="namespace-1",
            uid=os.getuid(), purpose="build", sensitivity=Sensitivity.PRIVATE, trace_id="trace-1",
            policy_revision="policy-1", lineage_hash="a" * 64, capability="build",
            intent_id="intent-1", target=profile.target_id, recipient=None,
            request_digest=canonical_digest(payload), retry_index=0,
            issued_at_monotonic=now, monotonic_expires_at=now + 300, grant_id="grant-1",
            nonce="nonce-1", context_digest="b" * 64, signature="sig",
            enrollment_id="enrollment-1", generation=profile.generation, operation="process.start")
        launcher = Launcher()
        service_catalog = object()
        service = RootBuildExecutionService(
            build_catalog=Catalog(), artifact_catalog=Artifacts(), artifact_staging_root=base,
            launcher=launcher, fact_inspector=FixtureInspector(), authority_key=b"k" * 32,
            service_catalog=service_catalog,
            store=make_store(base / "cas"), expected_uid=os.getuid())
        assert set(service.handlers()) == {("process.start", profile.target_id)}
        response = service(context=context, authorization=authorization, payload=payload,
                           timeout=60, peer_pid=42, peer_pidfd=7, cancelled=lambda: False)

        assert launcher.seen is True
        assert response["status"] == 200 and response["receipt_id"]
        receipt = json.loads(base64.b64decode(response["body"], validate=True))
        assert receipt["operation_id"] == "colibri-source-build-v1"
        assert receipt["service_generation_digest"] == profile.service_generation_digest
        assert {output["relative_path"] for output in receipt["output_records"]} == set(profile.output_specs)
        assert list(output_root.iterdir()) == []


def test_fixed_build_handler_fact_failure_cleans_unique_output_without_activating_receipt():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        output_root = base / "outputs"
        _owned_output_root(output_root)
        profile = Profile(output_root)
        source, toolchain = base / "source", base / "toolchain"
        source.mkdir(mode=0o700)
        toolchain.mkdir(mode=0o700)
        builder = base / "builder"
        builder.write_bytes(b"root-pinned builder")
        builder.chmod(0o700)
        artifact_specs = {
            "colibri-source": SimpleNamespace(sha256=profile.source_sha256, tree_files=False),
            "aarch64-sysroot": SimpleNamespace(sha256=profile.toolchain_sha256, tree_files=False),
            "fixed-builder": SimpleNamespace(sha256=profile.builder_sha256, tree_files=False),
        }
        paths = {"colibri-source": source, "aarch64-sysroot": toolchain, "fixed-builder": builder}

        class Artifacts:
            artifacts = artifact_specs

            def resolve(self, artifact_id, _digest, _staging, *, expected_uid):
                return SimpleNamespace(artifact_id=artifact_id, sha256=artifact_specs[artifact_id].sha256,
                                       path=paths[artifact_id], tree_files=(),
                                       tree_manifest_sha256=hashlib.sha256(b"[]").hexdigest())

        class Catalog:
            def resolve_service(self, _target_id, _generation, _services):
                return profile, SimpleNamespace(
                    enrollment_id=profile.build_service_enrollment_id,
                    generation=profile.build_service_generation,
                    service_uid=profile.output_owner_uid, service_gid=os.getgid())

        class Launcher:
            def run_selected_build(self, inputs, **_kwargs):
                filled_output(inputs.output_root)
                return completed()

        payload = json.dumps({"schema": 1, "enrollment_id": "enrollment-1",
                              "generation": profile.generation,
                              "operation_id": "colibri-source-build-v1", "parameters": {}},
                             sort_keys=True, separators=(",", ":")).encode("ascii")
        now = time.monotonic()
        context = HostContext(
            principal_id="principal-1", profile_id="profile-1", namespace_id="namespace-1",
            uid=os.getuid(), purpose="build", intent_id="intent-1", trace_id="trace-1",
            sensitivity=Sensitivity.PRIVATE, lineage_hash="a" * 64, policy_revision="policy-1",
            capabilities=frozenset({"build"}), issued_at_monotonic=now,
            monotonic_expires_at=now + 300, nonce="nonce-1", grant_id="grant-1", signature="sig",
            enrollment_id="enrollment-1", generation=profile.generation, operation="process.start")
        authorization = EffectAuthorization(
            principal_id="principal-1", profile_id="profile-1", namespace_id="namespace-1",
            uid=os.getuid(), purpose="build", sensitivity=Sensitivity.PRIVATE, trace_id="trace-1",
            policy_revision="policy-1", lineage_hash="a" * 64, capability="build",
            intent_id="intent-1", target=profile.target_id, recipient=None,
            request_digest=canonical_digest(payload), retry_index=0,
            issued_at_monotonic=now, monotonic_expires_at=now + 300, grant_id="grant-1",
            nonce="nonce-1", context_digest="b" * 64, signature="sig",
            enrollment_id="enrollment-1", generation=profile.generation, operation="process.start")
        store = make_store(base / "cas")
        service_catalog = object()
        service = RootBuildExecutionService(
            build_catalog=Catalog(), artifact_catalog=Artifacts(), artifact_staging_root=base,
            launcher=Launcher(), fact_inspector=FixtureInspector(corrupt=True),
            authority_key=b"k" * 32, service_catalog=service_catalog,
            store=store, expected_uid=os.getuid())

        with pytest.raises(AuthorityDenied):
            service(context=context, authorization=authorization, payload=payload,
                    timeout=60, peer_pid=42, peer_pidfd=7, cancelled=lambda: False)

        assert list(output_root.iterdir()) == []
        assert not (store.root / "current").exists()


def test_output_cleanup_rejects_replaced_job_root_instead_of_succeeding():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        target = base / "target"
        target.mkdir(mode=0o700)
        replaced = base / "job-output"
        replaced.symlink_to(target, target_is_directory=True)

        with pytest.raises(AuthorityDenied):
            RootBuildExecutionService._remove_job_output_root(replaced, os.getuid())

        assert target.is_dir()
        assert replaced.is_symlink()


def test_inspector_roots_are_resolved_from_exact_protected_artifact_pins():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        source = base / "source"
        sysroot = base / "sysroot"
        source.mkdir(mode=0o700)
        sysroot.mkdir(mode=0o700)
        source.chmod(0o500)
        sysroot.chmod(0o500)
        profile = Profile(base)
        expected_uid = os.getuid()
        specs = {
            profile.source_artifact_id: SimpleNamespace(sha256=profile.source_sha256, tree_files=(object(),)),
            profile.toolchain_artifact_id: SimpleNamespace(sha256=profile.toolchain_sha256, tree_files=(object(),)),
        }
        roots = {profile.source_artifact_id: source, profile.toolchain_artifact_id: sysroot}

        class ArtifactCatalog:
            artifacts = specs

            def resolve(self, *_args, **_kwargs):
                raise AssertionError("tree artifacts must be materialized through their protected manifest")

            def materialize_tree(self, artifact_id, digest, staging_root, *, expected_uid):
                assert artifact_id in roots and specs[artifact_id].sha256 == digest
                assert staging_root == base and expected_uid == expected_uid_outer
                return SimpleNamespace(path=roots[artifact_id])

        expected_uid_outer = expected_uid
        resolver = ProtectedBuildArtifactRootResolver(ArtifactCatalog(), base, owner_uid=expected_uid)
        assert resolver.source_root(profile) == source
        assert resolver.toolchain_root(profile) == sysroot


def filled_output(root):
    _owned_output_root(root)
    write_file(root, "bin/colibri", b"fixture ARM64 executable", executable=True)
    write_file(root, "runtime/lib/python3.9/os.py", b"stdlib fixture")
    write_file(root, "runtime/lib/python3.9/lib-dynload/_test.so", b"extension fixture")


def test_dynamic_output_manifest_is_root_hashed_and_atomically_resolved():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        output_root = base / "outputs"
        output_root.mkdir(mode=0o700)
        filled_output(output_root)
        profile = Profile(output_root)
        store = make_store(base / "cas")
        receipt = store.publish(profile, enrollment_id="enrollment-1",
                                operation_id="colibri-source-build-v1", process=completed(),
                                fact_inspector=FixtureInspector())

        assert receipt.service_generation_digest == profile.service_generation_digest
        assert receipt.receipt_digest == hashlib.sha256(json.dumps(
            receipt.unsigned_wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")).hexdigest()
        assert {item.relative_path for item in receipt.outputs} == set(profile.output_specs)
        assert all(item.sha256 for item in receipt.outputs)
        tree = next(item for item in receipt.outputs if item.kind == "tree")
        assert tree.tree_file_manifest_sha256 == tree.sha256
        assert (store.resolve_output(profile, "bin/colibri")).read_bytes() == b"fixture ARM64 executable"
        assert (store.resolve_output(profile, "runtime/lib/python3.9") / "os.py").read_bytes() == b"stdlib fixture"
        assert store.resolve(profile).receipt_id == receipt.receipt_id


def test_root_fact_mismatch_or_inspector_error_never_publishes_receipt():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        profile = Profile(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector(corrupt=True))
        assert not (store.root / "attestations").exists()


@pytest.mark.parametrize("changes", [
    {"exit_code": 1}, {"exit_code": None}, {"timed_out": True}, {"cancelled": True},
    {"cleanup_verified": False}, {"terminal_success_record_id": ""},
    {"process_identity_digest": "bad"}, {"mount_namespace_inode": 0},
    {"kernel_limits": {"PrivateNetwork": "no"}},
])
def test_no_receipt_for_nonterminal_or_unproven_process(changes):
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(Profile(root), enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(**changes), fact_inspector=FixtureInspector())
        assert not (store.root / "attestations").exists()


@pytest.mark.parametrize("mutation", ["missing", "extra", "symlink", "oversize"])
def test_output_scanner_rejects_incomplete_or_unbounded_tree(mutation):
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        if mutation == "missing":
            (root / "bin/colibri").unlink()
        elif mutation == "extra":
            write_file(root, "unreviewed", b"extra")
        elif mutation == "symlink":
            (root / "runtime/lib/python3.9/link").symlink_to(root / "bin/colibri")
        else:
            write_file(root, "bin/colibri", b"x" * (1024 * 1024 + 1), executable=True)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(Profile(root), enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector())
        assert not (store.root / "attestations").exists()


def test_cancellation_and_tampered_receipt_or_cas_object_fail_closed():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        base = Path(temp)
        root = base / "outputs"
        filled_output(root)
        profile = Profile(root)
        store = make_store(base / "cas")
        with pytest.raises(AuthorityDenied):
            store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                          process=completed(), fact_inspector=FixtureInspector(), cancelled=lambda: True)
        assert not store.root.exists()
        receipt = store.publish(profile, enrollment_id="e", operation_id="colibri-source-build-v1",
                                process=completed(), fact_inspector=FixtureInspector())
        path = store.resolve_output(profile, "bin/colibri")
        path.chmod(0o755)
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)
        path.chmod(0o555)
        record_path = store.root / "attestations" / f"{receipt.receipt_id}.json"
        record_path.chmod(0o600)
        raw = json.loads(record_path.read_text())
        raw["service_generation_digest"] = "d" * 64
        record_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")))
        with pytest.raises(AuthorityDenied):
            store.resolve(profile)


def elf64_aarch64(needed=()):
    data = bytearray(512)
    data[:4] = b"\x7fELF"
    data[4:7] = b"\x02\x01\x01"
    data[7] = 0
    data[16:18] = (2).to_bytes(2, "little")
    data[18:20] = (183).to_bytes(2, "little")
    data[32:40] = (64).to_bytes(8, "little")
    data[52:54] = (64).to_bytes(2, "little")
    data[54:56] = (56).to_bytes(2, "little")
    if needed:
        data[56:58] = (2).to_bytes(2, "little")
        strings = b"\0" + b"\0".join(name.encode() for name in needed) + b"\0"
        load = 64
        data[load:load+4] = (1).to_bytes(4, "little")
        data[load+8:load+16] = (0).to_bytes(8, "little")
        data[load+16:load+24] = (0).to_bytes(8, "little")
        data[load+32:load+40] = len(data).to_bytes(8, "little")
        data[load+40:load+48] = len(data).to_bytes(8, "little")
        dynamic_header = 120
        data[dynamic_header:dynamic_header+4] = (2).to_bytes(4, "little")
        data[dynamic_header+8:dynamic_header+16] = (200).to_bytes(8, "little")
        data[dynamic_header+16:dynamic_header+24] = (200).to_bytes(8, "little")
        data[dynamic_header+32:dynamic_header+40] = (96).to_bytes(8, "little")
        data[dynamic_header+40:dynamic_header+48] = (96).to_bytes(8, "little")
        rows = [(5, 300), (10, len(strings))]
        rows.extend((1, offset) for offset in [] )
        cursor = 1
        for name in needed:
            rows.append((1, cursor))
            cursor += len(name) + 1
        rows.append((0, 0))
        for index, (tag, value) in enumerate(rows):
            offset = 200 + index * 16
            data[offset:offset+8] = tag.to_bytes(8, "little", signed=True)
            data[offset+8:offset+16] = value.to_bytes(8, "little")
        data[300:300+len(strings)] = strings
    return bytes(data)


def test_linux_fact_inspector_parses_aarch64_elf_dependencies_and_rejects_x86():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        root = Path(temp)
        path = root / "colibri"
        path.write_bytes(elf64_aarch64(("libgomp.so.1", "libm.so.6", "libc.so.6")))
        path.chmod(0o444)
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=lambda _profile: root,
            source_root_resolver=lambda _profile: root,
            runtime_probe=SimpleNamespace(inspect_cpython39=lambda _profile, _path: {}),
            owner_uid=os.getuid())
        facts, dependencies = inspector._elf(path)
        assert facts == {"elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux"}
        assert dependencies == ("libgomp.so.1", "libm.so.6", "libc.so.6")

        wrong = bytearray(elf64_aarch64())
        wrong[18:20] = (62).to_bytes(2, "little")
        path.chmod(0o600)
        path.write_bytes(wrong)
        with pytest.raises(AuthorityDenied):
            inspector._elf(path)


def test_linux_fact_inspector_hashes_actual_root_owned_dependency_closure():
    with tempfile.TemporaryDirectory(dir=_test_temp_parent()) as temp:
        root = Path(temp)
        expected = {}
        for name in ("libgomp.so.1", "libm.so.6", "libc.so.6"):
            content = elf64_aarch64()
            path = root / name
            path.write_bytes(content)
            path.chmod(0o444)
            expected[name] = hashlib.sha256(content).hexdigest()
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=lambda _profile: root,
            source_root_resolver=lambda _profile: root,
            runtime_probe=SimpleNamespace(inspect_cpython39=lambda _profile, _path: {}),
            owner_uid=os.getuid())
        closure = inspector._dependency_closure(root, tuple(expected))
        assert {row["name"]: row["sha256"] for row in closure} == expected
        assert all(row["owner_uid"] == os.getuid() and Path(row["absolute_path"]).is_absolute() for row in closure)
