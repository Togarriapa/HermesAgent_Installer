"""Default-deny checks for the actual root TTY consent producer."""
from pathlib import Path
import hashlib
import os
import pty
import pwd
import select
import sys
import time
from types import MappingProxyType

import pytest

from hermes_installer.authority.root_consent_choices import RootTTYConsentChoiceRegistry
from hermes_installer.authority.enrollment import ProtectedEnrollment
from hermes_installer.authority.provider_runtime_composition import ProviderRuntimeSelection
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.root_memory_capture_consent import RootMemoryCaptureConsentRegistry
from hermes_installer.authority.root_private_input_consent import RootPrivateInputConsentRegistry
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.memory.compound import MemoryRouteRecipe
from hermes_installer.memory.enrollment import MemoryServiceEnrollment, SOURCE_PINS
from hermes_installer.protected_enrollment import (
    HostServiceProfile, OwnedRoots, ProtectedEnrollmentCatalog,
)
from hermes_installer.provider_effect_handlers import ProviderEnrollment
from hermes_installer.codex_responses import CODEX_RECIPIENT, CODEX_TARGET


def _service():
    binding = PrincipalBinding(12001, "fixture-owner", "fixture-profile", "fixture-namespace",
                               frozenset({"provider-dispatch"}))
    digest = "a" * 64
    service = AuthorityService(signing_key=b"r" * 32, key_id="fixture-key",
                               bindings_by_uid={binding.uid: binding}, rules={}, handlers={},
                               profile_generations={binding.profile_id: "fixture-generation"},
                               service_generation_digest=digest)
    enrollment = ProtectedEnrollment(
        key_id="fixture-key", bindings_by_uid={binding.uid: binding}, rules={}, policy=None,
        process_profiles={}, provider_enrollments={}, mcp_services={}, mcp_http_bindings={},
        delegations={}, memory_providers={}, native_bridges={}, artifact_catalog={}, package_catalog={},
        artifact_catalog_path=Path("/unused"), artifact_staging_directory=Path("/unused"),
        service_records=[], protected_devices=[], protected_build_records=[],
        protected_enrollment_digest=digest, native_package_records=[], memory_enrollments={},
        operation_parameter_schemas=[], source_issuers=(), resource_job_records=(),
        remote_session_records=(), resource_backend_enrollment_records=(), resource_body_recipe_records=(),
    )
    providers = ProviderRuntimeSelection(
        provider_enrollments_by_id=MappingProxyType({}), bridges_by_id=MappingProxyType({}),
        root_selected_enrollments_by_bridge=MappingProxyType({}),
        normalization_policies_by_route=MappingProxyType({}),
        provider_result_observer_ids=MappingProxyType({}), provider_tool_call_parser=lambda *_: (),
    )
    return service, enrollment, providers


def test_uncommitted_profile_cannot_reach_tty_or_persist_a_consent_choice(tmp_path: Path):
    service, enrollment, providers = _service()
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    journal.chmod(0o700)
    choices = RootTTYConsentChoiceRegistry(service, providers, enrollment, journal)

    with pytest.raises(AuthorityDenied, match="no active private profile"):
        choices.observe_current_profile_selection_from_tty()

    assert not (journal / "root-tty-consent-choices" / "registry.json").exists()
    assert choices.is_current_private_provider_choice(object()) is False
    assert choices.is_current_memory_capture_choice(object()) is False


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.geteuid() != 0,
                    reason="actual controlling-TTY issuance requires an isolated Linux root fixture")
def test_root_tty_private_and_memory_choices_are_distinct_and_current(tmp_path: Path):
    account = pwd.getpwnam("nobody")
    principal = PrincipalBinding(account.pw_uid, "fixture-owner", "fixture-profile",
                                 "fixture-namespace", frozenset({"provider-dispatch"}))
    digest = "b" * 64
    roots_base = Path("/root") / f"consent-fixture-{os.getpid()}"
    roots_base.mkdir(mode=0o700)
    owned_roots = []
    for name in ("home", "work", "data"):
        path = roots_base / name
        path.mkdir(mode=0o700)
        os.chown(path, account.pw_uid, account.pw_gid)
        owned_roots.append(path)
    roots = OwnedRoots("home-fixture", "work-fixture", "data-fixture",
                       *owned_roots, account.pw_uid, account.pw_gid)
    executable = Path("/usr/bin/sleep")
    profile = HostServiceProfile(
        enrollment_id="fixture-enrollment", generation="fixture-generation",
        profile_id=principal.profile_id, principal_id=principal.principal_id,
        service_uid=account.pw_uid, service_gid=account.pw_gid, service_user=account.pw_name,
        device_enrollment_id=None, expected_device_generation=None, executable=executable,
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        runtime_artifact_ids=(), package_runtime_records={}, roots=roots,
        authority_endpoint_id="fixture-authority", namespace_identity=principal.namespace_id,
        socket_policy_id="fixture-socket", target_route_ids=(), operation_targets={},
        operation_recipes={}, argv_recipe=(), environment={}, max_lifetime_seconds=60,
        memory_max_bytes=1024, cpu_quota_percent=100, io_weight=100,
    )
    catalog = ProtectedEnrollmentCatalog(
        {("fixture-enrollment", "fixture-generation"): profile}, digest=digest,
    )
    raw_provider = {
        "provider": "codex", "account_id": "fixture-account", "principal_id": principal.principal_id,
        "target": CODEX_TARGET, "recipient": CODEX_RECIPIENT,
        "credential_ref": "fixture-credential", "credential_scope": "fixture-scope",
        "models": ["fixture-model"], "allowed_sensitivities": ["private"],
        "additional_metered_fee_usd": 0.0,
    }
    provider = ProviderEnrollment(
        provider=raw_provider["provider"], account_id=raw_provider["account_id"],
        principal_id=raw_provider["principal_id"], target=raw_provider["target"],
        recipient=raw_provider["recipient"], credential_ref=raw_provider["credential_ref"],
        credential_scope=raw_provider["credential_scope"], models=frozenset(raw_provider["models"]),
        allowed_sensitivities=frozenset(raw_provider["allowed_sensitivities"]),
    )
    memory_route = MemoryRouteRecipe(
        "agentmemory-capture", "default", (), "fixture-request", "fixture-result",
        MappingProxyType({}), "fixture-auth", 10, 4096,
    )
    memory = MemoryServiceEnrollment(
        target_id=f"memory-agentmemory:{principal.profile_id}", provider="agentmemory",
        backend_variant="default", profile_id=principal.profile_id, principal_id=principal.principal_id,
        service_enrollment_id="fixture-memory-enrollment", source_revision=SOURCE_PINS["agentmemory"],
        service_generation="fixture-generation", namespace_identity=principal.namespace_id,
        literal_loopback_port=3111, fixed_route_map=MappingProxyType({"agentmemory-capture": memory_route}),
        data_root_id="data-fixture", auth_reference_id="fixture-memory-auth",
        fixed_project_account_user_scope=MappingProxyType({}), authority_state_root_id="state-fixture",
        memory_owner_generation=1, private_extraction_embedding_routes=MappingProxyType({}),
        background_consent_revision="memory-consent-v1", limits=MappingProxyType({}),
    )
    enrollment = ProtectedEnrollment(
        key_id="fixture-key", bindings_by_uid={principal.uid: principal}, rules={}, policy=None,
        process_profiles={}, provider_enrollments={"fixture-private-route": raw_provider},
        mcp_services={}, mcp_http_bindings={}, delegations={}, memory_providers={}, native_bridges={},
        artifact_catalog={}, package_catalog={}, artifact_catalog_path=Path("/unused"),
        artifact_staging_directory=Path("/unused"), service_records=[], protected_devices=[],
        protected_build_records=[], protected_enrollment_digest=digest, native_package_records=[],
        memory_enrollments={(memory.service_enrollment_id, memory.service_generation): memory},
        operation_parameter_schemas=[], source_issuers=(), resource_job_records=(),
        remote_session_records=(), resource_backend_enrollment_records=(), resource_body_recipe_records=(),
    )
    providers = ProviderRuntimeSelection(
        provider_enrollments_by_id=MappingProxyType({"fixture-private-route": provider}),
        bridges_by_id=MappingProxyType({}), root_selected_enrollments_by_bridge=MappingProxyType({}),
        normalization_policies_by_route=MappingProxyType({}),
        provider_result_observer_ids=MappingProxyType({}), provider_tool_call_parser=lambda *_: (),
    )
    service = AuthorityService(signing_key=b"r" * 32, key_id="fixture-key",
                               bindings_by_uid={principal.uid: principal}, rules={}, handlers={},
                               profile_generations={principal.profile_id: "fixture-generation"},
                               service_generation_digest=digest)
    runtime_bindings = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None, process_manager=None,
        effect_handlers={}, native_bridges={}, artifact_catalog={}, build_store=None,
        service_connector=object(), protected_principal_bindings=(principal,),
    )
    service.attach_root_runtime_bindings(runtime_bindings)
    journal = tmp_path / "root-journal"
    journal.mkdir(mode=0o700)
    journal.chmod(0o700)
    choices = RootTTYConsentChoiceRegistry(service, providers, enrollment, journal)
    private_registry = RootPrivateInputConsentRegistry(service, choices, providers, journal)
    memory_registry = RootMemoryCaptureConsentRegistry(service, choices, choices, journal)

    pid, master = pty.fork()
    if pid == 0:
        try:
            profile_handle = choices.observe_current_profile_selection_from_tty()
            assert profile_handle
            private_choice_handle = choices.observe_selected_private_provider_routes(profile_handle)
            assert private_choice_handle
            private_consent_handle = private_registry.issue_selected_private_input_consent(
                private_choice_handle, principal,
            )
            assert private_registry.selection_handle_for_current_profile(principal) == private_consent_handle
            assert not (journal / "memory-capture-consent" / "registry.json").exists()
            memory_choice_handle = choices.observe_selected_memory_capture(profile_handle)
            assert memory_choice_handle
            memory_consent_handle = memory_registry.issue_selected_capture_consent(memory_choice_handle, memory)
            current_memory_choice = choices.resolve_memory_capture_choice(memory_choice_handle, profile_handle)
            assert choices.is_current_memory_capture_choice(current_memory_choice)
            assert choices.resolve_current_memory_enrollment(memory.service_enrollment_id) is memory
            # A later explicit TTY choice replaces the prior private-route
            # choice. The old persistent consent must stop resolving even
            # though its signed profile row remains on disk.
            replacement_choice_handle = choices.observe_selected_private_provider_routes(profile_handle)
            assert replacement_choice_handle and replacement_choice_handle != private_choice_handle
            replacement_choice = choices.resolve_private_provider_routes_choice(
                replacement_choice_handle, profile_handle,
            )
            assert choices.is_current_private_provider_choice(replacement_choice)
            try:
                choices.resolve_private_provider_routes_choice(private_choice_handle, profile_handle)
            except AuthorityDenied:
                pass
            else:
                raise AssertionError("replaced TTY route choice remained resolvable")
            try:
                private_registry.selection_handle_for_current_profile(principal)
            except AuthorityDenied:
                pass
            else:
                raise AssertionError("replaced root TTY choice left the old consent current")
            os.write(1, b"RESULT:private-and-memory-current\n")
            os._exit(0)
        except BaseException as exc:
            os.write(1, f"FAIL:{type(exc).__name__}:{exc}\n".encode())
            os._exit(1)
    os.write(master, b"1\n1\n1\n1\n1\n")
    output = bytearray()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        child, status = os.waitpid(pid, os.WNOHANG)
        if child:
            break
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        pytest.fail("root TTY consent fixture timed out")
    os.close(master)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        pytest.fail(output.decode(errors="replace"))
    assert b"RESULT:private-and-memory-current" in output
    assert (journal / "private-input-consent" / "registry.json").exists()
    assert (journal / "memory-capture-consent" / "registry.json").exists()
