from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest
import urllib.request

from hermes_installer.authority.application_workload_execution import (
    RootApplicationExecutionJournal,
    RootApplicationQualificationContext,
    RootApplicationQualificationRequest,
    RootOwnedApplicationFixtureServer,
    RootApplicationWorkloadAuthority,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.protected_enrollment import RootJournalSelection


class _Invocations:
    def is_selected_application_invocation_current(self, invocation):
        return True


class _Service:
    service_generation_digest = "a" * 64

    @staticmethod
    def monotonic():
        return 1.0


class _CatalogWithoutWorkloadJoin:
    """An active app row alone cannot authorize a caller-selected workload."""


def test_admission_denies_without_protected_action_to_workload_mapping():
    arguments = json.dumps({}, sort_keys=True, separators=(",", ":")).encode()
    invocation = SimpleNamespace(
        request_sha256=hashlib.sha256(arguments).hexdigest(),
        service_generation_digest="a" * 64,
        expires_monotonic=20.0,
        profile_id="profile-1",
        profile_generation="generation-1",
    )
    authority = RootApplicationWorkloadAuthority.__new__(RootApplicationWorkloadAuthority)
    authority.catalog = _CatalogWithoutWorkloadJoin()
    authority.invocations = _Invocations()
    authority.service = _Service()

    with pytest.raises(AuthorityDenied, match="action-to-workload"):
        authority.admit_selected_workload(invocation, arguments)


def test_owned_fixture_receipt_requires_live_loopback_listener():
    binding = SimpleNamespace(expires_monotonic=30.0)

    class Controllers:
        def resolve_binding(self, handle):
            return binding if handle == "c" * 32 else None

        @staticmethod
        def verify_binding(value):
            return value is binding

    server = RootOwnedApplicationFixtureServer(controllers=Controllers(), monotonic=lambda: 1.0,
        service_generation_digest="a" * 64)
    receipt = server.start(setup_session_id="setup-session", controller_binding_handle="c" * 32)
    try:
        assert receipt.url.startswith("http://127.0.0.1:")
        assert server.resolve(receipt.handle, setup_session_id="setup-session",
            service_generation_digest="a" * 64) is receipt
        with urllib.request.urlopen(receipt.url, timeout=2) as response:
            assert response.status == 200
            assert response.read() == RootOwnedApplicationFixtureServer._BODY
        with pytest.raises(AuthorityDenied, match="stale"):
            server.resolve(receipt.handle, setup_session_id="other",
                service_generation_digest="a" * 64)
    finally:
        server.close()


def test_root_execution_journal_consumes_qualification_once(tmp_path):
    root = tmp_path / "authority-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    info = root.stat()
    selection = RootJournalSelection("application-journal", root, info.st_dev, info.st_ino,
        "journal-generation", "a" * 64)
    clock = lambda: 10.0
    journal = RootApplicationExecutionJournal(selection,
        selection_resolver=lambda: selection, expected_uid=os.geteuid(), monotonic=clock)
    projected = b'{"arguments":{},"id":"graphify-code-fixture"}'
    request = RootApplicationQualificationRequest(
        1, "h" * 32, "r" * 32, "installer-application-qualification", "qualify-graphify-v1",
        "graphify", "graphify", "profile", "profile-generation", "principal", "namespace",
        "a" * 64, "b" * 64, "setup-session", "c" * 32, ("s" * 32,), "d" * 64,
        hashlib.sha256(projected).hexdigest(), "schema-v1", "", 1.0, 100.0, 0)
    context = RootApplicationQualificationContext(
        "setup-session", "graphify", "graphify", "profile", "profile-generation", "principal",
        "namespace", "a" * 64, "b" * 64, "c" * 32, ("s" * 32,), "d" * 64,
        "schema-v1", "", None, "e" * 64, 0)
    journal.retain_application_qualification_request(request, context, projected)
    assert journal.is_application_qualification_request_current(request.request_handle)
    assert journal.consume_application_qualification_request(request.request_handle)
    assert not journal.consume_application_qualification_request(request.request_handle)
    assert not journal.is_application_qualification_request_current(request.request_handle)
    runtime_selection = SimpleNamespace(operation_id="app-graphify-probe", runtime_receipt_handle="t" * 32,
        source_generation_receipt_handle="s" * 32)
    admission = journal.admit_selected_application_qualification_workload(request=request,
        context=context, workload_bytes=projected, selection=runtime_selection)
    assert journal.is_application_admission_current(admission.admission_handle)
    step = journal.resolve_application_step(admission.admission_handle, "graphify-code-fixture:0")
    assert journal.application_step_handle(step) == step.handle
    assert journal.is_application_step_current(step.handle)
