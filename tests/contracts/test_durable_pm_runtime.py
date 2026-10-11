"""Durable published-home PM lineage and restart-proof contracts."""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from hermes_installer.authority import committed_pm_executable as committed
from hermes_installer.authority import durable_pm_runtime as durable
from hermes_installer.authority import setup_policy_publication as publication


def _row(**changes):
    values = dict(
        home_binding_id="home-binding", source_profile_id="delegate-a",
        source_revision="rev-1", source_manifest_sha256="1" * 64,
        role="resource-delegate-home", native_profile_key="default",
        display_name="Delegate A", home_selection_handle="selection-a",
        materialization_receipt_handle="materialization-a", mapping_sha256="2" * 64,
        home_generation="home-generation", principal_id="principal-a",
        namespace_id="namespace-a", runtime_receipt_handle="r" * 48,
        runtime_identity_sha256="3" * 64, behavioral_manifest_sha256="4" * 64,
    )
    values.update(changes)
    return publication.RootPublishedNativeProfileHomeRow(**values)


def _identity(path, *, handle="r" * 48, runtime_sha="3" * 64,
              principal="principal-a", namespace="namespace-a"):
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    class Custody:
        closed = False
        def release(self, _identity):
            if not self.closed:
                self.closed = True
                os.close(fd)
    identity = committed.RootVerifiedCommittedPMExecutableIdentity(
        identity_handle=hashlib.sha256(os.urandom(16)).hexdigest(),
        service_generation_digest="5" * 64, publication_receipt_handle="publication-a",
        publication_sha256="6" * 64, active_generation_id="active-a", network_id="network-a",
        profile_id="service-profile-a", service_generation="service-generation-a",
        principal_id=principal, namespace_id=namespace,
        runtime_record_id="runtime-record-a", runtime_record_sha256="7" * 64,
        source_choice_selection_handle="choice-a", source_choice_signed_record_sha256="8" * 64,
        source_original_setup_deadline_unix=1.0, pm_runtime_receipt_handle=handle,
        pm_receipt_sha256="9" * 64, pm_generation="pm-" + "a" * 32,
        source_commit="7085fbf7753266fc4943c55ac04926186bc90005",
        runtime_relative="home/bin/python", runtime_venv_relative="home",
        runtime_closure_sha256="a" * 64, executable_path=path,
        executable_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        executable_device=info.st_dev, executable_inode=info.st_ino,
        executable_uid=info.st_uid, executable_gid=info.st_gid,
        executable_mode=info.st_mode & 0o7777, runtime_identity_sha256=runtime_sha,
        expires_monotonic=time.monotonic() + 60,
        member_fds=(fd,), runtime_member_fds=(("home/bin/python", fd),),
        _custody=Custody(), _issuer=object(),
    )
    return identity


def _resolver(tmp_path, monkeypatch, rows):
    generation = "5" * 64
    core = object.__new__(publication.RootPublishedAuthorityCore)
    object.__setattr__(core, "service_generation_digest", generation)
    object.__setattr__(core, "_issuer", object())

    def current_crosswalk(_core):
        member = tmp_path / "member.json"
        member.write_bytes(b"{}")
        fd = os.open(member, os.O_RDONLY)
        return publication.RootPublishedNativeProfileHomeCrosswalk(
            schema=1, rows=tuple(rows), publication_handle="publication-a",
            service_generation_digest=generation, crosswalk_member_sha256="b" * 64,
            source_output_claim_sha256="c" * 64, _core=core, _member_fd=fd,
            _member_device=os.fstat(fd).st_dev, _member_inode=os.fstat(fd).st_ino,
            _member_size=2, _seal=publication._NATIVE_PROFILE_HOME_SEAL,
        )

    monkeypatch.setattr(publication.RootPublishedAuthorityCore,
                        "resolve_current_native_profile_home_crosswalk", current_crosswalk)
    monkeypatch.setattr(publication.RootPublishedNativeProfileHomeCrosswalk,
                        "close", lambda self: os.close(self._member_fd))

    journals = object.__new__(__import__(
        "hermes_installer.protected_enrollment", fromlist=["ProtectedRootJournalCatalog"]
    ).ProtectedRootJournalCatalog)
    object.__setattr__(journals, "generation_digest", generation)
    pm = object.__new__(committed.RootActiveCommittedPMExecutableResolver)
    pm._journals = journals
    pm._catalog = SimpleNamespace(digest=generation)
    pm._closed = False
    pm._issued = {}
    identity_factory = []

    def resolve_selected(_self):
        identity = identity_factory.pop(0)
        _self._issued[identity.identity_handle] = identity
        return identity

    def verify_current(_self, identity):
        assert _self._issued.get(identity.identity_handle) is identity
        assert identity.expires_monotonic > time.monotonic()
        return identity

    monkeypatch.setattr(committed.RootActiveCommittedPMExecutableResolver,
                        "resolve_selected", resolve_selected)
    monkeypatch.setattr(committed.RootActiveCommittedPMExecutableResolver,
                        "verify_current", verify_current)
    resolver = durable.RootPublishedProfileHomePMRuntimeResolver.from_root_runtime(
        core, pm, journals)
    return resolver, identity_factory


def test_fresh_current_published_row_holds_and_duplicates_actual_runtime_fds(
        tmp_path, monkeypatch):
    executable = tmp_path / "python"
    executable.write_bytes(b"current pm executable")
    row = _row()
    resolver, identities = _resolver(tmp_path, monkeypatch, [row])
    identities.append(_identity(executable))

    proof = resolver.resolve_current_profile_home_runtime(row)
    assert proof.runtime_identity_sha256 == row.runtime_identity_sha256
    assert proof.pm_runtime_receipt_handle == row.runtime_receipt_handle
    executable_fd = resolver.duplicate_executable_fd(proof, row)
    member_fd = resolver.duplicate_runtime_member_fd(proof, row, "home/bin/python")
    owned_fd = resolver.duplicate_runtime_member_fd(proof, row, "home/bin/python")
    owned_fd = resolver.duplicate_runtime_member_fd(proof, row, "home/bin/python")
    assert os.fstat(executable_fd).st_ino == proof.executable_inode
    assert os.fstat(member_fd).st_ino == proof.executable_inode
    assert resolver.verify_current(proof, row)
    transferred_fd = resolver.release_duplicate_fd(proof, row, executable_fd)
    reused_fd = member_fd
    os.close(member_fd)
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"preserve this descriptor")
    unrelated_fd = os.open(unrelated, os.O_RDONLY)
    assert unrelated_fd == reused_fd
    proof.close()
    assert os.read(unrelated_fd, 9) == b"preserve "
    os.close(unrelated_fd)
    os.close(transferred_fd)
    with pytest.raises(OSError):
        os.fstat(owned_fd)
    with pytest.raises(OSError):
        os.fstat(owned_fd)


def test_expired_setup_is_not_needed_and_restart_mints_a_new_process_proof(
        tmp_path, monkeypatch):
    executable = tmp_path / "python"
    executable.write_bytes(b"current pm executable")
    row = _row()
    first, identities = _resolver(tmp_path, monkeypatch, [row])
    identities.append(_identity(executable))
    old = first.resolve_current_profile_home_runtime(row)
    second, identities = _resolver(tmp_path, monkeypatch, [row])
    identities.append(_identity(executable))
    fresh = second.resolve_current_profile_home_runtime(row)
    assert fresh.proof_handle != old.proof_handle
    assert fresh.identity is not old.identity
    assert second.verify_current(fresh, row)
    with pytest.raises(durable.PublishedPMRuntimeUnavailable, match="stale or foreign"):
        second.verify_current(old, row)
    assert not old.identity._custody.closed
    old.close()
    fresh.close()


def test_current_row_runtime_or_namespace_drift_denies_publication_proof(
        tmp_path, monkeypatch):
    executable = tmp_path / "python"
    executable.write_bytes(b"current pm executable")
    original = _row()
    current_rows = [original]
    resolver, identities = _resolver(tmp_path, monkeypatch, current_rows)
    identities.append(_identity(executable))
    proof = resolver.resolve_current_profile_home_runtime(original)
    current_rows[0] = replace(original, runtime_identity_sha256="d" * 64)
    with pytest.raises(durable.PublishedPMRuntimeUnavailable, match="stale"):
        resolver.verify_current(proof, original)

    wrong_ns = _row(namespace_id="namespace-other")
    resolver, identities = _resolver(tmp_path, monkeypatch, [wrong_ns])
    identities.append(_identity(executable, namespace="namespace-a"))
    with pytest.raises(durable.PublishedPMRuntimeUnavailable, match="absent or changed"):
        resolver.resolve_current_profile_home_runtime(wrong_ns)


def test_runtime_projection_uses_all_eleven_published_identity_fields():
    observed = {
        "sha256": "e" * 64, "device": 10, "inode": 11, "uid": 0, "gid": 0,
        "mode": 0o500, "version_info": [3, 14, 7], "implementation": "cpython",
        "cache_tag": "cpython-314", "soabi": "cpython-314-aarch64-linux-gnu",
        "machine": "aarch64",
    }
    receipt = {
        "runtime_executable_sha256": observed["sha256"], "runtime_device": 10,
        "runtime_inode": 11, "runtime_uid": 0, "runtime_gid": 0,
        "runtime_mode": 0o500, "version_info": [3, 14, 7],
        "implementation": "cpython", "cache_tag": "cpython-314",
        "soabi": "cpython-314-aarch64-linux-gnu", "machine": "aarch64",
    }
    projection = {
        "runtime_receipt_handle": "r" * 48, "runtime_sha256": "e" * 64,
        "device": 10, "inode": 11, "uid": 0, "gid": 0,
        "version_info": [3, 14, 7], "implementation": "cpython",
        "cache_tag": "cpython-314", "soabi": "cpython-314-aarch64-linux-gnu",
        "machine": "aarch64",
    }
    from hermes_installer.authority.committed_pm_executable import (
        _canonical, _runtime_identity_sha256,
    )
    actual = _runtime_identity_sha256("r" * 48, observed, receipt)
    assert actual == hashlib.sha256(_canonical(projection)).hexdigest()
    receipt["cache_tag"] = "changed"
    with pytest.raises(ValueError, match="metadata differs"):
        _runtime_identity_sha256("r" * 48, observed, receipt)
