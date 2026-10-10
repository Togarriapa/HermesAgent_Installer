"""Root-native immutable CAS receipt producer contracts."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import time
from dataclasses import replace
from pathlib import Path

import pytest

from hermes_installer.authority.native_output_receipts import (
    NativeOutputMember,
    NativeOutputReceiptDenied,
    NativeOutputSelection,
    RootMaterializationReceiptRegistry,
    _read_archive_member,
    _archive_manifest,
    _member_manifest_digest,
    _normalize_reservation_ids,
    _normalize_members,
    _verify_payload,
    _verify_resources_source,
    _validate_role_selection_payload,
    _parse_canonical_json,
)


def _archive(path: str, content: bytes) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(path)
        info.size = len(content)
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def _compiled_closure(candidate: bytes | None = None) -> tuple[bytes, tuple[NativeOutputMember, ...]]:
    leaf = b"selected native module"
    overlay = json.dumps({
        "compiler_artifact_id": "installer-module:native_materializer",
        "compiler_sha256": "3" * 64,
        "members": [{"mode": 420, "path": "module.py",
                     "sha256": hashlib.sha256(leaf).hexdigest(), "size_bytes": len(leaf)}],
        "schema": 1, "source_commit": "d" * 40,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    closure_row = {"relative_path": "module.py", "sha256": hashlib.sha256(leaf).hexdigest(),
                   "size_bytes": len(leaf), "mode": 0o644}
    process_role = {
        "role_id": "native-loader", "package_id": "package-1",
        "native_package_generation": "generation-1", "profile_id": "demo",
        "profile_generation": "process-generation-1",
        "role_artifact_id": "role:native-loader",
        "role_sha256": hashlib.sha256(leaf).hexdigest(),
        "role_source_receipt_handle": "role-source-receipt-1",
        "module_name": "hermes_installer.native_plugin_loader",
        "closure_member_path": "module.py", "role_source_revision": "d" * 40,
        "role_source_tree_sha256": "e" * 64,
        "observer_enrollment_ids": ["observer-1"],
        "registration_ids": ["registration-1"],
        "action_binding_ids": ["action-1"], "workflow_ids": [],
    }
    process_roles_sha256 = hashlib.sha256(json.dumps(
        [process_role], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    resolver = json.dumps({"process_role_records_sha256": process_roles_sha256, "schema": 1},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    resolver_sha256 = hashlib.sha256(resolver).hexdigest()
    if candidate is None:
        candidate = json.dumps({"candidates": [], "generation": "generation-1",
                                "package_id": "package-1", "profile_id": "demo",
                                "resolver_sha256": resolver_sha256, "schema": 1},
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    manifest = json.dumps({
        "candidate_index": {"artifact_id": "native-candidate-index:package-1:generation-1",
                            "relative_path": "catalog/native-candidates.json",
                            "sha256": hashlib.sha256(candidate).hexdigest(),
                            "size_bytes": len(candidate)},
        "closure_files": [closure_row],
        "adapters": [],
        "dependencies": [],
        "process_role_records": [process_role],
        "process_role_records_sha256": process_roles_sha256,
        "resolver_sha256": resolver_sha256,
        "generation": "generation-1",
        "package_id": "package-1",
        "profile_id": "demo",
        "schema": 1,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    files = {"manifest.json": manifest, "resolver/resolver": resolver,
             "catalog/native-candidates.json": candidate, "closure/module.py": leaf,
             "overlay/manifest.json": overlay}
    stream = io.BytesIO()
    members = []
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, content in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
            members.append(NativeOutputMember(path, hashlib.sha256(content).hexdigest(),
                                              len(content), 0o644))
    return stream.getvalue(), tuple(members)


def _closure_tree_sha256(payload: bytes) -> str:
    rows = json.loads(_read_archive_member(payload, "manifest.json"))["closure_files"]
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()


def test_resources_source_receipt_input_is_exact_full_pinned_archive() -> None:
    bundle = (Path(__file__).parents[2] / "src/hermes_installer/registry/bundle_data"
              / "hermes-agent-resources-2.3.1.tar.gz").read_bytes()
    members = _archive_manifest(bundle, source_archive=True)
    assert len(members) == 739
    _verify_resources_source(bundle)
    with pytest.raises(NativeOutputReceiptDenied, match="file count"):
        _archive_manifest(_archive("one.txt", b"bad"), source_archive=True)


def test_member_manifest_commits_to_mode_size_and_content() -> None:
    content = b"profile instructions"
    row = NativeOutputMember("profiles/demo/SOUL.md",
                             hashlib.sha256(content).hexdigest(), len(content), 0o644)
    changed_mode = NativeOutputMember(row.path, row.sha256, row.size_bytes, 0o600)
    assert _member_manifest_digest((row,)) != _member_manifest_digest((changed_mode,))
    with pytest.raises(NativeOutputReceiptDenied, match="malformed"):
        _normalize_members((NativeOutputMember("../escape", row.sha256,
                                                row.size_bytes, 0o644),))


def test_compiled_closure_requires_candidate_index_as_fixed_member() -> None:
    payload, members = _compiled_closure()
    _verify_payload("native-compiled-closure", "compiled-closure", payload, members)
    index = _read_archive_member(payload, "catalog/native-candidates.json")
    assert _read_archive_member(payload, "catalog/native-candidates.json") == index
    _verify_payload("native-candidate-index", "candidate-index-json", index,
                    (NativeOutputMember("catalog/native-candidates.json",
                                        hashlib.sha256(index).hexdigest(), len(index), 0o644),))

    broken, broken_members = _compiled_closure(b'{"candidates":[],"schema":1}')
    with pytest.raises(NativeOutputReceiptDenied, match="schema is unsupported"):
        _verify_payload("native-compiled-closure", "compiled-closure", broken,
                        broken_members)

    without_index = _archive("profiles/demo/SOUL.md", b"profile")
    profile = NativeOutputMember("profiles/demo/SOUL.md",
                                 hashlib.sha256(b"profile").hexdigest(), 7, 0o644)
    with pytest.raises(NativeOutputReceiptDenied, match="required native member"):
        _verify_payload("native-compiled-closure", "compiled-closure", without_index,
                        (profile,))


def test_closure_role_binds_index_manifest_and_selected_generation() -> None:
    payload, _members = _compiled_closure()
    selection = NativeOutputSelection(
        "native-output:native-compiled-closure:package-1:generation-1",
        "native-compiled-closure", "compiled-closure", "package-1", "demo", "generation-1",
        "session-1", "transaction-" + "1" * 64, "2" * 64,
        "generation-1", "installer-module:native_materializer", "3" * 64,
        "installer-module:native_materializer", "5" * 64,
        ("A" * 48, "B" * 48), "4" * 64, hashlib.sha256(payload).hexdigest(),
        len(payload), _closure_tree_sha256(payload), 10_000.0)
    _validate_role_selection_payload(selection, "native-compiled-closure", payload)
    with pytest.raises(NativeOutputReceiptDenied, match="selected package generation"):
        _validate_role_selection_payload(replace(selection, generation="other"),
                                         "native-compiled-closure", payload)


def test_native_json_must_be_canonical_and_reject_duplicate_keys() -> None:
    with pytest.raises(NativeOutputReceiptDenied, match="canonical UTF-8"):
        _parse_canonical_json(b'{ "schema":1}')
    with pytest.raises(NativeOutputReceiptDenied, match="malformed"):
        _parse_canonical_json(b'{"schema":1,"schema":2}')


def test_active_compilation_reservation_requires_exact_five_opaque_handles() -> None:
    handles = tuple(chr(65 + index) * 48 for index in range(5))
    assert _normalize_reservation_ids(handles) == handles
    with pytest.raises(NativeOutputReceiptDenied, match="handle set"):
        _normalize_reservation_ids(handles[:-1])
    with pytest.raises(NativeOutputReceiptDenied, match="handle set"):
        _normalize_reservation_ids((*handles[:-1], handles[0]))


def test_non_root_cannot_construct_or_publish_native_output_receipts(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("non-root denial is covered by root Linux fixture")

    class Binding:
        def authorize_native_output(self, **_kwargs):
            raise AssertionError("must not authorize outside root")

        def revalidate_native_output(self, _selection):
            return False

    cas, journal = tmp_path / "cas", tmp_path / "journal"
    cas.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    with pytest.raises(NativeOutputReceiptDenied, match="root setup factory"):
        RootMaterializationReceiptRegistry(Binding(), cas_root=cas,
                                           journal_root=journal, authority_uid=os.getuid())


@pytest.mark.skipif(os.geteuid() != 0, reason="requires isolated root-owned Linux CAS fixture")
def test_output_receipt_is_current_immutable_and_one_use(tmp_path: Path) -> None:
    content = b"native selected profile"
    payload, members = _compiled_closure()
    archive_contents = {member.path: _read_archive_member(payload, member.path)
                        for member in members}
    outputs = {
        "native-entrypoint-manifest": ("entrypoint-json", "manifest.json"),
        "native-action-resolver": ("resolver-json", "resolver/resolver"),
        "native-boundary-overlay": ("boundary-overlay", "overlay/manifest.json"),
        "native-candidate-index": ("candidate-index-json", "catalog/native-candidates.json"),
        "native-compiled-closure": ("compiled-closure", ""),
    }
    closure_tree_sha256 = _closure_tree_sha256(payload)

    class Binding:
        def authorize_native_output(self, *, artifact_role, output_kind,
                                    member_tree_sha256, output_sha256,
                                    output_size_bytes):
            artifact_id = ("native-candidate-index:package-1:generation-1"
                           if artifact_role == "native-candidate-index" else
                           f"native-output:{artifact_role}:package-1:generation-1")
            return NativeOutputSelection(
                artifact_id,
                artifact_role, output_kind, "package-1", "demo", "generation-1",
                "session-1", "transaction-" + "1" * 64, "2" * 64,
                "generation-1", "installer-module:native_materializer",
                "3" * 64, "installer-module:native_materializer", "5" * 64,
                ("A" * 48, "B" * 48), member_tree_sha256,
                output_sha256, output_size_bytes, closure_tree_sha256, time.monotonic() + 3600,
            )

        current = True

        def revalidate_native_output(self, selection):
            return self.current and selection.transaction_handle == "transaction-" + "1" * 64

    cas, journal = tmp_path / "cas", tmp_path / "journal"
    cas.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    binding = Binding()
    registry = RootMaterializationReceiptRegistry._from_root_factory(
        binding=binding, cas_root=cas, journal_root=journal)
    receipts = {}
    for role, (kind, path) in outputs.items():
        data = payload if role == "native-compiled-closure" else archive_contents[path]
        rows = members if role == "native-compiled-closure" else (
            NativeOutputMember(path, hashlib.sha256(data).hexdigest(), len(data), 0o644),)
        receipts[role] = registry.publish_selected(
            artifact_role=role, output_kind=kind, payload=data, members=rows)
    receipt = receipts["native-compiled-closure"]
    object_path = cas / receipt.sha256[:2] / receipt.sha256
    assert object_path.read_bytes() == payload
    assert object_path.stat().st_uid == 0 and object_path.stat().st_mode & 0o777 == 0o400
    assert receipt.artifact_id == "native-output:native-compiled-closure:package-1:generation-1"
    output_ids = tuple(receipts[role].receipt_id for role in outputs)
    reservation = registry.reserve_for_active_compilation(
        output_ids, prepared_generation_id="generation-1",
        publication_handle="publication-" + "a" * 40, claim_digest="b" * 64)
    held = registry.verify_active_compilation(
        reservation.reservation_handle, prepared_generation_id="generation-1",
        publication_handle=reservation.publication_handle, claim_digest=reservation.claim_digest)
    assert {item.receipt_id for item in held} == set(output_ids)
    registry.release_active_compilation(
        reservation.reservation_handle, prepared_generation_id="generation-1",
        publication_handle=reservation.publication_handle, claim_digest=reservation.claim_digest)
    # A released transaction can be reserved under a fresh publication claim;
    # loss of source currentness prevents the next held verification.
    retry = registry.reserve_for_active_compilation(
        output_ids, prepared_generation_id="generation-1",
        publication_handle="publication-" + "c" * 40, claim_digest="d" * 64)
    binding.current = False
    with pytest.raises(NativeOutputReceiptDenied, match="current|revalid"):
        registry.verify_active_compilation(
            retry.reservation_handle, prepared_generation_id="generation-1",
            publication_handle=retry.publication_handle, claim_digest=retry.claim_digest)
    binding.current = True
    registry.release_active_compilation(
        retry.reservation_handle, prepared_generation_id="generation-1",
        publication_handle=retry.publication_handle, claim_digest=retry.claim_digest)
    consumed = None
    for role in outputs:
        consumed = registry.resolve_for_activation(
            receipts[role].receipt_id, artifact_role=role,
            prepared_generation_id="generation-1")
    assert consumed is not None
    assert consumed.store_id == receipt.store_id
    with pytest.raises(NativeOutputReceiptDenied, match="spent"):
        registry.resolve_for_activation(
            receipt.receipt_id, artifact_role="native-compiled-closure",
            prepared_generation_id="generation-1")


@pytest.mark.skipif(os.geteuid() != 0, reason="requires isolated root-owned Linux CAS fixture")
def test_active_reservation_recovers_after_registry_restart_and_completes_idempotently(tmp_path: Path) -> None:
    payload, members = _compiled_closure()
    archive_contents = {member.path: _read_archive_member(payload, member.path)
                        for member in members}
    outputs = {
        "native-entrypoint-manifest": ("entrypoint-json", "manifest.json"),
        "native-action-resolver": ("resolver-json", "resolver/resolver"),
        "native-boundary-overlay": ("boundary-overlay", "overlay/manifest.json"),
        "native-candidate-index": ("candidate-index-json", "catalog/native-candidates.json"),
        "native-compiled-closure": ("compiled-closure", ""),
    }
    closure_tree_sha256 = _closure_tree_sha256(payload)
    claim_digest = "9" * 64
    publication_handle = "P" * 48
    transaction_handle = "transaction-" + "1" * 64
    current_time = [time.monotonic()]
    expires = current_time[0] + 3600

    class Binding:
        def authorize_native_output(self, *, artifact_role, output_kind,
                                    member_tree_sha256, output_sha256,
                                    output_size_bytes):
            artifact_id = ("native-candidate-index:package-1:generation-1"
                           if artifact_role == "native-candidate-index" else
                           f"native-output:{artifact_role}:package-1:generation-1")
            return NativeOutputSelection(
                artifact_id, artifact_role, output_kind, "package-1", "demo", "generation-1",
                "session-1", transaction_handle, "2" * 64, "generation-1",
                "installer-module:native_materializer", "3" * 64,
                "installer-module:native_materializer", "5" * 64,
                ("A" * 48, "B" * 48), member_tree_sha256, output_sha256,
                output_size_bytes, closure_tree_sha256, expires)

        def revalidate_native_output(self, selection):
            return selection.transaction_handle == transaction_handle

        def verify_native_publication_receipt(self, reservation, receipt):
            return (receipt.state == "active-committed"
                    and receipt.publication_handle == reservation.publication_handle
                    and receipt.claim_digest == reservation.claim_digest
                    and receipt.prepared_generation_id == reservation.prepared_generation_id
                    and receipt.transaction_handle == transaction_handle
                    and set(reservation.receipt_ids).issubset(receipt.materialization_receipt_handles))

    cas, journal = tmp_path / "cas", tmp_path / "journal"
    cas.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    binding = Binding()
    registry = RootMaterializationReceiptRegistry._from_root_factory(
        binding=binding, cas_root=cas, journal_root=journal)
    registry._monotonic = lambda: current_time[0]
    receipts = {}
    for role, (kind, path) in outputs.items():
        data = payload if role == "native-compiled-closure" else archive_contents[path]
        rows = members if role == "native-compiled-closure" else (
            NativeOutputMember(path, hashlib.sha256(data).hexdigest(), len(data), 0o644),)
        receipts[role] = registry.publish_selected(
            artifact_role=role, output_kind=kind, payload=data, members=rows)
    receipt_ids = tuple(sorted(row.receipt_id for row in receipts.values()))
    reservation = registry.reserve_for_active_compilation(
        receipt_ids, prepared_generation_id="generation-1",
        publication_handle=publication_handle, claim_digest=claim_digest)

    class _Publication:
        state = "active-committed"

        def __init__(self):
            self.publication_handle = publication_handle
            self.claim_digest = claim_digest
            self.prepared_generation_id = "generation-1"
            self.transaction_handle = transaction_handle
            self.materialization_receipt_handles = receipt_ids

    # A newly opened registry recovers only by the typed current publication,
    # exact transaction/claim, and the one complete durable output reservation.
    reopened = RootMaterializationReceiptRegistry._from_root_factory(
        binding=binding, cas_root=cas, journal_root=journal)
    reopened._monotonic = lambda: current_time[0]
    publication = _Publication()
    tampered = _Publication()
    tampered.claim_digest = "8" * 64
    with pytest.raises(NativeOutputReceiptDenied, match="does not resolve"):
        reopened.resolve_active_compilation_reservation(tampered)
    recovered = reopened.resolve_active_compilation_reservation(publication)
    assert recovered.reservation_handle == reservation.reservation_handle
    assert recovered.receipt_ids == receipt_ids
    completed = reopened.complete_active_compilation(
        recovered.reservation_handle, publication, prepared_generation_id="generation-1",
        publication_handle=publication_handle, claim_digest=claim_digest)
    assert {row.receipt_id for row in completed} == set(receipt_ids)
    # Retrying after the registry commit returns the exact consumed receipt set.
    retry = reopened.complete_active_compilation(
        recovered.reservation_handle, publication, prepared_generation_id="generation-1",
        publication_handle=publication_handle, claim_digest=claim_digest)
    assert {row.receipt_id for row in retry} == set(receipt_ids)
    with reopened._connect() as db:
        db.execute(
            "INSERT INTO reservations(reservation_handle,publication_handle,claim_digest,"
            "prepared_generation_id,receipt_ids,transaction_handle,expires_monotonic,state) "
            "SELECT ?,publication_handle,claim_digest,prepared_generation_id,receipt_ids,"
            "transaction_handle,expires_monotonic,state FROM reservations WHERE reservation_handle=?",
            ("R" * 48, recovered.reservation_handle),
        )
    with pytest.raises(NativeOutputReceiptDenied, match="does not resolve one"):
        reopened.resolve_active_compilation_reservation(publication)
    current_time[0] = expires + 1
    with pytest.raises(NativeOutputReceiptDenied, match="does not resolve"):
        reopened.resolve_active_compilation_reservation(publication)
