"""Selected app source/runtime registries reject stale and altered generations."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from hermes_installer.authority.application_runtime import (
    RootApplicationRuntimeReceiptRegistry,
    RootApplicationRunReceipt,
    RootComponentSourceReceiptRegistry,
    RootSelectedApplicationRuntime,
    RootManagedApplicationRuntimeProbeRegistry,
    SelectedApplicationUnavailable,
)
from hermes_installer.components.runtime_factory import SelectedApplicationWorkloadFactory
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.runtime_source import bind_component_runtime_source
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


def _source(component_id: str = "ecc") -> VerifiedComponentSource:
    contract = resolve_component_adapter(component_id)
    files = {"LICENSE": b"fixture license\n", "source.py": b"print('reviewed')\n"}
    modes = {name: 0o644 for name in files}
    content = hashlib.sha256()
    for name in sorted(files):
        content.update(name.encode() + b"\0")
        content.update(f"{modes[name]:o}".encode() + b"\0")
        content.update(hashlib.sha256(files[name]).digest())
    tree = _git_tree(files, modes)[0]
    archive_sha = "a" * 64
    provenance = {
        "schema": 1, "component_id": component_id,
        "source_identity": contract.source_identity, "source_url": contract.selected_source_url,
        "revision": contract.revision, "source_selection": contract.source_selection,
        "source_archive_sha256": archive_sha, "source_content_sha256": content.hexdigest(),
        "source_tree_sha": tree, "declared_license": contract.license,
        "license_files": ["LICENSE"],
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    files["INSTALLER-SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    modes["INSTALLER-SOURCE-PROVENANCE.json"] = 0o644
    return VerifiedComponentSource(
        component_id=component_id, source_identity=contract.source_identity or "",
        revision=contract.revision or "", files=files, file_modes=modes,
        archive_sha256=archive_sha, content_sha256=content.hexdigest(),
        source_tree_sha=tree, license=contract.license, license_files=("LICENSE",),
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )


def _store(path: Path) -> GenerationStore:
    owned = OwnedRoot(path)
    owned.ensure()
    return GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)


class _Catalog:
    def __init__(self, row: dict):
        self.row = row
        self.generation_digest = "f" * 64

    def selected_application_runtime_record(self, application_id: str):
        if application_id != self.row["application_id"]:
            raise KeyError(application_id)
        return self.row


def test_source_receipt_reopens_root_generation_and_rejects_tampering(tmp_path: Path) -> None:
    source = _source()
    store = _store(tmp_path / "source-store")
    generation = bind_component_runtime_source(source, store, component_id="ecc")
    handle = "s" * 40
    row = {
        "application_id": "ecc", "source_identity": source.source_identity,
        "source_revision": source.revision, "source_tree_sha256": source.source_tree_sha,
        "source_generation_receipt_handle": handle,
        "source_generation_manifest_sha256": generation.generation_digest,
    }
    catalog = _Catalog(row)
    registry = RootComponentSourceReceiptRegistry(
        enrollment_catalog=catalog, generation_stores={"ecc": store}, expected_uid=os.getuid(),
    )
    assert registry.record_verified_generation(source, generation, application_id="ecc") == handle
    selected = registry.resolve(handle, application_id="ecc", service_generation_digest=catalog.generation_digest)
    assert selected.source_tree_sha256 == source.source_tree_sha

    member = selected.generation_root / "source.py"
    member.chmod(0o600)
    member.write_bytes(b"changed after source receipt\n")
    with pytest.raises(SelectedApplicationUnavailable, match="failed root verification"):
        registry.resolve(handle, application_id="ecc", service_generation_digest=catalog.generation_digest)


def test_runtime_receipt_refuses_without_actual_custody_probe_producer(tmp_path: Path) -> None:
    source = _source()
    source_store = _store(tmp_path / "source-store")
    generation = bind_component_runtime_source(source, source_store, component_id="ecc")
    runtime_store = _store(tmp_path / "runtime-store")
    runtime_store.stage("runtime-ecc", {"bin/python": b"verified runtime placeholder\n"},
                        file_modes={"bin/python": 0o500})
    _, manifest, runtime_digest = runtime_store._verify("runtime-ecc")
    del manifest
    source_handle, runtime_handle, probe_handle = "s" * 40, "r" * 40, "p" * 40
    row = {
        "application_id": "ecc", "source_identity": source.source_identity,
        "source_revision": source.revision, "source_tree_sha256": source.source_tree_sha,
        "source_generation_receipt_handle": source_handle,
        "source_generation_manifest_sha256": generation.generation_digest,
        "runtime_id": "runtime-ecc", "runtime_receipt_handle": runtime_handle,
        "runtime_manifest_sha256": runtime_digest, "lock_sha256": "a" * 64,
    }
    catalog = _Catalog(row)
    source_registry = RootComponentSourceReceiptRegistry(
        enrollment_catalog=catalog, generation_stores={"ecc": source_store}, expected_uid=os.getuid(),
    )
    source_registry.record_verified_generation(source, generation, application_id="ecc")
    from hermes_installer.managed_process_custodian import ManagedProcessEffectHandler
    manager = object.__new__(ManagedProcessEffectHandler)
    probe_registry = RootManagedApplicationRuntimeProbeRegistry(manager)
    runtime_registry = RootApplicationRuntimeReceiptRegistry(
        source_receipts=source_registry, enrollment_catalog=catalog,
        runtime_stores={"runtime-ecc": runtime_store}, managed_probe_registry=probe_registry,
        expected_uid=os.getuid(),
    )
    selected_lock = {"application_id": "ecc", "runtime_id": "runtime-ecc",
                     "runtime_manifest_sha256": runtime_digest, "lock_sha256": "a" * 64}
    with pytest.raises(SelectedApplicationUnavailable, match="no selected isolated-runtime probe receipt producer"):
        runtime_registry.record_observed_environment(source_handle, selected_lock, probe_handle)


def test_production_factory_forwards_only_canonical_selected_request() -> None:
    source = _source()
    source_receipt = SimpleSourceReceipt(
        "ecc", source.source_identity, source.revision, source.source_tree_sha,
        "s" * 40, "b" * 64, "f" * 64,
    )
    runtime_receipt = SimpleRuntimeReceipt("ecc", "s" * 40, "runtime-ecc", "r" * 40, "c" * 64, "a" * 64, "f" * 64)
    runtime = RootSelectedApplicationRuntime(
        "ecc", "profile", "generation", "principal", "ecc.adapter.v1",
        source.source_identity, source.revision, source.source_tree_sha,
        "s" * 40, "b" * 64, "runtime-ecc", "r" * 40, "c" * 64, "a" * 64,
        "work", "data", "ecc.run.v1", "process.start.target",
        "ecc.request.v1", "d" * 64, "ecc.result.v1", "validator", "e" * 64,
        ("component.ecc.run",), (), (), None, None, 30, 64 * 1024 * 1024,
        1, "0", True, "f" * 64, source_receipt, runtime_receipt, {},
    )

    class Bindings:
        def resolve_selected_application_runtime(self, app, profile):
            assert (app, profile) == ("ecc", "profile")
            return runtime

    class Authority:
        def dispatch_selected_application(self, invocation, app, canonical):
            assert invocation == "i" * 40
            assert app == "ecc"
            assert canonical == b'{"count":2,"mode":"local"}'
            return RootApplicationRunReceipt(
                1, "r" * 40, "ecc", "profile", "generation", "f" * 64,
                "s" * 40, "r" * 40, "ecc.run.v1", hashlib.sha256(canonical).hexdigest(),
                "t" * 40, "c" * 40, "complete", 10.0, 20.0,
            )

    adapter = SelectedApplicationWorkloadFactory(bindings=Bindings(), authority=Authority()).build("ecc", "profile")
    receipt = adapter.invoke("i" * 40, {"mode": "local", "count": 2})
    assert receipt.state == "complete"


@dataclass(frozen=True)
class SimpleSourceReceipt:
    application_id: str
    source_identity: str
    source_revision: str
    source_tree_sha256: str
    handle: str
    generation_manifest_sha256: str
    service_generation_digest: str


@dataclass(frozen=True)
class SimpleRuntimeReceipt:
    application_id: str
    source_receipt_handle: str
    runtime_id: str
    handle: str
    runtime_manifest_sha256: str
    lock_sha256: str
    service_generation_digest: str
