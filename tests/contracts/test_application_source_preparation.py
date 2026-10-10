"""Pre-active source and lock receipts use the real pinned-source verifier."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.application_source_preparation import (
    ApplicationSourcePreparationDenied,
    RootApplicationSourcePreparationRegistry,
    RootApplicationSourcePreparationSelection,
    reviewed_application_source_profile,
)
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.source_bundle import (
    GitHubComponentSourceFetcher, HttpResponse,
)
from hermes_installer.protected_enrollment import RootJournalSelection
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


class _Transport:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, url, *, max_bytes, timeout_seconds):
        return self.responses.pop(0)


def _archive(identity: str, revision: str, files: dict[str, bytes]) -> tuple[bytes, str]:
    modes = {name: 0o644 for name in files}
    tree_sha = _git_tree(files, modes)[0]
    owner, repo = identity.split("/", 1)
    prefix = f"{owner}-{repo}-{revision[:7]}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        root = tarfile.TarInfo(prefix + "/")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        for name, body in files.items():
            item = tarfile.TarInfo(prefix + "/" + name)
            item.mode = modes[name]
            item.size = len(body)
            tar.addfile(item, io.BytesIO(body))
    return buffer.getvalue(), tree_sha


def _fetcher_for_graphify():
    contract = resolve_component_adapter("graphify")
    files = {
        "LICENSE": b"MIT License\n",
        "pyproject.toml": (
            b"[project]\nname = \"graphifyy\"\nversion = \"0.9.82\"\n"
            b"requires-python = \">=3.10\"\n"
        ),
        "uv.lock": b"version = 1\nrequires-python = \">=3.10\"\n\n[[package]]\nname = \"graphifyy\"\nversion = \"0.9.82\"\n",
    }
    archive, tree_sha = _archive(contract.source_identity, contract.revision, files)
    commit_url = f"https://api.github.com/repos/{contract.source_identity}/commits/{contract.revision}"
    commit = json.dumps({
        "sha": contract.revision,
        "html_url": f"https://github.com/{contract.source_identity}/commit/{contract.revision}",
        "commit": {"tree": {"sha": tree_sha}},
    }).encode()
    archive_url = f"https://codeload.github.com/{contract.source_identity}/legacy.tar.gz/{contract.revision}"
    fetcher = GitHubComponentSourceFetcher(_Transport([
        HttpResponse(200, commit_url, commit), HttpResponse(200, archive_url, archive),
    ]))
    return fetcher


class _SetupBindingFixture:
    """Narrow setup-bound resolver fixture; source DTO still comes from real fetcher."""

    def __init__(self, selection):
        self.selection = selection
        self.choice = SimpleNamespace(
            selection_handle=selection.qualification_choice_handle,
            setup_session_id=selection.setup_session_id,
            transaction_handle=selection.transaction_handle,
            prepared_generation_id=selection.prepared_generation_id,
            workflow_id=selection.workflow_id,
            application_id=selection.application_id,
        )
        self.namespace = SimpleNamespace(
            receipt_handle=selection.namespace_selection_receipt_handle,
            target_profile_id=selection.target_profile_id,
            setup_session_id=selection.setup_session_id,
            transaction_handle=selection.transaction_handle,
            prepared_generation_id=selection.prepared_generation_id,
            prepared_generation_digest=selection.prepared_generation_digest,
            expires_monotonic=9999.0,
        )
        self.consent = SimpleNamespace(
            receipt_handle=selection.qualification_consent_receipt_handle,
            purpose="installer-application-local-qualification",
            qualification_choice_handle=selection.qualification_choice_handle,
            setup_session_id=selection.setup_session_id,
            transaction_handle=selection.transaction_handle,
            plan_sha256=selection.plan_sha256,
            prepared_generation_id=selection.prepared_generation_id,
            prepared_generation_digest=selection.prepared_generation_digest,
            application_id=selection.application_id,
            workflow_id=selection.workflow_id,
            target_profile_id=selection.target_profile_id,
            namespace_selection_receipt_handle=selection.namespace_selection_receipt_handle,
            controller_binding_handle=selection.controller_binding_handle,
            allowed_phase_ids=("stage-pinned-source-locks",), expires_monotonic=9999.0,
        )

    def resolve_application_source_preparation(self, choice_handle, application_id):
        assert choice_handle == self.selection.qualification_choice_handle
        assert application_id == self.selection.application_id
        return self.selection

    def resolve_application_setup_choice(self, handle):
        assert handle == self.selection.qualification_choice_handle
        return self.choice

    def resolve_application_qualification_consent(self, choice_handle, phase_id):
        assert choice_handle == self.selection.qualification_choice_handle
        assert phase_id == "stage-pinned-source-locks"
        return self.consent

    def resolve_adopted_namespace_selection(self):
        return self.namespace


def _registry(tmp_path: Path, now: list[float]):
    profile = reviewed_application_source_profile("graphify")
    root = OwnedRoot(tmp_path / "root")
    root.ensure()
    journal = Journal(root.path("journal.sqlite3"))
    store = GenerationStore(root, journal, mutation_locked=True)
    journal_info = root.root.lstat()
    source_selection = RootApplicationSourcePreparationSelection._mint(
        schema=1,
        selection_handle="source-selection-handle-0000000000000000000000000000",
        setup_session_id="setup-session-0000000000000000000000000000",
        transaction_handle="transaction-handle-0000000000000000000000000000",
        plan_sha256="a" * 64,
        prepared_generation_id="prepared-generation-0000000000000000000000000000",
        prepared_generation_digest="b" * 64,
        qualification_choice_handle="qualification-choice-0000000000000000000000000000",
        qualification_consent_receipt_handle="qualification-consent-0000000000000000000000000",
        application_id=profile.application_id,
        workflow_id=profile.workflow_id,
        source_identity=profile.source_identity,
        source_revision=profile.source_revision,
        source_catalog_artifact_id=profile.source_catalog_artifact_id,
        source_catalog_sha256=profile.source_catalog_sha256,
        manifest_paths=profile.manifest_paths,
        lock_paths=profile.lock_paths,
        target_profile_id="hermes-agent-native-v1",
        namespace_selection_receipt_handle="namespace-selection-00000000000000000000000",
        principal_selection_receipt_handle=None,
        controller_binding_handle="controller-binding-0000000000000000000000000",
        expires_monotonic=now[0] + 100,
    )
    binding = _SetupBindingFixture(source_selection)
    root_journal = RootJournalSelection(
        root_id="fixture-root-journal",
        path=root.root,
        device=journal_info.st_dev,
        inode=journal_info.st_ino,
        generation="fixture-generation",
        service_generation_digest="c" * 64,
    )
    registry = RootApplicationSourcePreparationRegistry.from_root_setup(
        binding, _fetcher_for_graphify(), store, root_journal,
        expected_uid=root.root.stat().st_uid, monotonic=lambda: now[0],
    )
    return registry, binding, source_selection, root, journal


def test_pre_active_source_and_lock_receipts_are_current_and_source_verified(tmp_path: Path) -> None:
    now = [100.0]
    registry, _binding, selection, _root, journal = _registry(tmp_path, now)
    with process_lock(registry.store.owned.path("installer.lock")):
        current_selection = registry.resolve_application_source_preparation(
            selection.qualification_choice_handle, "graphify")
        source_receipt = registry.prepare_selected_source(current_selection.selection_handle)
        lock_receipt = registry.resolve_application_lock_for_prepared_source(
            current_selection.selection_handle, source_receipt.receipt_handle)
        assert source_receipt.source_identity == "Graphify-Labs/graphify"
        assert source_receipt.source_revision == "5b74d7d74911cf435c8f1636b6f96ea202cc6246"
        assert source_receipt.lock_member_records[0]["sha256"] == lock_receipt.lock_sha256
        lock_bytes = registry.read_current_lock_bytes(
            lock_receipt.receipt_handle, current_selection.selection_handle,
            source_receipt.receipt_handle,
        )
        assert isinstance(lock_bytes, bytes) and hashlib.sha256(lock_bytes).hexdigest() == lock_receipt.lock_sha256
        assert journal.owned("application-source")
        assert registry.record_prepared_verified_generation(
            source_receipt.receipt_handle, current_selection.selection_handle) is source_receipt


def test_pre_active_receipts_reject_source_tamper_stale_choice_and_expiry(tmp_path: Path) -> None:
    now = [100.0]
    registry, binding, selection, _root, _journal = _registry(tmp_path, now)
    with process_lock(registry.store.owned.path("installer.lock")):
        registry.resolve_application_source_preparation(selection.qualification_choice_handle, "graphify")
        source_receipt = registry.prepare_selected_source(selection.selection_handle)
        entry = registry._sources[selection.selection_handle]
        staged = entry.journal_source_root / "pyproject.toml"
        staged.chmod(0o600)
        staged.write_bytes(b"tampered\n")
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.resolve_prepared_source(source_receipt.receipt_handle)

    now = [100.0]
    registry, binding, selection, _root, _journal = _registry(tmp_path / "stale", now)
    with process_lock(registry.store.owned.path("installer.lock")):
        registry.resolve_application_source_preparation(selection.qualification_choice_handle, "graphify")
        binding.selection = replace(selection, namespace_selection_receipt_handle="changed-namespace-handle-000000000000000")
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.resolve_selection(selection.selection_handle)

    now = [100.0]
    registry, _binding, selection, _root, _journal = _registry(tmp_path / "expired", now)
    with process_lock(registry.store.owned.path("installer.lock")):
        registry.resolve_application_source_preparation(selection.qualification_choice_handle, "graphify")
        now[0] = 1000.0
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.resolve_selection(selection.selection_handle)


def test_pre_active_lock_receipt_and_namespace_currentness_are_sealed(tmp_path: Path) -> None:
    now = [100.0]
    registry, binding, selection, _root, _journal = _registry(tmp_path, now)
    with process_lock(registry.store.owned.path("installer.lock")):
        registry.resolve_application_source_preparation(selection.qualification_choice_handle, "graphify")
        source = registry.prepare_selected_source(selection.selection_handle)
        lock = registry.resolve_application_lock_for_prepared_source(
            selection.selection_handle, source.receipt_handle)
        lock_entry = registry._locks[lock.receipt_handle]
        lock_path = registry.store.root / lock_entry.generation_id / lock.lock_member_path
        lock_path.chmod(0o600)
        lock_path.write_bytes(b"tampered lock\n")
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.resolve_application_lock_receipt(
                lock.receipt_handle,
                preparation_selection_handle=selection.selection_handle,
                prepared_source_receipt_handle=source.receipt_handle,
            )
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.read_current_lock_bytes(
                lock.receipt_handle, selection.selection_handle, source.receipt_handle)

    now = [100.0]
    registry, binding, selection, _root, _journal = _registry(tmp_path / "namespace", now)
    with process_lock(registry.store.owned.path("installer.lock")):
        registry.resolve_application_source_preparation(selection.qualification_choice_handle, "graphify")
        binding.namespace.receipt_handle = "replaced-namespace-handle-00000000000000000"
        with pytest.raises(ApplicationSourcePreparationDenied):
            registry.resolve_selection(selection.selection_handle)


def test_source_selection_dto_rejects_caller_construction() -> None:
    with pytest.raises(TypeError, match="minted by the root setup binding"):
        RootApplicationSourcePreparationSelection(
            schema=1, selection_handle="x", setup_session_id="x",
            transaction_handle="x", plan_sha256="x", prepared_generation_id="x",
            prepared_generation_digest="x", qualification_choice_handle="x",
            qualification_consent_receipt_handle="x", application_id="graphify",
            workflow_id="qualify-graphify-v1", source_identity="Graphify-Labs/graphify",
            source_revision="0" * 40, source_catalog_artifact_id="x",
            source_catalog_sha256="0" * 64, manifest_paths=("pyproject.toml",),
            lock_paths=("uv.lock",), target_profile_id="hermes-agent-native-v1",
            namespace_selection_receipt_handle="x", principal_selection_receipt_handle=None,
            controller_binding_handle="x", expires_monotonic=100.0,
        )
