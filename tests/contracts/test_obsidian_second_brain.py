"""Contract/effect coverage for the persistent Obsidian second-brain leaf.

These filesystem fixtures exercise leaf semantics only; the Pi run separately
proves ROOT's native binding, persistent managed path, and actual Hermes effects.
"""
from __future__ import annotations

import hashlib
import json
import time

import pytest

from hermes_installer.remote.obsidian_second_brain import (
    ObsidianVaultConfig,
    ObsidianVaultConflict,
    ObsidianVaultError,
    ObsidianVaultStore,
    prepare_obsidian_vault,
)


OWNER = "a" * 64


def _store(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))


def test_vault_preparation_is_idempotent_and_preserves_existing_obsidian_files(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    vault = root / "obsidian-vault"
    vault.mkdir(mode=0o700)
    (vault / "Notes").mkdir(mode=0o700)
    note = vault / "Notes" / "existing.md"
    note.write_text("# Existing\nKeep these bytes.\n", encoding="utf-8")
    settings = vault / ".obsidian"
    settings.mkdir(mode=0o700)
    config = settings / "app.json"
    config.write_text('{"alwaysUpdateLinks":true}\n', encoding="utf-8")

    first = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    second = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))

    assert first._root == second._root == vault
    assert note.read_text(encoding="utf-8") == "# Existing\nKeep these bytes.\n"
    assert config.read_text(encoding="utf-8") == '{"alwaysUpdateLinks":true}\n'
    assert all((vault / name).is_dir() for name in ("Projects", "Sources", "Daily"))


def test_current_markdown_search_backlinks_and_graph_resolve_real_links(tmp_path):
    store = _store(tmp_path / "managed")
    (store._root / "Notes" / "Alpha.md").write_text(
        "---\ntitle: Alpha note\ntags: [garden, seed]\naliases: [A note]\n---\n"
        "Read [[Beta|the other note]] and [a local note](Beta.md). "
        "Ignore [the web](https://example.org). <script>text</script>\n",
        encoding="utf-8")
    (store._root / "Notes" / "Beta.md").write_text(
        "# Beta\nA real note.\n", encoding="utf-8")
    (store._root / "Notes" / "Gamma.md").write_text(
        "Unresolved [[missing note]].\n", encoding="utf-8")

    page = store.search_notes("garden", limit=10)
    alpha = next(note for note in page.notes if note.title == "Alpha note")
    links = store.links_for(alpha.note_id)
    graph = store.graph_snapshot().to_projection()

    assert alpha.tags == ("garden", "seed")
    assert len(links.links) == 2
    assert links.links[0].kind == "wikilink"
    assert {link.kind for link in links.links} == {"wikilink", "markdown"}
    assert len(links.backlinks) == 0
    assert any(row["label"] == "missing note" for row in graph["unresolved"])
    assert len(graph["nodes"]) == 3 and len(graph["edges"]) == 2
    assert "<script>" in store.read_note(alpha.note_id).markdown


def test_expert_note_scope_and_execution_private_draft_do_not_escape_owner_projection(tmp_path):
    store = _store(tmp_path / "managed")
    (store._root / "Notes" / "OwnerOnly.md").write_text("Private owner note.\n", encoding="utf-8")
    note = store.list_notes().notes[0]
    draft = store.create_private_draft(
        execution_id="mission_run_123", source_instance_id="expert_alpha",
        title="Suggested knowledge", markdown="# Suggested knowledge\nDraft only.\n",
        citations=(f"note:{note.note_id}",),
    )

    assert store.search_notes("Draft only").notes == ()
    assert all(row["title"] != draft.title for row in store.graph_snapshot().nodes)
    assert store.dashboard_projection()["draftCount"] == 1
    assert store.read_private_draft(execution_id="mission_run_123",
                                    draft_id=draft.draft_id)["state"] == "private-draft"
    with pytest.raises(ObsidianVaultError, match="unavailable|present"):
        store.read_private_draft(execution_id="mission_run_other",
                                 draft_id=draft.draft_id)
    with pytest.raises(ObsidianVaultError, match="outside the admitted"):
        store.read_note(note.note_id, note_scope=frozenset())
    scoped = store.list_notes(note_scope=frozenset({note.note_id}))
    assert [row.note_id for row in scoped.notes] == [note.note_id]
    assert scoped.partial is True


def test_symlinked_note_directory_and_traversal_are_not_read_or_written(tmp_path):
    store = _store(tmp_path / "managed")
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (outside / "escape.md").write_text("outside", encoding="utf-8")
    (store._root / "Notes" / "linked").symlink_to(outside, target_is_directory=True)

    assert store.list_notes().notes == ()
    with pytest.raises(ObsidianVaultError, match="normalized relative"):
        store._atomic_note_write("../outside.md", b"no", expected_sha256=None)
    with pytest.raises(ObsidianVaultError, match="hidden"):
        store._atomic_note_write(".hermes-private/drafts/no.md", b"no", expected_sha256=None)
    assert (outside / "escape.md").read_text(encoding="utf-8") == "outside"


def test_stale_external_edit_keeps_owner_bytes_and_reviewed_draft(tmp_path):
    store = _store(tmp_path / "managed")
    target = store._root / "Notes" / "Target.md"
    target.write_text("# Target\nOwner version.\n", encoding="utf-8")
    base_id = store.list_notes().notes[0].note_id
    base_sha = hashlib.sha256(target.read_bytes()).hexdigest()
    draft = store.create_private_draft(
        execution_id="mission_run_456", source_instance_id="expert_alpha",
        title="Target", markdown="# Target\nExpert proposal.\n",
        base_note_id=base_id, base_sha256=base_sha,
    )
    target.write_text("# Target\nConcurrent Obsidian edit.\n", encoding="utf-8")

    args = {
        "execution_id": "mission_run_456", "draft_id": draft.draft_id,
        "expected_draft_sha256": draft.content_sha256, "destination": "Notes/Target.md",
        "expected_base_sha256": base_sha,
    }
    observed, permit = _root_effect_proof(args, OWNER)
    from unittest.mock import patch
    from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments

    canonical = canonical_tool_arguments(args)
    dispatch = NativeToolDispatch(object(), observed.tool_call_id,
                                  "obsidian_promote_reviewed_draft", canonical)
    with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
               return_value=dispatch):
        with pytest.raises(ObsidianVaultConflict, match="changed after review"):
            store.promote_reviewed_draft(**args, observed_call=observed, permit=permit)

    assert "Concurrent Obsidian edit" in target.read_text(encoding="utf-8")
    assert store.read_private_draft(execution_id="mission_run_456",
                                    draft_id=draft.draft_id)["state"] == "private-draft"


def test_promotion_requires_exact_typed_root_permit_and_current_dispatch(tmp_path):
    store = _store(tmp_path / "managed")
    draft = store.create_private_draft(
        execution_id="mission_run_789", source_instance_id="jarvis",
        title="Reviewed", markdown="# Reviewed\nExact bytes.\n",
    )
    args = {
        "execution_id": "mission_run_789", "draft_id": draft.draft_id,
        "expected_draft_sha256": draft.content_sha256, "destination": "Notes/Reviewed.md",
        "expected_base_sha256": None,
    }
    observed, permit = _root_effect_proof(args, OWNER)
    from unittest.mock import patch
    from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments

    canonical = canonical_tool_arguments(args)
    dispatch = NativeToolDispatch(object(), observed.tool_call_id,
                                  "obsidian_promote_reviewed_draft", canonical)
    with pytest.raises(ObsidianVaultError, match="exact current root owner permit"):
        store.promote_reviewed_draft(**args, observed_call={}, permit={})
    with patch("hermes_installer.native_invocations.current_native_tool_dispatch",
               return_value=dispatch):
        saved = store.promote_reviewed_draft(**args, observed_call=observed, permit=permit)

    assert saved.markdown == "# Reviewed\nExact bytes.\n"
    assert (store._root / "Notes" / "Reviewed.md").read_text(encoding="utf-8") == saved.markdown
    assert store.read_private_draft(execution_id="mission_run_789",
                                    draft_id=draft.draft_id)["state"] == "promoted"


def test_backup_restore_preserves_notes_obsidian_settings_and_private_drafts(tmp_path):
    source = _store(tmp_path / "source-managed")
    (source._root / "Notes" / "Durable.md").write_text("# Durable\nKeep me.\n", encoding="utf-8")
    (source._root / ".obsidian" / "app.json").write_text(
        '{"legacyEditor":false}\n', encoding="utf-8")
    draft = source.create_private_draft(
        execution_id="mission_backup", source_instance_id="expert_beta",
        title="Private", markdown="# Private\nKeep this review.\n",
    )
    snapshot = source.create_backup()
    restored = _store(tmp_path / "restore-managed")

    count = restored.restore_backup(snapshot)

    assert count >= 3
    assert restored.search_notes("Keep me").notes[0].title == "Durable"
    assert (restored._root / ".obsidian" / "app.json").read_text(encoding="utf-8") == '{"legacyEditor":false}\n'
    assert restored.read_private_draft(execution_id="mission_backup",
                                       draft_id=draft.draft_id)["contentSha256"] == draft.content_sha256


def test_backup_restore_refuses_to_overwrite_existing_external_note(tmp_path):
    source = _store(tmp_path / "source-managed")
    (source._root / "Notes" / "Shared.md").write_text("# Shared\nOriginal.\n", encoding="utf-8")
    snapshot = source.create_backup()
    restored = _store(tmp_path / "restore-managed")
    target = restored._root / "Notes" / "Shared.md"
    target.write_text("# Shared\nExternal edit.\n", encoding="utf-8")

    with pytest.raises(ObsidianVaultConflict, match="restore target settings conflict"):
        restored.restore_backup(snapshot)

    assert target.read_text(encoding="utf-8") == "# Shared\nExternal edit.\n"


def test_journal_recovery_classifies_an_uncommitted_note_write(tmp_path):
    store = _store(tmp_path / "managed")
    proposed = b"# Recovered\n"
    relative = "Notes/Recovered.md"
    journal_path = "revisions/00000000000000000001-recovery.json"
    store._write_private(journal_path, json.dumps({
        "schema": 1, "ownerScopeSha256": OWNER, "relativePath": relative,
        "priorSha256": None, "priorBase64": None,
        "proposedSha256": hashlib.sha256(proposed).hexdigest(), "state": "prepared",
    }, sort_keys=True, separators=(",", ":")).encode(), create_only=True)

    report = store.recover_journal()
    record = json.loads(store._read_private(journal_path, 2 * 1024 * 1024))

    assert report["rolledBack"] == 1
    assert record["state"] == "rolled-back"
    assert not (store._root / relative).exists()


def test_private_drafts_reject_group_or_world_readable_existing_directory(tmp_path):
    root = tmp_path / "managed"
    store = _store(root)
    (store._root / ".hermes-private").chmod(0o755)

    with pytest.raises(ObsidianVaultError, match="owner-only"):
        store.create_private_draft(
            execution_id="mission_secure", source_instance_id="expert_alpha",
            title="No leakage", markdown="# No leakage\n",
        )


def _root_effect_proof(arguments, owner):
    import hashlib

    from hermes_installer.native_invocations import canonical_tool_arguments
    from hermes_installer.remote.core_native_observer import ObservedNativeToolCall
    from hermes_installer.remote.jarvis_final_effects import FinalEffectPermit, review_digest

    name = "obsidian_promote_reviewed_draft"
    digest = hashlib.sha256(canonical_tool_arguments(arguments)).hexdigest()
    observed = ObservedNativeToolCall(
        handle="B" * 43, attempt_handle="C" * 43, owner_turn_handle="D" * 43,
        tool_call_id="obsidian-call-1", tool_name=name, arguments_sha256=digest,
        expires_monotonic=time.monotonic() + 20,
    )
    review = review_digest(name, digest)
    permit = FinalEffectPermit(
        pending_id="E" * 43, owner_turn_handle=observed.owner_turn_handle,
        gateway_turn_id="turn-obsidian-1", owner_subject_sha256=owner,
        core_generation="f" * 64, core_source_generation="1" * 64,
        source_generation_sha256="2" * 64, source_profile_id="hermes",
        tool_call_id=observed.tool_call_id, tool_name=name,
        arguments_sha256=digest, review_sha256=review,
        expires_monotonic=time.monotonic() + 10,
    )
    return observed, permit
