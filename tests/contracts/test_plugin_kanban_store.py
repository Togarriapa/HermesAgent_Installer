from __future__ import annotations

import os

import pytest

from hermes_installer.components.plugin_kanban_store import BoardStoreError, SQLiteEpicBoardStore
from hermes_installer.state import OwnedRoot


def make_store(tmp_path, *, accepted=False):
    root=OwnedRoot(tmp_path / "installer-state")
    approvals=[]
    store=SQLiteEpicBoardStore(root, "profile_one",
        lambda profile, board, summary: approvals.append((profile, board, summary)) or accepted)
    return root, store, approvals


def test_private_sqlite_board_lifecycle_and_completion_summary_archive(tmp_path):
    _root, store, approvals=make_store(tmp_path, accepted=True)
    board=store.create("EPIC-42", "Ship installer")
    item=store.add_item(board, "task", "Implement", "Bounded description")
    assert store.read(board)["epic_id"] == "EPIC-42"
    attestation="attest-accepted-123"
    with pytest.raises(BoardStoreError, match="must be done"):
        store.delete_after_accepted_done(board, attestation)
    store.move_item(board, item["item_id"], "done")
    receipt=store.delete_after_accepted_done(board, attestation)
    assert receipt["receipt_id"]
    assert store.read(board) is None
    archived=store.accepted_summary(board)
    assert archived["summary"] == "accepted lifecycle attestation verified"
    assert approvals == [("profile_one", board, attestation)]
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_board_deletion_requires_trusted_acceptance_attestation(tmp_path):
    _, store, _=make_store(tmp_path, accepted=False)
    board=store.create("EPIC-7", "Do")
    item=store.add_item(board, "task", "Done", "")
    store.move_item(board, item["item_id"], "done")
    with pytest.raises(BoardStoreError, match="trusted accepted-completion"):
        store.delete_after_accepted_done(board, "attest-accepted-123")
    assert store.read(board) is not None


def test_one_board_per_epic_and_bad_paths_are_rejected(tmp_path):
    _root, store, _=make_store(tmp_path)
    store.create("E-1", "first")
    with pytest.raises(BoardStoreError, match="already exists"):
        store.create("E-1", "second")
    with pytest.raises(BoardStoreError, match="invalid board id"):
        store.read("../outside")


def test_profile_separation_and_invalid_item_schema(tmp_path):
    root=OwnedRoot(tmp_path / "installer-state")
    store1=SQLiteEpicBoardStore(root, "profile_one", lambda *_: True)
    store2=SQLiteEpicBoardStore(root, "profile_two", lambda *_: True)
    board=store1.create("E-2", "one")
    assert store2.read(board) is None
    with pytest.raises(BoardStoreError, match="item type"):
        store1.add_item(board, "exec", "x", "")


def test_database_symlink_is_rejected(tmp_path):
    root=OwnedRoot(tmp_path / "installer-state")
    root.ensure()
    target=tmp_path / "outside.sqlite"
    target.write_bytes(b"leave me")
    path=root.path("runtime/epic-boards/profile_one/boards.sqlite3")
    path.parent.mkdir(parents=True)
    path.symlink_to(target)
    with pytest.raises(BoardStoreError, match="path is unsafe"):
        SQLiteEpicBoardStore(root, "profile_one", lambda *_: True)
    assert target.read_bytes() == b"leave me"
