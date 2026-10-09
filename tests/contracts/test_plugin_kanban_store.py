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
    store.mutate(board, "add_item", {"id":"TASK-1", "type":"task", "title":"Implement", "state":"ready"})
    assert store.read(board)["epic_id"] == "EPIC-42"
    assert store.delete_after_accepted_done(board, "accepted by operator") is False
    store.mutate(board, "move_item", {"id":"TASK-1", "type":"task", "title":"Implement", "state":"done"})
    assert store.delete_after_accepted_done(board, "accepted by operator") is True
    assert store.read(board) is None
    archived=store.accepted_summary(board)
    assert archived["summary"] == "accepted by operator"
    assert approvals == [("profile_one", board, "accepted by operator")]
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_board_deletion_requires_trusted_acceptance_even_when_text_is_present(tmp_path):
    _, store, _=make_store(tmp_path, accepted=False)
    board=store.create("EPIC-7", "Do")
    store.mutate(board, "add_item", {"id":"T-1", "type":"task", "title":"Done", "state":"done"})
    with pytest.raises(BoardStoreError, match="trusted accepted-completion"):
        store.delete_after_accepted_done(board, "looks accepted")
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
    with pytest.raises(BoardStoreError, match="outside the Epic board schema"):
        store1.mutate(board, "add_item", {"id":"T", "type":"task", "title":"x", "state":"ready", "command":"rm"})


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
