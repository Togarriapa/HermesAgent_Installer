from __future__ import annotations

import os
import stat

import pytest

from hermes_installer.authority.filesystem_selection import (
    RootFilesystemSelectionDenied,
    _open_root_owned_directory,
)


def test_explicit_existing_directory_is_opened_and_bound_to_inode(tmp_path):
    selected = tmp_path / "existing-model-store"
    selected.mkdir(mode=0o700)

    fd = _open_root_owned_directory(selected, expected_uid=os.geteuid())
    try:
        selected_info = selected.stat(follow_symlinks=False)
        held_info = os.fstat(fd)
        assert stat.S_ISDIR(held_info.st_mode)
        assert (held_info.st_dev, held_info.st_ino) == (selected_info.st_dev, selected_info.st_ino)
        assert held_info.st_uid == os.geteuid()
        assert stat.S_IMODE(held_info.st_mode) == 0o700
    finally:
        os.close(fd)


def test_model_store_root_rejects_symlink_and_group_writable_leaf(tmp_path):
    selected = tmp_path / "existing-model-store"
    selected.mkdir(mode=0o700)
    link = tmp_path / "model-store-link"
    link.symlink_to(selected, target_is_directory=True)

    with pytest.raises(RootFilesystemSelectionDenied):
        _open_root_owned_directory(link, expected_uid=os.geteuid())

    selected.chmod(0o770)
    with pytest.raises(RootFilesystemSelectionDenied):
        _open_root_owned_directory(selected, expected_uid=os.geteuid())


def test_model_store_root_rejects_root_and_dotdot(tmp_path):
    with pytest.raises(RootFilesystemSelectionDenied):
        _open_root_owned_directory(tmp_path / "..", expected_uid=os.geteuid())
    with pytest.raises(RootFilesystemSelectionDenied):
        _open_root_owned_directory(tmp_path.anchor, expected_uid=os.geteuid())
