from __future__ import annotations

import os
import stat

import pytest

from hermes_installer.authority import filesystem_selection as fs


def _open_fixture_root():
    if os.geteuid() != 0 or not fs._linux():
        pytest.skip("fixed model-store observation is Linux-root-only")
    try:
        return fs._open_fixed_model_store_root()
    except fs.RootFilesystemSelectionDenied as exc:
        pytest.skip(f"disposable Linux fixture has no eligible pre-created model-store root: {exc}")


def test_fixed_root_is_opened_and_bound_to_live_inode():
    """Read-only contract test against an already provisioned disposable fixture."""
    fd = _open_fixture_root()
    try:
        info = os.fstat(fd)
        assert stat.S_ISDIR(info.st_mode)
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
        fs._verify_fd(fd, info.st_dev, info.st_ino, 0, 0, 0o700)
        with pytest.raises(fs.RootFilesystemSelectionDenied):
            fs._verify_fd(fd, info.st_dev, info.st_ino + 1, 0, 0, 0o700)
    finally:
        os.close(fd)
