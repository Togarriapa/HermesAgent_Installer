from __future__ import annotations

import os
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.root_memory_service_enablement import (
    RootMemoryServiceEnablementDenied,
    RootMemoryServiceEnablementRegistry,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.protected_enrollment import (
    ProtectedRootJournalCatalog, RootJournalSelection,
)


ROOT_LINUX = pytest.mark.skipif(
    not (os.name == "posix" and os.uname().sysname == "Linux" and os.geteuid() == 0),
    reason="root-owned active journal fixture requires isolated Linux root",
)


def _registry(tmp_path: Path, *, digest: str = "a" * 64):
    root = tmp_path / "root-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    info = root.stat()
    journal_catalog = ProtectedRootJournalCatalog.from_protected_records([{
        "root_id": "authority-journal", "absolute_path": str(root.resolve()),
        "owner_uid": 0, "owner_gid": info.st_gid, "mode": 0o700,
        "device": info.st_dev, "inode": info.st_ino, "generation": "fixture-generation",
        "purpose": "authority-journal",
    }], generation_digest=digest)
    journal = RootJournalSelection("authority-journal", root, info.st_dev, info.st_ino,
                                   "fixture-generation", digest)
    # This intentionally lacks any protected memory selector. It exercises the
    # public fail-closed boundary, not a fabricated positive authority receipt.
    bindings = RootRuntimeBindings(
        enrollment_catalog=SimpleNamespace(digest=digest), build_catalog=None,
        device_catalog=None, process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=None, build_store=None, service_connector=None,
        root_journal_catalog=journal_catalog,
    )
    return RootMemoryServiceEnablementRegistry.from_root_runtime(
        bindings, object(), journal,
    )


@ROOT_LINUX
def test_lifecycle_selection_is_unavailable_without_active_published_choice():
    # /tmp is intentionally rejected by ProtectedRootJournalCatalog because
    # its ancestor is writable by other users. Keep the test fixture under a
    # private root-owned ancestor rather than weakening production custody.
    with TemporaryDirectory(prefix="hermes-memory-enable-", dir="/root") as directory:
        registry = _registry(Path(directory))
        with pytest.raises(RootMemoryServiceEnablementDenied,
                           match="current root memory service enablement is unavailable"):
            registry.resolve_selected_enablement("memory-fixture")


@ROOT_LINUX
def test_lifecycle_selection_rejects_journal_from_another_active_generation(tmp_path: Path):
    root = tmp_path / "root-journal"
    root.mkdir(mode=0o700)
    info = root.stat()
    journal = RootJournalSelection("authority-journal", root, info.st_dev, info.st_ino,
                                   "fixture-generation", "b" * 64)
    bindings = RootRuntimeBindings(
        enrollment_catalog=SimpleNamespace(digest="a" * 64), build_catalog=None,
        device_catalog=None, process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=None, build_store=None, service_connector=None,
    )

    with pytest.raises(RootMemoryServiceEnablementDenied,
                       match="active root runtime and matching root journal"):
        RootMemoryServiceEnablementRegistry.from_root_runtime(bindings, object(), journal)
