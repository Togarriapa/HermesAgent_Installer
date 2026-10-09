from pathlib import Path
import os
import pytest
from hermes_installer.registry.generation import GenerationError,GenerationStore
from hermes_installer.state import Journal,OwnedRoot

def make_store(root:Path):
    owned=OwnedRoot(root); owned.ensure()
    return owned,GenerationStore(owned,Journal(owned.path("installer-state.sqlite3")),mutation_locked=True)

def test_journaled_generation_switch_and_rollback(tmp_path:Path):
    owned,store=make_store(tmp_path/"installer")
    store.stage("one",{"runtime/config.json":b"{}"})
    assert store.activate("one") is None
    store.stage("two",{"runtime/config.json":b'{"version":2}'})
    assert store.activate("two")=="one"
    store.rollback("one")
    assert (owned.root/"active-generation").read_text().strip()=="one"

def test_generation_rejects_escape_overwrite_tamper_and_forged_manifest(tmp_path:Path):
    owned,store=make_store(tmp_path/"installer")
    with pytest.raises(ValueError):store.stage("bad",{"../escape":b"x"})
    store.stage("one",{"data":b"original"})
    with pytest.raises(GenerationError):store.stage("one",{"data":b"replacement"})
    (owned.root/"generations"/"one"/"data").write_bytes(b"tampered")
    with pytest.raises(GenerationError):store.activate("one")
    with pytest.raises(ValueError):store.activate("../other")
    with pytest.raises(ValueError):store.rollback("../other")

def test_foreign_pointer_and_journal_crash_reconcile(tmp_path:Path):
    owned,store=make_store(tmp_path/"installer")
    store.stage("one",{"data":b"ok"})
    store.journal.checkpoint("registry-generation:one","activation_prepared",{"manifest_digest":store._manifest_digest({"schema":1,"generation":"one","files":{"data":__import__("hashlib").sha256(b"ok").hexdigest()}}),"previous":None})
    pointer=owned.path("active-generation"); pointer.write_text("../foreign\n")
    with pytest.raises(ValueError):store.activate("one")
    pointer.unlink()
    store._write_pointer("one")
    assert store.recover_pointer_transaction()=="activation_reconciled"
    assert store.journal.operation("registry-generation:one")["status"]=="active"

def test_staged_files_are_private(tmp_path:Path):
    owned,store=make_store(tmp_path/"installer")
    store.stage("one",{"data":b"ok"})
    assert (owned.root/"generations"/"one"/"data").stat().st_mode & 0o077 == 0
