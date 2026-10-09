from pathlib import Path
import pytest
from hermes_installer.registry.generation import GenerationError,GenerationStore
from hermes_installer.state import OwnedRoot

def test_owned_generation_switch_and_rollback(tmp_path:Path):
    owned=OwnedRoot(tmp_path/"installer"); store=GenerationStore(owned)
    store.stage("one",{"runtime/config.json":b"{}"})
    assert store.activate("one") is None
    store.stage("two",{"runtime/config.json":b'{"version":2}'})
    assert store.activate("two")=="one"
    store.rollback("one")
    assert (owned.root/"active-generation").read_text().strip()=="one"

def test_generation_rejects_escape_overwrite_symlink_and_tamper(tmp_path:Path):
    owned=OwnedRoot(tmp_path/"installer"); store=GenerationStore(owned)
    with pytest.raises(ValueError):store.stage("bad",{"../escape":b"x"})
    store.stage("one",{"data":b"original"})
    with pytest.raises(GenerationError):store.stage("one",{"data":b"replacement"})
    (owned.root/"generations"/"one"/"data").write_bytes(b"tampered")
    with pytest.raises(GenerationError):store.activate("one")
    with pytest.raises(ValueError):store.activate("../other")
    with pytest.raises(ValueError):store.rollback("../other")
