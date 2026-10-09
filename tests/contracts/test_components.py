from pathlib import Path
import pytest
from hermes_installer.components import ComponentCatalog, ComponentSpec
from hermes_installer.state import OwnedRoot

def test_full_skill_tree_is_private_immutable_and_not_discoverable_early(tmp_path:Path):
    src=tmp_path/"source"; (src/"skills"/"design").mkdir(parents=True); (src/"assets").mkdir()
    (src/"skills"/"design"/"SKILL.md").write_text("See ../../assets/palette.json")
    (src/"assets"/"palette.json").write_text('{"colors":["blue"]}')
    catalog=ComponentCatalog([ComponentSpec("design-pack","https://example.invalid/x","a"*40,aliases=("dp",))])
    root=OwnedRoot(tmp_path/"owned"); imported=catalog.import_skill("dp",src,root)
    assert imported.files==("assets/palette.json","skills/design/SKILL.md")
    assert (imported.destination/"assets"/"palette.json").exists()
    assert imported.source_resolved and not imported.discoverable
    discovered=catalog.mark_discovered(imported,lambda path:(path/"skills/design/SKILL.md").is_file())
    assert discovered.discoverable
    assert catalog.import_skill("dp",src,root).sha256==imported.sha256

def test_alias_conflict_symlink_and_unverified_app_fail_closed(tmp_path:Path):
    with pytest.raises(ValueError):ComponentCatalog([ComponentSpec("a","u","r",aliases=("same",)),ComponentSpec("b","u","r",aliases=("SAME",))])
    src=tmp_path/"src";src.mkdir(); outside=tmp_path/"outside";outside.write_text("secret")
    try:(src/"escape").symlink_to(outside)
    except OSError:pytest.skip("symlinks unavailable")
    root=OwnedRoot(tmp_path/"owned")
    with pytest.raises(ValueError):ComponentCatalog([ComponentSpec("a","u","r")]).import_skill("a",src,root)
    catalog=ComponentCatalog([ComponentSpec("app","u","r",kind="application")])
    assert not catalog.application_gate("app",{"network"},{"network"},dependencies_verified=False,arm64_verified=False,isolation_verified=False)[0]
