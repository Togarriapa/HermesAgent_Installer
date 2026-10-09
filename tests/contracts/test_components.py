from pathlib import Path
import pytest
from hermes_installer.components import ComponentCatalog,ComponentSpec

def test_full_skill_tree_and_relative_asset_survive_import(tmp_path:Path):
    src=tmp_path/"source"; (src/"skills"/"design").mkdir(parents=True); (src/"assets").mkdir()
    (src/"skills"/"design"/"SKILL.md").write_text("See ../../assets/palette.json")
    (src/"assets"/"palette.json").write_text('{"colors":["blue"]}')
    catalog=ComponentCatalog([ComponentSpec("design-pack","https://example.invalid/x","a"*40,aliases=("dp",))])
    result=catalog.import_skill("dp",src,tmp_path/"installed")
    assert result.files==("assets/palette.json","skills/design/SKILL.md")
    assert (result.destination/"assets"/"palette.json").exists()
    assert result.discoverable and result.hook_status=="instruction_only"
def test_alias_collision_and_symlinks_fail(tmp_path:Path):
    with pytest.raises(ValueError):ComponentCatalog([ComponentSpec("a","u","r",aliases=("same",)),ComponentSpec("b","u","r",aliases=("SAME",))])
    src=tmp_path/"src"; src.mkdir(); outside=tmp_path/"outside"; outside.write_text("secret")
    try:(src/"escape").symlink_to(outside)
    except OSError:pytest.skip("symlinks unavailable")
    catalog=ComponentCatalog([ComponentSpec("a","u","r")])
    with pytest.raises(ValueError):catalog.import_skill("a",src,tmp_path/"out")
def test_application_is_gated_by_capability_and_on_demand(tmp_path:Path):
    catalog=ComponentCatalog([ComponentSpec("app","u","r",kind="application")])
    assert catalog.application_gate("app",{"network"},set())[0] is False
    assert catalog.application_gate("app",{"network"},{"network"})[0] is True
