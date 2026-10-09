from pathlib import Path
import pytest
from hermes_installer.registry import RegistryResolver,Resource,ResourceKind
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.resolver import RegistryError

def res(name,requires=(),inherits=(),caps=()):return Resource(name,ResourceKind.PROFILE,"1.0",{}, "pin",tuple(requires),tuple(inherits),frozenset(caps))
def test_graph_missing_cycle_and_policy_fail_closed():
    resolver=RegistryResolver({"a":res("a",requires=("b",)),"b":res("b",caps=("home.write",))},host_capabilities={"home.write"})
    assert [r.id for r in resolver.resolve(["a"]) ]==["b","a"]
    assert resolver.authorize([resolver.resources["b"]],lambda *_:(False,"fresh Authentik lookup failed"))[0].capabilities==frozenset()
    with pytest.raises(RegistryError):resolver.resolve(["missing"])
    with pytest.raises(RegistryError):RegistryResolver({"a":res("a",requires=("b",)),"b":res("b",requires=("a",))}).resolve(["a"])
def test_nested_map_inherits_and_child_lists_replace():
    got=RegistryResolver.inherit({"config":{"a":1,"list":[1]}},{"config":{"b":2,"list":[3]}})
    assert got=={"config":{"a":1,"b":2,"list":[3]}}
def test_generation_activation_and_rollback(tmp_path:Path):
    store=GenerationStore(tmp_path)
    store.stage("one",{"runtime/config.json":b"{}"})
    assert store.activate("one") is None
    store.stage("two",{"runtime/config.json":b"{\"v\":2}"})
    assert store.activate("two")=="one"
    store.rollback("one")
    assert (tmp_path/"active").read_text().strip()=="one"
    with pytest.raises(ValueError):store.stage("bad",{"../escape":b"x"})
