import hashlib, json, pathlib, socket, sys
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import os
os.environ["SCRAPEGRAPHAI_TELEMETRY_ENABLED"] = "false"
source_root = pathlib.Path(sys.argv[1]).resolve(strict=True)
fixture_path = pathlib.Path(sys.argv[2]).resolve(strict=True)
expected_source = {
    "pyproject.toml": "c88e138a741bcac006d58dd41303c4a68b48f925b929067af4b43c04bfd5b886",
    "uv.lock": "2fd36ae40e1eda563043b7204bd32755b67078abc471c8cf29f3f48c9c309771",
    "scrapegraphai/graphs/smart_scraper_graph.py": "1e9cd02492172c3ea629b8745d685203776351afe3f783458a5f33e1acd706dc",
}
for relative, digest in expected_source.items():
    if hashlib.sha256((source_root / relative).read_bytes()).hexdigest() != digest:
        raise RuntimeError("pinned source changed: " + relative)
html = fixture_path.read_text(encoding="utf-8")
if hashlib.sha256(html.encode()).hexdigest() != "d84bb550cc5d5d43ce04b7172d6df3e32925f7ff85f98b746b58d60f803b9cdf":
    raise RuntimeError("local fixture digest mismatch")

# Block any actual socket use, including accidental telemetry or a redirect.
def deny_network(*args, **kwargs):
    raise AssertionError("network access attempted during local ScrapeGraphAI fixture")
socket.socket.connect = deny_network
socket.create_connection = deny_network

sys.path.insert(0, str(source_root))
import scrapegraphai
from scrapegraphai.graphs import SmartScraperGraph
from scrapegraphai.telemetry import telemetry as telemetry_module

telemetry_module.disable_telemetry()
if pathlib.Path(scrapegraphai.__file__).resolve().is_relative_to(source_root) is False:
    raise RuntimeError("SmartScraperGraph did not import from the pinned source tree")

class Product(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    price: str

class FixtureModel(BaseChatModel):
    observed_prompts: list[str] = Field(default_factory=list)
    @property
    def _llm_type(self) -> str:
        return "allowlisted-local-fixture-mock"
    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: Any = None, **kwargs: Any) -> ChatResult:
        prompt = "\n".join(str(message.content) for message in messages)
        self.observed_prompts.append(prompt)
        if "Cedar Mug" not in prompt or "$18.50" not in prompt:
            raise AssertionError("real upstream model boundary did not receive fixture HTML")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(
            content='{"name":"Cedar Mug","price":"$18.50"}'))])

model = FixtureModel()
graph = SmartScraperGraph(
    "Extract the product name and price from this local page.",
    html,
    {"llm": {"model": "allowlisted/fixture-mock", "model_instance": model,
             "model_tokens": 512}, "html_mode": True, "verbose": False,
     "timeout": 5, "reattempt": False},
    schema=Product,
)
if not isinstance(graph, SmartScraperGraph):
    raise RuntimeError("upstream SmartScraperGraph instance missing")
if graph.input_key != "local_dir":
    raise RuntimeError("upstream SmartScraperGraph selected a non-local input path")
nodes = [node.node_name for node in graph.graph.nodes]
if nodes != ["Fetch", "GenerateAnswer"]:
    raise RuntimeError("upstream graph/node chain differs from reviewed local extraction")
fetch = graph.graph.nodes[0]
original_fetch_execute = fetch.execute
fetch_observations = []
def observe_local_fetch(state):
    if state.get("local_dir") != html or "url" in state:
        raise AssertionError("upstream FetchNode did not receive the owned local HTML")
    fetch_observations.append(True)
    return original_fetch_execute(state)
fetch.execute = observe_local_fetch
result = graph.run()
answer = graph.final_state.get("answer")
if answer != {"name": "Cedar Mug", "price": "$18.50"}:
    raise RuntimeError("upstream graph returned wrong or incomplete structured fields")
if not model.observed_prompts or len(model.observed_prompts) != 1:
    raise RuntimeError("allowlisted mock model boundary was not called exactly once")
if fetch_observations != [True]:
    raise RuntimeError("actual upstream FetchNode did not execute once on the local fixture")
if not isinstance(result, dict) or result != answer:
    raise RuntimeError("SmartScraperGraph.run did not return the structured result")
if any(float(item.get("total_cost_USD", 0)) != 0 for item in graph.execution_info):
    raise RuntimeError("fixture unexpectedly reported metered model cost")
if telemetry_module.g_telemetry_enabled:
    raise RuntimeError("ScrapeGraphAI telemetry must remain disabled for the private fixture")
print("HERMES_SCRAPEGRAPH_AI_PROOF=" + json.dumps({
    "schema_version": 1,
    "source_revision": "194055e203afce41ed4e70365dbc416bad756115",
    "upstream_class": "scrapegraphai.graphs.SmartScraperGraph",
    "upstream_source": str(pathlib.Path(scrapegraphai.__file__).resolve()),
    "nodes": nodes, "source_kind": "local_dir", "local_fetch_calls": len(fetch_observations),
    "model": "allowlisted-fixture-mock",
    "model_calls": len(model.observed_prompts), "observed_fixture_values": True,
    "structured_result": answer, "network_attempts": 0, "telemetry_enabled": False,
    "metered_cost_usd": 0,
}, sort_keys=True))
