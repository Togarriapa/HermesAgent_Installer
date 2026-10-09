"""Pinned, local-only ScrapeGraphAI functional fixture.

The fixture invokes the selected upstream ``SmartScraperGraph`` and its real
Fetch/Parse/GenerateAnswer node chain in the component's isolated Python. The
only model is an in-process LangChain test double injected through the
upstream-supported ``llm.model_instance`` constructor seam. No cloud smart-
scraper API, MCP service, credentials, or metered route is involved.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Mapping

from hermes_installer.components.application_handlers import ComponentInvocation
from hermes_installer.components.runtime_source import VerifiedComponentGeneration


SOURCE_REVISION = "194055e203afce41ed4e70365dbc416bad756115"
SOURCE_IDENTITY = "ScrapeGraphAI/Scrapegraph-ai"
SOURCE_SHA256: Mapping[str, str] = {
    "pyproject.toml": "c88e138a741bcac006d58dd41303c4a68b48f925b929067af4b43c04bfd5b886",
    "uv.lock": "2fd36ae40e1eda563043b7204bd32755b67078abc471c8cf29f3f48c9c309771",
    "scrapegraphai/graphs/smart_scraper_graph.py": "1e9cd02492172c3ea629b8745d685203776351afe3f783458a5f33e1acd706dc",
}
FIXTURE_NAME = "scrapegraph-r0093.html"
FIXTURE_HTML = (
    "<!doctype html><html><body><article>"
    "<h1>Cedar Mug</h1><span class=\"price\">$18.50</span>"
    "</article></body></html>\n"
)
FIXTURE_SHA256 = hashlib.sha256(FIXTURE_HTML.encode("utf-8")).hexdigest()
PROOF_MARKER = "HERMES_SCRAPEGRAPH_AI_PROOF="


class ScrapeGraphFixtureError(ValueError):
    """The selected pinned source or fixture cannot establish local behavior."""


def _absolute(value: str, label: str) -> Path:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise ScrapeGraphFixtureError(f"{label} must be a normalized absolute path")
    return Path(path.as_posix())


def _private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
        canonical = path.resolve(strict=True)
    except OSError:
        raise ScrapeGraphFixtureError(f"{label} must already exist") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or canonical != path):
        raise ScrapeGraphFixtureError(f"{label} must be a canonical private owned directory")


def _read_regular(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ScrapeGraphFixtureError(f"{label} must be an owned regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_ino != info.st_ino or opened.st_dev != info.st_dev
                    or not stat.S_ISREG(opened.st_mode)):
                raise ScrapeGraphFixtureError(f"{label} changed during verification")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(32 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ScrapeGraphFixtureError(f"{label} cannot be safely read: {exc}") from None


def verify_scrapegraph_source(source_root: str) -> Path:
    """Require the exact upstream files whose bytes were reviewed in the ledger."""
    root = _absolute(source_root, "ScrapeGraphAI source root")
    _private_directory(root, "ScrapeGraphAI source root")
    for relative, expected in SOURCE_SHA256.items():
        body = _read_regular(root / relative, f"pinned ScrapeGraphAI file {relative}")
        if len(body) > 32 * 1024 * 1024 or hashlib.sha256(body).hexdigest() != expected:
            raise ScrapeGraphFixtureError(f"pinned ScrapeGraphAI file digest mismatch: {relative}")
    return root


def stage_scrapegraph_ai_fixture(work_root: str) -> Path:
    """Stage one fixed owned HTML fixture in a trusted private work directory."""
    root = _absolute(work_root, "ScrapeGraphAI work root")
    _private_directory(root, "ScrapeGraphAI work root")
    fixture = root / FIXTURE_NAME
    body = FIXTURE_HTML.encode("utf-8")
    try:
        fd = os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o444)
    except FileExistsError:
        existing = _read_regular(fixture, "ScrapeGraphAI fixture")
        info = fixture.lstat()
        if info.st_mode & 0o222 or existing != body:
            raise ScrapeGraphFixtureError("ScrapeGraphAI fixture conflicts with fixed fixture content")
    except OSError as exc:
        raise ScrapeGraphFixtureError(f"ScrapeGraphAI fixture cannot be staged: {exc}") from None
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    _stage_private_file(root / ".scrapegraphai.conf",
                        b"[DEFAULT]\ntelemetry_enabled = false\nanonymous_id = hermes-r0093-fixture\n")
    return fixture


def _stage_private_file(path: Path, content: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        existing = _read_regular(path, "ScrapeGraphAI fixture configuration")
        info = path.lstat()
        if info.st_mode & 0o077 or existing != content:
            raise ScrapeGraphFixtureError("ScrapeGraphAI fixture configuration conflicts")
    except OSError as exc:
        raise ScrapeGraphFixtureError(f"ScrapeGraphAI fixture configuration cannot be staged: {exc}") from None
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())


def _probe_source() -> str:
    # This code deliberately lives in the installer source and takes only the
    # two trusted roots bound by the builder. It cannot select a provider,
    # source URL, model name, output path, or command from the request.
    return r'''import hashlib, json, pathlib, socket, sys
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
if hashlib.sha256(html.encode()).hexdigest() != "''' + FIXTURE_SHA256 + r'''":
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
    "source_revision": "194055e203afce41ed4e70365dbc416bad756115",
    "upstream_class": "scrapegraphai.graphs.SmartScraperGraph",
    "upstream_source": str(pathlib.Path(scrapegraphai.__file__).resolve()),
    "nodes": nodes, "source_kind": "local_dir", "local_fetch_calls": len(fetch_observations),
    "model": "allowlisted-fixture-mock",
    "model_calls": len(model.observed_prompts), "observed_fixture_values": True,
    "structured_result": answer, "network_attempts": 0, "telemetry_enabled": False,
    "metered_cost_usd": 0,
}, sort_keys=True))
'''


def build_scrapegraph_ai_fixture_invocation(
    python_executable: str, source_generation: VerifiedComponentGeneration, work_root: str,
) -> ComponentInvocation:
    """Build the fixture only from a full, journal-owned pinned source generation."""
    python = _absolute(python_executable, "ScrapeGraphAI Python executable")
    if (not isinstance(source_generation, VerifiedComponentGeneration)
            or source_generation.component_id != "scrapegraph-ai"
            or source_generation.source_identity != SOURCE_IDENTITY
            or source_generation.revision != SOURCE_REVISION):
        raise ScrapeGraphFixtureError("ScrapeGraphAI runtime requires its selected verified source generation")
    source = verify_scrapegraph_source(str(source_generation.verify()))
    fixture = stage_scrapegraph_ai_fixture(work_root)
    work = _absolute(work_root, "ScrapeGraphAI work root")
    return ComponentInvocation(
        component_id="scrapegraph-ai",
        executable=str(python),
        argv=(str(python), "-c", _probe_source(), str(source), str(fixture)),
        cwd=str(work),
        environment=(("HOME", str(_absolute(work_root, "ScrapeGraphAI work root"))),
                     ("PYTHONNOUSERSITE", "1"),
                     ("SCRAPEGRAPHAI_TELEMETRY_ENABLED", "false")),
        credential_references=(),
        capability_scopes=("component.scrapegraph-ai.read-fixture",
                           "component.scrapegraph-ai.fixture-model"),
        sensitivity="PRIVATE",
        network="deny",
        timeout_seconds=45,
        memory_limit_mb=1024,
    )


def verify_scrapegraph_ai_fixture_result(result: object) -> dict[str, object]:
    """Accept only an explicit successful proof from the pinned upstream graph."""
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise ScrapeGraphFixtureError("ScrapeGraphAI local fixture process failed")
    output = result.get("stdout")
    if not isinstance(output, str):
        raise ScrapeGraphFixtureError("ScrapeGraphAI fixture returned no structured proof")
    records = [line[len(PROOF_MARKER):] for line in output.splitlines()
               if line.startswith(PROOF_MARKER)]
    if len(records) != 1:
        raise ScrapeGraphFixtureError("ScrapeGraphAI fixture proof is missing or ambiguous")
    try:
        proof = json.loads(records[0])
    except json.JSONDecodeError as exc:
        raise ScrapeGraphFixtureError("ScrapeGraphAI fixture proof is invalid JSON") from exc
    expected = {
        "source_revision": SOURCE_REVISION,
        "upstream_class": "scrapegraphai.graphs.SmartScraperGraph",
        "nodes": ["Fetch", "GenerateAnswer"],
        "source_kind": "local_dir",
        "local_fetch_calls": 1,
        "model": "allowlisted-fixture-mock",
        "model_calls": 1,
        "observed_fixture_values": True,
        "structured_result": {"name": "Cedar Mug", "price": "$18.50"},
        "network_attempts": 0,
        "telemetry_enabled": False,
        "metered_cost_usd": 0,
    }
    if not isinstance(proof, dict) or any(proof.get(k) != v for k, v in expected.items()):
        raise ScrapeGraphFixtureError("ScrapeGraphAI proof does not establish the required local graph effects")
    source = proof.get("upstream_source")
    if not isinstance(source, str) or not Path(source).is_absolute():
        raise ScrapeGraphFixtureError("ScrapeGraphAI proof does not identify its imported upstream source")
    return proof


async def run_scrapegraph_ai_fixture(
    supervisor: object, python_executable: str,
    source_generation: VerifiedComponentGeneration, work_root: str,
) -> dict[str, object]:
    """Run and verify through the injected managed component supervisor."""
    invocation = build_scrapegraph_ai_fixture_invocation(
        python_executable, source_generation, work_root,
    )
    invoke = getattr(supervisor, "invoke", None)
    if not callable(invoke):
        raise TypeError("managed component supervisor must provide invoke")
    result = await invoke(invocation)
    return verify_scrapegraph_ai_fixture_result(result)
