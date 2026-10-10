"""R0092 fixture against the exact upstream app and mocked OpenAI SDK transport.

Set HERMES_SCREENSHOT_TO_CODE_SOURCE to a full checkout of the pinned commit
and HERMES_SCREENSHOT_TO_CODE_PYTHON to its isolated Poetry interpreter. The
test never falls back to a hand-written parser or a live provider.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.screenshot_to_code import (
    SOURCE_IDENTITY,
    SOURCE_REVISION,
    HostCredentialReference,
    ScreenshotToCodeError,
    VisionRoute,
    resolve_vision_route,
    review_screenshot_to_code_files,
    validate_vision_route,
)
from hermes_installer.components.screenshot_to_code_probe import (
    ProbeResultError,
    validate_upstream_events,
)


FIXTURE_IMAGE = Path(__file__).parents[1] / "fixtures" / "screenshot_to_code_probe.png"
FIXTURE_MANIFEST = FIXTURE_IMAGE.with_suffix(".json")


def test_fixed_probe_asset_matches_its_role_manifest():
    image = FIXTURE_IMAGE.read_bytes()
    manifest = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema"] == "hermes-screenshot-to-code-fixture-asset-v1"
    assert manifest["sha256"] == hashlib.sha256(image).hexdigest()
    assert manifest["size_bytes"] == len(image)
    assert manifest["dimensions_px"] == {"width": 640, "height": 360}
    assert manifest["member_roles"] == [
        "synthetic-input-screenshot", "local-fixture-only", "not-user-content", "not-a-runtime-receipt",
    ]
    assert manifest["live_provider_dispatch"] is False
    assert manifest["metered_budget_default"] == 0


def test_strict_fixture_result_requires_generated_code_and_successful_variant():
    image = FIXTURE_IMAGE.read_bytes()
    valid = [
        {"type": "setCode", "value": "<!doctype html><main>fixture</main>", "variantIndex": 0},
        {"type": "variantComplete", "value": "Variant generation complete", "variantIndex": 0},
    ]
    result = validate_upstream_events(valid, fixture_image=image, route_id="openai-gpt-5.5")
    assert result.evidence_kind == "local-synthetic-fixture-with-mocked-provider-transport"
    assert result.fixture_image_sha256 == hashlib.sha256(image).hexdigest()
    assert result.generated_code_sha256 == hashlib.sha256(valid[0]["value"].encode()).hexdigest()
    assert result.completed_variants == (0,)

    for invalid in (
        [{"type": "variantComplete", "variantIndex": 0}],
        [*valid, {"type": "variantError", "variantIndex": 0}],
        [{"type": "setCode", "value": "ok", "variantIndex": True}, valid[1]],
        [{"type": "setCode", "value": "ok", "variantIndex": 0, "extra": "unexpected"}, valid[1]],
    ):
        with pytest.raises(ProbeResultError):
            validate_upstream_events(invalid, fixture_image=image, route_id="openai-gpt-5.5")


def test_text_only_or_unreviewed_vision_route_is_denied_before_image_processing():
    for provider, model in (
        ("openai", "text-only-model"),
        ("anthropic", "claude-sonnet"),
        ("openai", "gpt-5.5-text"),
    ):
        route_id = f"{provider}-{model}"
        with pytest.raises(ScreenshotToCodeError, match="not reviewed for image input"):
            resolve_vision_route(route_id)

    with pytest.raises(ScreenshotToCodeError, match="installer-owned credential"):
        HostCredentialReference("host:vision-fixture")
    with pytest.raises(ScreenshotToCodeError, match="installer-owned credential"):
        HostCredentialReference("sk-not-a-reference")

    with pytest.raises(ScreenshotToCodeError, match="not reviewed for image input"):
        validate_vision_route(VisionRoute(
            "openai-text-only-model", HostCredentialReference("host:installer/screenshot-to-code/openai")
        ))


def _pinned_checkout() -> tuple[Path, Path]:
    source_value = os.environ.get("HERMES_SCREENSHOT_TO_CODE_SOURCE")
    if not source_value:
        pytest.skip("set HERMES_SCREENSHOT_TO_CODE_SOURCE to the full pinned upstream checkout")
    source_root = Path(source_value).resolve(strict=True)
    backend = source_root / "backend"
    commit = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if commit != SOURCE_REVISION:
        pytest.fail("screenshot-to-code checkout is not the reviewed pinned commit")
    adapter = resolve_component_adapter("screenshot-to-code")
    assert adapter.source_identity == SOURCE_IDENTITY
    assert adapter.revision == SOURCE_REVISION

    python_value = os.environ.get("HERMES_SCREENSHOT_TO_CODE_PYTHON")
    if python_value:
        # Preserve venv/bin/python symlinks: resolving them bypasses the venv
        # and starts the bare interpreter without the pinned site-packages.
        python = Path(python_value).absolute()
        if not python.is_file():
            pytest.fail("configured screenshot-to-code interpreter does not exist")
    else:
        python = backend / ".venv" / "bin" / "python"
        if not python.is_file():
            pytest.skip("install the exact backend Poetry lock in backend/.venv or set HERMES_SCREENSHOT_TO_CODE_PYTHON")
    return backend, python


def test_pinned_upstream_stream_code_pipeline_sends_image_and_returns_generated_code(tmp_path):
    backend, python = _pinned_checkout()
    source_root = backend.parent
    required_files = (
        "backend/pyproject.toml", "backend/poetry.lock", "backend/routes/generate_code.py",
        "frontend/package.json", "frontend/pnpm-lock.yaml",
    )
    files = {path: (source_root / path).read_bytes() for path in required_files}
    source_review = review_screenshot_to_code_files(SOURCE_IDENTITY, SOURCE_REVISION, files)
    assert source_review.source_revision == SOURCE_REVISION
    assert source_review.evidence_state == "lockfile-integrity-reviewed; functional-probe-pending"
    script = textwrap.dedent(r'''
        import base64, hashlib, json, os, sys
        from pathlib import Path

        import httpx
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        backend = Path.cwd()
        sys.path.insert(0, str(backend))
        import routes.generate_code as generate_code
        import agent.providers.factory as provider_factory

        # Exercise one of the source's real OpenAI-only variants; both resolve
        # through the upstream Llm map to the reviewed vision model gpt-5.5.
        generate_code.NUM_VARIANTS = 1
        observed = []
        function_args = json.dumps({
            "path": "index.html",
            "content": "<!doctype html><html><body><main data-fixture=\"vision-ok\">Generated from screenshot</main></body></html>",
        }, separators=(",", ":"))

        def event(name, payload):
            return b"event: " + name.encode() + b"\ndata: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n"

        def provider(request):
            assert request.method == "POST"
            assert request.url.scheme == "https" and request.url.host == "vision-mock.invalid"
            assert request.url.path == "/v1/responses"
            assert request.headers.get("authorization") == "Bearer fixture-only"
            body = json.loads(request.content)
            observed.append(body)
            assert body["model"] == "gpt-5.5"
            assert body["stream"] is True
            if len(observed) == 1:
                user = next(item for item in body["input"] if item["role"] == "user")
                image = next(item for item in user["content"] if item["type"] == "input_image")
                assert image["image_url"].startswith("data:image/png;base64,")
                png = base64.b64decode(image["image_url"].split(",", 1)[1], validate=True)
                assert hashlib.sha256(png).hexdigest() == os.environ["FIXTURE_IMAGE_SHA256"]
                tool_names = {item.get("name") for item in body["tools"]}
                assert "generate_images" not in tool_names
                assert "edit_images" not in tool_names
                assert "extract_assets" not in tool_names
                item = {
                    "id": "fc_fixture", "type": "function_call", "call_id": "call_fixture",
                    "name": "create_file", "arguments": function_args,
                }
                response = {
                    "id": "resp_fixture_1", "object": "response", "created_at": 1,
                    "status": "completed", "model": "gpt-5.5", "output": [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                }
                payload = b"".join((
                    event("response.created", {"type": "response.created", "response": {"id": "resp_fixture_1", "object": "response", "created_at": 1, "status": "in_progress", "model": "gpt-5.5", "output": []}}),
                    event("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {**item, "arguments": ""}}),
                    event("response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "item_id": "fc_fixture", "output_index": 0, "call_id": "call_fixture", "name": "create_file", "delta": function_args}),
                    event("response.function_call_arguments.done", {"type": "response.function_call_arguments.done", "item_id": "fc_fixture", "output_index": 0, "call_id": "call_fixture", "name": "create_file", "arguments": function_args}),
                    event("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
                    event("response.completed", {"type": "response.completed", "response": response}),
                    b"data: [DONE]\n\n",
                ))
            else:
                # The second upstream turn receives the real create_file tool
                # result and closes the selected generation path.
                assert any("Successfully created file" in str(item) for item in body["input"])
                response = {
                    "id": "resp_fixture_2", "object": "response", "created_at": 2,
                    "status": "completed", "model": "gpt-5.5", "output": [],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                }
                payload = b"".join((
                    event("response.created", {"type": "response.created", "response": {"id": "resp_fixture_2", "object": "response", "created_at": 2, "status": "in_progress", "model": "gpt-5.5", "output": []}}),
                    event("response.output_text.delta", {"type": "response.output_text.delta", "delta": "Generated fixture page."}),
                    event("response.completed", {"type": "response.completed", "response": response}),
                    b"data: [DONE]\n\n",
                ))
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload)

        real_async_openai = provider_factory.AsyncOpenAI
        transport = httpx.MockTransport(provider)
        clients = []
        def mockable_openai(*args, **kwargs):
            kwargs["http_client"] = httpx.AsyncClient(transport=transport)
            client = real_async_openai(*args, **kwargs)
            clients.append(client)
            return client
        provider_factory.AsyncOpenAI = mockable_openai

        app = FastAPI()
        app.include_router(generate_code.router)
        # Fixed synthetic local PNG; no URL, upload server, or fetch target.
        image_bytes = Path(os.environ["FIXTURE_IMAGE_PATH"]).read_bytes()
        image = "data:image/png;base64," + base64.b64encode(image_bytes).decode("ascii")
        request = {
            "generatedCodeConfig": "html_tailwind",
            "inputMode": "image",
            "generationType": "create",
            "prompt": {"text": "Build the page in this screenshot.", "images": [image], "videos": []},
            "history": [],
            "openAiApiKey": "fixture-only",
            "openAiBaseURL": "https://vision-mock.invalid/v1",
            "isImageGenerationEnabled": False,
            "isAssetExtractionEnabled": False,
        }
        try:
            with TestClient(app) as client:
                with client.websocket_connect("/generate-code") as socket:
                    socket.send_json(request)
                    messages = []
                    while True:
                        message = socket.receive_json()
                        messages.append(message)
                        if message.get("type") == "variantComplete":
                            break
                        if message.get("type") in {"error", "variantError"}:
                            raise AssertionError("upstream pipeline returned an error: " + str(message))
            assert len(observed) == 2, "upstream agent must call the mock provider and consume create_file result"
            codes = [m.get("value", "") for m in messages if m.get("type") == "setCode"]
            assert any('data-fixture="vision-ok"' in value for value in codes)
            assert any(m.get("type") == "variantComplete" for m in messages)
            Path(os.environ["FIXTURE_EVENTS_PATH"]).write_text(json.dumps(messages), encoding="utf-8")
        finally:
            for client in clients:
                import asyncio
                asyncio.run(client.close())
            transport.close()
    ''')
    image_bytes = FIXTURE_IMAGE.read_bytes()
    event_path = tmp_path / "upstream-events.json"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(backend),
        "IS_PROD": "",
        "PROMPT_REPORTS_ENABLED": "0",
        "LOCAL_ASSET_DIR": str(tmp_path / "assets"),
        "LOGS_PATH": str(tmp_path / "logs"),
        "FIXTURE_IMAGE_SHA256": hashlib.sha256(image_bytes).hexdigest(),
        "FIXTURE_IMAGE_PATH": str(FIXTURE_IMAGE),
        "FIXTURE_EVENTS_PATH": str(event_path),
    }
    result = subprocess.run(
        [str(python), "-c", script], cwd=backend, env=env,
        capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, f"pinned upstream pipeline fixture failed:\n{result.stdout}\n{result.stderr}"
    upstream_events = json.loads(event_path.read_text(encoding="utf-8"))
    parsed = validate_upstream_events(upstream_events, fixture_image=image_bytes, route_id="openai-gpt-5.5")
    assert parsed.source_revision == SOURCE_REVISION
    assert 'data-fixture="vision-ok"' in parsed.generated_code
