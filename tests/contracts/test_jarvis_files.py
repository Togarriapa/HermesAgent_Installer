from __future__ import annotations

import asyncio
import base64
import json
import time

import pytest

from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatDenied, JarvisChatStore
from hermes_installer.remote.jarvis_chat import JarvisChatService
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.core_client import NativeFileAttachment
from hermes_installer.remote.jarvis_files import (
    JarvisFilesStore,
    _read_upload,
    upload_file,
)
from hermes_installer.remote.jarvis_files_assets import FEATURE_ASSETS


def _principal(subject="owner-a", generation="core-generation-a"):
    now = time.monotonic()
    return ChatPrincipal(subject, now + 120, now + 4, generation)


def _conversation(store, subject="owner-a"):
    return store.create_conversation(
        subject, f"runtime-{subject}", f"stored-{subject}", "core-generation-a")


def _reserve(files, conversation, *, subject="owner-a", key="file-request-key-00000001",
             content=b"safe notes\n"):
    return files.reserve(
        subject=subject, conversation_id=conversation["id"],
        core_generation="core-generation-a", idempotency_key=key,
        name="notes.txt", mime_type="text/plain", content=content)


def test_file_reservation_is_idempotent_closed_and_one_shot_per_exact_turn(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)

    receipt, created = _reserve(files, conversation)
    replay, created_again = _reserve(files, conversation)
    assert created is True and created_again is False
    assert replay == receipt
    assert receipt["state"] == "pending"
    assert "ref_text" not in receipt

    with pytest.raises(JarvisChatDenied, match="idempotency"):
        _reserve(files, conversation, content=b"different content\n")

    receipt = files.complete(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a", file_id=receipt["id"],
        ref_text="@file:attachments/notes.txt")
    assert receipt["state"] == "ready"
    assert "ref_text" not in receipt

    turn_id, _nonce, _ = chat.begin_turn(
        "owner-a", conversation["id"], "summarize my notes", "turn-request-key-00000001",
        _principal())
    refs = files.claim_pending(
        subject="owner-a", conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a")
    assert refs == ("@file:attachments/notes.txt",)
    assert files.claim_pending(
        subject="owner-a", conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a") == ()
    assert files.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")[0]["state"] == "attached"
    with pytest.raises(JarvisChatDenied):
        files.for_conversation(subject="owner-b", conversation_id=conversation["id"],
                               core_generation="core-generation-a")


def test_file_claim_denies_foreign_or_wrong_generation_turn_and_stale_conversation(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)
    receipt, _ = _reserve(files, conversation)
    files.complete(subject="owner-a", conversation_id=conversation["id"],
                   core_generation="core-generation-a", file_id=receipt["id"],
                   ref_text="@file:attachments/notes.txt")
    turn_id, _nonce, _ = chat.begin_turn(
        "owner-a", conversation["id"], "read this", "turn-request-key-00000002", _principal())

    with pytest.raises(JarvisChatDenied):
        files.claim_pending(subject="owner-b", conversation_id=conversation["id"],
                            turn_id=turn_id, core_generation="core-generation-a")
    with pytest.raises(JarvisChatDenied):
        files.claim_pending(subject="owner-a", conversation_id=conversation["id"],
                            turn_id=turn_id, core_generation="core-generation-b")
    with pytest.raises(JarvisChatDenied):
        files.for_conversation(subject="owner-a", conversation_id=conversation["id"],
                               core_generation="core-generation-b")


def test_uncertain_native_upload_is_never_retried_after_store_recovery(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)
    receipt, created = _reserve(files, conversation)
    assert created

    recovered = JarvisFilesStore(chat)
    rows = recovered.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")
    assert rows[0]["id"] == receipt["id"]
    assert rows[0]["state"] == "unavailable"
    replay, replayed = _reserve(recovered, conversation)
    assert replayed is False
    assert replay["state"] == "unavailable"


def test_file_upload_parser_accepts_only_bounded_utf8_text_with_safe_basename():
    from aiohttp import web

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, body):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    body = {"name": "notes.md", "content_base64": base64.b64encode(b"hello\n").decode(),
            "idempotency_key": "file-request-key-00000002"}
    assert asyncio.run(_read_upload(Request(body))) == (
        "notes.md", "text/markdown", b"hello\n", "file-request-key-00000002")

    for invalid in (
        {**body, "name": "../private.txt"},
        {**body, "name": "notes.pdf"},
        {**body, "content_base64": base64.b64encode(b"bad\x00text").decode()},
        {**body, "content_base64": base64.b64encode(b"\xff").decode()},
        {**body, "extra": "unreviewed"},
    ):
        with pytest.raises(web.HTTPException):
            asyncio.run(_read_upload(Request(invalid)))


def test_upload_stages_native_attachment_once_and_retry_only_reads_receipt(tmp_path):
    from types import SimpleNamespace

    payload = b"owner supplied notes\n"
    key = "file-request-key-00000003"
    body = {"name": "notes.txt", "content_base64": base64.b64encode(payload).decode(),
            "idempotency_key": key}

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, service, conversation_id):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)
            self.match_info = {"conversation_id": conversation_id}
            self.app = {"jarvis_chat_service": service}

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    class Backend:
        def __init__(self):
            self.attachments = []

        async def attach_file(self, session_id, *, name, media_type, content):
            self.attachments.append((session_id, name, media_type, content))
            return NativeFileAttachment(name, "@file:attachments/notes.txt")

    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = _conversation(chat)
    backend = Backend()
    service = JarvisChatService(
        chat, backend, principal_from_request=lambda _request: _principal())
    request = Request(service, conversation["id"])

    first = asyncio.run(upload_file(request))
    second = asyncio.run(upload_file(request))
    assert first.status == 201
    assert second.status == 200
    assert len(backend.attachments) == 1
    assert backend.attachments[0] == (
        "runtime-owner-a", "notes.txt", "text/plain", payload)
    assert "ref_text" not in first.text
    receipt = service.files_store.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")
    assert receipt[0]["state"] == "ready"


def test_uncertain_upload_failure_is_closed_and_same_key_does_not_repeat_native_effect(tmp_path):
    from aiohttp import web
    from types import SimpleNamespace

    body = {"name": "notes.txt", "content_base64": base64.b64encode(b"hello").decode(),
            "idempotency_key": "file-request-key-00000004"}

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, service, conversation_id):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)
            self.match_info = {"conversation_id": conversation_id}
            self.app = {"jarvis_chat_service": service}

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    class Backend:
        def __init__(self):
            self.calls = 0

        async def attach_file(self, *_args, **_kwargs):
            self.calls += 1
            raise RuntimeError("uncertain upstream failure")

    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = _conversation(chat)
    backend = Backend()
    service = JarvisChatService(
        chat, backend, principal_from_request=lambda _request: _principal())
    request = Request(service, conversation["id"])

    with pytest.raises(web.HTTPServiceUnavailable):
        asyncio.run(upload_file(request))
    with pytest.raises(web.HTTPConflict):
        asyncio.run(upload_file(request))
    assert backend.calls == 1


def test_files_feature_is_static_and_declares_only_fixed_owner_routes():
    validate_feature_assets((FEATURE_ASSETS,))

    assert FEATURE_ASSETS.feature_id == "files"
    assert FEATURE_ASSETS.api_routes == (
        ("GET", "/chat/api/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/files"),
        ("POST", "/chat/api/conversations/{conversation_id}/files"),
    )
    assert "textContent" in FEATURE_ASSETS.mount_js
    assert "innerHTML" not in FEATURE_ASSETS.mount_js
    assert "download" in FEATURE_ASSETS.view_html.lower()
