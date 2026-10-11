"""Source contracts for the read-only Jarvis Bots/channels/schedules feature."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.core_client import CoreRpcClient
from hermes_installer.remote.jarvis_bots import (
    FEATURE_ROUTES,
    build_status_snapshot,
    install_jarvis_bots_routes,
)
from hermes_installer.remote.jarvis_channels import CHANNEL_STATUS_PENDING, project_channel_status
from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService, JarvisChatStore
from hermes_installer.remote.jarvis_schedules import project_schedules


def test_schedule_projection_is_bounded_and_excludes_sensitive_native_fields():
    projected, missing_timezone = project_schedules([{
        "job_id": "native-job-id-must-not-leak",
        "name": "sensitive prompt preview must not be used as a title",
        "enabled": False,
        "schedule": "*/15 * * * *",
        "next_run_at": "2026-10-11T18:30:00Z",
        "last_run_at": 1_791_737_400,
        "last_status": "success",
        "state": "paused",
        "paused_at": 1_791_737_000,
        "prompt_preview": "private instruction",
        "script": "do-not-run",
        "workdir": "/private/path",
        "delivery": {"to": "private-destination"},
    }])

    assert missing_timezone is True
    assert len(projected) == 1
    assert set(projected[0]) == {
        "opaque_id", "label", "enabled", "timezone", "schedule_summary", "next_run_at", "last_state",
    }
    assert projected[0]["label"] == "Scheduled job 1"
    assert projected[0]["enabled"] is False
    assert projected[0]["timezone"] is None
    assert projected[0]["schedule_summary"] == "*/15 * * * *"
    assert projected[0]["next_run_at"] == "2026-10-11T18:30:00Z"
    assert projected[0]["last_state"] == "success"
    assert "private" not in repr(projected)
    assert "native-job-id" not in repr(projected)


def test_schedule_unknown_enabled_and_timestamp_remain_unknown():
    projected, missing_timezone = project_schedules([{
        "job_id": "opaque",
        "name": "Scheduled job",
        "enabled": None,
        "schedule": None,
        "next_run_at": "not-a-timestamp",
        "last_status": "unknown",
    }])
    assert missing_timezone is True
    assert projected[0]["enabled"] is None
    assert projected[0]["schedule_summary"] == "Schedule details unavailable"
    assert projected[0]["next_run_at"] is None
    assert projected[0]["last_state"] is None


def test_status_snapshot_reports_observed_profile_and_schedule_with_exact_pending_sources():
    result = build_status_snapshot(
        core_generation="generation-1",
        observed_at="2026-10-11T12:00:00Z",
        profile={"name": "default", "display_name": "Jarvis", "is_default": True,
                 "provider": "secret-provider", "model": "private-model", "path": "/private/profile"},
        schedules=[{"name": "Scheduled job", "enabled": True, "schedule": "0 * * * *",
                    "next_run_at": None, "last_status": None, "prompt": "private"}],
    )

    assert set(result) == {
        "schema", "observed_at", "core_generation", "profiles", "channels", "schedules", "pending_reasons",
    }
    assert result["schema"] == 1
    assert result["profiles"][0]["display_name"] == "Jarvis"
    assert result["profiles"][0]["kind"] == "profile"
    assert result["profiles"][0]["bot_mode_available"] is False
    assert set(result["profiles"][0]) == {
        "opaque_id", "display_name", "kind", "state", "bot_mode_available",
    }
    assert result["channels"] == []
    assert result["schedules"][0]["enabled"] is True
    assert result["schedules"][0]["timezone"] is None
    assert all(isinstance(reason, str) and reason for reason in result["pending_reasons"])
    encoded = repr(result)
    assert "secret-provider" not in encoded and "private-model" not in encoded
    assert "/private/profile" not in encoded and "private\'" not in encoded


def test_channel_status_is_explicitly_unavailable_instead_of_fabricated():
    items, reason = project_channel_status()
    assert items == []
    assert reason == CHANNEL_STATUS_PENDING
    assert "unknown" in reason


def test_routes_use_only_fixed_default_profile_and_reject_query_selectors(tmp_path, monkeypatch):
    async def scenario():
        profile_calls = []
        cron_calls = []

        async def list_profiles(self):
            profile_calls.append(True)
            return [{"name": "default", "display_name": "Jarvis", "is_default": True}]

        async def list_schedules(self):
            cron_calls.append(True)
            return [{"job_id": "secret-id", "name": "Scheduled job", "enabled": False,
                     "schedule": "0 9 * * *", "next_run_at": None, "last_run_at": None,
                     "last_status": "success", "state": "paused", "paused_at": None}]

        monkeypatch.setattr(CoreRpcClient, "list_profiles", list_profiles, raising=False)
        monkeypatch.setattr(CoreRpcClient, "list_schedules", list_schedules, raising=False)
        backend = CoreRpcClient(token_file=Path(tmp_path / "unused-token"))

        def principal(_request):
            now = time.monotonic()
            return ChatPrincipal("owner-subject", now + 30, now + 10, "generation-1")

        service = JarvisChatService(JarvisChatStore(tmp_path / "chat.sqlite3"), backend,
                                    principal_from_request=principal)
        app = web.Application()
        install_jarvis_bots_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/schedules")
            assert response.status == 200
            payload = await response.json()
            assert payload["core_generation"] == "generation-1"
            assert payload["schedules"][0]["enabled"] is False
            assert profile_calls == [True, True]
            assert cron_calls == [True]
            assert (await client.get("/chat/api/schedules?profile=private-profile")).status == 404
            assert profile_calls == [True, True]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_routes_are_fixed_get_only_collections():
    assert FEATURE_ROUTES == (
        ("GET", "/chat/api/bots"),
        ("GET", "/chat/api/channels"),
        ("GET", "/chat/api/schedules"),
    )
