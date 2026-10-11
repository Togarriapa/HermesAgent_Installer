from hermes_installer.remote.jarvis_native_inventory import decode_native_inventory


def test_native_inventory_projects_closed_bounded_tool_and_skill_rows():
    snapshot = decode_native_inventory(
        toolsets=[
            {"name": "web", "tool_count": 2, "enabled": True,
             "tools": ["web_search", "web_extract"]},
            {"name": "optional", "tool_count": 1, "enabled": False,
             "tools": ["optional_tool"]},
        ],
        skills=[{"category": "research", "names": ["web-facts", "nested/reference-skill"]}],
    )

    assert snapshot.to_public_dict() == {
        "schema": 1,
        "tools": {
            "state": "observed", "selectionState": "reported",
            "items": [
                {"name": "web", "selection": True, "toolCount": 2,
                 "tools": ["web_search", "web_extract"]},
                {"name": "optional", "selection": False, "toolCount": 1,
                 "tools": ["optional_tool"]},
            ],
        },
        "skills": {
            "state": "discovered", "count": 2,
            "categories": [{"name": "research", "skills": ["web-facts", "reference-skill"]}],
        },
    }


def test_all_true_toolset_flags_remain_ambiguous():
    snapshot = decode_native_inventory(
        toolsets=[{"name": "all-tools", "tool_count": 1, "enabled": True,
                   "tools": ["read_file"]}],
        skills=None,
    )

    public = snapshot.to_public_dict()
    assert public["tools"]["selectionState"] == "ambiguous"
    assert public["tools"]["items"][0]["selection"] is None
    assert public["skills"] == {"state": "unknown", "categories": [], "count": 0}


def test_malformed_or_sensitive_source_row_fails_only_its_section_closed():
    snapshot = decode_native_inventory(
        toolsets=[{"name": "../private", "tool_count": 1, "enabled": True,
                   "tools": ["secret_value"]}],
        skills=[{"category": "safe", "names": ["https://example.invalid/private"]}],
    )

    public = snapshot.to_public_dict()
    assert public["tools"] == {"state": "unknown", "selectionState": "unknown", "items": []}
    assert public["skills"] == {"state": "unknown", "categories": [], "count": 0}
    assert "private" not in repr(public)


def test_skill_duplicate_relative_identifier_displays_only_basename():
    snapshot = decode_native_inventory(
        toolsets=[{"name": "core", "tool_count": 0, "enabled": False, "tools": []}],
        skills=[{"category": "general", "names": ["duplicate-folder/usable-skill"]}],
    )

    public = snapshot.to_public_dict()
    assert public["skills"]["categories"][0]["skills"] == ["usable-skill"]
    assert "duplicate-folder" not in repr(public)


def test_native_inventory_route_is_fixed_current_and_keeps_section_failures_unknown(tmp_path):
    import asyncio
    import time

    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService
    from hermes_installer.remote.jarvis_native_inventory import install_jarvis_native_inventory_routes

    class Backend:
        def __init__(self):
            self.tool_calls = 0
            self.skill_calls = 0

        async def toolsets_inventory(self):
            self.tool_calls += 1
            return [{"name": "core", "tool_count": 1, "enabled": True, "tools": ["read_file"]}]

        async def skills_inventory(self):
            self.skill_calls += 1
            raise RuntimeError("private backend detail")

    class Service(JarvisChatService):
        def __init__(self, backend):
            self.backend = backend
            self.current_calls = 0

        def _current(self, _request):
            self.current_calls += 1
            now = time.monotonic()
            return ChatPrincipal("owner-subject", now + 30, now + 10, "generation-1")

    async def scenario():
        backend = Backend()
        service = Service(backend)
        app = web.Application()
        install_jarvis_native_inventory_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/native-capabilities")
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store"
            payload = await response.json()
            assert payload["tools"]["state"] == "observed"
            assert payload["tools"]["items"][0]["tools"] == ["read_file"]
            assert payload["skills"] == {"state": "unknown", "categories": [], "count": 0}
            assert "private backend detail" not in await response.text()
            assert service.current_calls == 2
            assert backend.tool_calls == backend.skill_calls == 1

            assert (await client.get("/chat/api/native-capabilities?profile=other")).status == 404
            assert backend.tool_calls == backend.skill_calls == 1
        finally:
            await client.close()

    asyncio.run(scenario())


def test_native_inventory_route_denies_a_changed_principal_or_generation():
    import asyncio
    import time

    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService
    from hermes_installer.remote.jarvis_native_inventory import install_jarvis_native_inventory_routes

    class Backend:
        async def toolsets_inventory(self):
            return []

        async def skills_inventory(self):
            return []

    class Service(JarvisChatService):
        def __init__(self):
            self.backend = Backend()
            self.current_calls = 0

        def _current(self, _request):
            self.current_calls += 1
            now = time.monotonic()
            generation = "generation-1" if self.current_calls == 1 else "generation-2"
            return ChatPrincipal("owner-subject", now + 30, now + 10, generation)

    async def scenario():
        service = Service()
        app = web.Application()
        install_jarvis_native_inventory_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/native-capabilities")
            assert response.status == 403
            assert service.current_calls == 2
        finally:
            await client.close()

    asyncio.run(scenario())


def test_native_inventory_route_converts_stale_ingress_denial_to_forbidden():
    import asyncio

    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from hermes_installer.remote.jarvis_chat import JarvisChatDenied, JarvisChatService
    from hermes_installer.remote.jarvis_native_inventory import install_jarvis_native_inventory_routes

    class Backend:
        async def toolsets_inventory(self):
            raise AssertionError("backend must not be read without current ingress")

        async def skills_inventory(self):
            raise AssertionError("backend must not be read without current ingress")

    class Service(JarvisChatService):
        def __init__(self):
            self.backend = Backend()

        def _current(self, _request):
            raise JarvisChatDenied("private expired-ingress detail")

    async def scenario():
        app = web.Application()
        install_jarvis_native_inventory_routes(app, Service())
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/native-capabilities")
            assert response.status == 403
            assert "private expired-ingress detail" not in await response.text()
        finally:
            await client.close()

    asyncio.run(scenario())
