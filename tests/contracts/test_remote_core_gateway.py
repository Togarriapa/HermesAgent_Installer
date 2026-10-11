"""Core-mode gateway proof binding and protected HTTP middleware contracts."""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

from hermes_installer.remote import core_gateway, core_gateway_inspector
from hermes_installer.remote.gateway import Principal, RemotePolicy


def _config():
    digest = "a" * 64
    return core_gateway.CoreGatewayConfig(
        hostname="jarvis.example.test", issuer="https://team.cloudflareaccess.com",
        audience="core-test-audience", allowed_emails=frozenset({"owner@example.test"}),
        gateway_uid=996, gateway_gid=981, core_uid=1000, core_gid=1000,
        boot_id="12345678-1234-1234-1234-123456789012",
        gateway_unit_sha256=digest, gateway_python_sha256=digest,
        tunnel_unit_sha256=digest, cloudflared_binary_sha256=digest,
        core_unit_sha256=digest, core_launcher_sha256=digest,
        core_python=core_gateway_inspector.CORE_PYTHON_LINK,
        core_python_sha256=core_gateway_inspector.CORE_PYTHON_SHA256,
        ingress_socket=core_gateway.CORE_INGRESS_SOCKET,
        config_path=core_gateway.CORE_CONFIG, config_sha256=digest)


def _root_observation(config, *, now=10.0):
    nonce = "b" * 64
    core_pid, start_ticks, listener_inode = 330, "77", 8822
    invocation = "12345678-1234-1234-1234-123456789012"
    source_generation = _expected_source_generation(config)
    generation = hashlib.sha256(
        b"hermes-jarvis-core-generation-v1\0" +
        f"{invocation}\0{core_pid}\0{start_ticks}\0{listener_inode}\0{source_generation}".encode("ascii")
    ).hexdigest()
    claims = {
        "schema": 1, "nonce": nonce, "boot_id": config.boot_id,
        "issued_monotonic": now, "expires_monotonic": now + 5.0,
        "peer_pid": 440, "peer_uid": 996, "peer_gid": 981,
        "peer_start_ticks": "88", "tunnel_invocation_id": invocation,
        "tunnel_unit_sha256": config.tunnel_unit_sha256,
        "tunnel_executable_sha256": config.cloudflared_binary_sha256,
        "origin_socket_device": 1, "origin_socket_inode": 2,
        "gateway_unit_sha256": config.gateway_unit_sha256,
        "core_unit_sha256": config.core_unit_sha256,
        "core_invocation_id": invocation, "core_pid": core_pid,
        "core_start_ticks": start_ticks, "core_listener_inode": listener_inode,
        "core_source_generation": source_generation,
        "core_generation": generation, "config_sha256": config.config_sha256,
    }
    proof_sha = core_gateway_inspector._observation_digest(claims)
    return core_gateway_inspector.CoreVerifiedIngressObservation(
        **claims, proof_sha256=proof_sha, _seal=core_gateway_inspector._PROOF_SEAL)


def _expected_source_generation(config):
    inspector = core_gateway_inspector
    if config.core_python != inspector.CORE_PYTHON_LINK:
        raise AssertionError("fixture must use the reviewed PM Python link")
    closure = {
        "source_revision": inspector.CORE_SOURCE_REVISION,
        "files": dict(inspector.CORE_SOURCE_FILES),
        "pyvenv_cfg_sha256": inspector.CORE_PYVENV_CFG_SHA256,
        "python_sha256": inspector.CORE_PYTHON_SHA256,
    }
    canonical = json.dumps(closure, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-source-generation-v1\0" + canonical).hexdigest()


def _accepted_observation(config, *, now, lease_seconds=4.0):
    root = _root_observation(config, now=now - 0.01)
    principal = Principal("owner@example.test", "owner-subject", time.time() + 120, "c" * 64)
    jwt_expiry = now + 100.0
    expiry = min(now + lease_seconds, root.expires_monotonic, jwt_expiry)
    claims = dict(principal=principal, jwt_expiry=jwt_expiry, root_proof=root,
        peer=(440, 996, 981), listener=(1, 2), issued=now - 0.01, expiry=expiry,
        core_generation=root.core_generation, config_sha256=config.config_sha256)
    return core_gateway.CoreAcceptedIngressObservation(
        principal, jwt_expiry, root, 440, 996, 981, 1, 2, now - 0.01, expiry,
        root.core_generation, config.config_sha256,
        core_gateway._accepted_claim_digest(**claims), core_gateway._ACCEPTED_INGRESS_SEAL)


class CoreGatewayProofTests(unittest.TestCase):
    def test_config_load_accepts_only_actual_pinned_core_python_path(self):
        document = {
            "schema": 1, "hostname": "jarvis.example.test",
            "issuer": "https://team.cloudflareaccess.com", "audience": "core-test-audience",
            "allowed_emails": ["owner@example.test"], "gateway_uid": 996,
            "gateway_gid": 981, "core_uid": 1000, "core_gid": 1000,
            "boot_id": "12345678-1234-1234-1234-123456789012",
            "gateway_unit_sha256": "a" * 64, "gateway_python_sha256": "b" * 64,
            "tunnel_unit_sha256": "c" * 64, "cloudflared_binary_sha256": "d" * 64,
            "core_unit_sha256": "e" * 64, "core_launcher_sha256": "f" * 64,
            "core_python": str(core_gateway_inspector.CORE_PYTHON_LINK),
            "core_python_sha256": core_gateway_inspector.CORE_PYTHON_SHA256,
            "ingress_socket": str(core_gateway.CORE_INGRESS_SOCKET),
        }
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "gateway.json"
            config_path.write_text(json.dumps(document), encoding="utf-8")
            config_path.chmod(0o600)
            parent_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                if Path(path) == config_path.parent:
                    return parent_info
                return real_lstat(path, *args, **kwargs)

            with patch.object(core_gateway, "CORE_CONFIG", config_path), \
                 patch.object(core_gateway, "CORE_CONFIG_DIR", config_path.parent), \
                 patch.object(core_gateway.os, "lstat", side_effect=lstat):
                loaded = core_gateway.CoreGatewayConfig.load(
                    path=config_path, expected_owner_uid=os.getuid())
                self.assertEqual(loaded.core_python, core_gateway_inspector.CORE_PYTHON_LINK)

                document["core_python"] = (
                    "/home/admin/HermesInstaller/data/installs/" + "0" * 24 +
                    "/environments/" + "0" * 32 + "/venv/bin/python")
                config_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    core_gateway.CoreGatewayConfig.load(
                        path=config_path, expected_owner_uid=os.getuid())

                document["core_python"] = str(core_gateway_inspector.CORE_PYTHON_LINK)
                config_path.write_text(json.dumps(document), encoding="utf-8")
                hardlink = Path(temporary) / "linked-config.json"
                os.link(config_path, hardlink)
                with self.assertRaises(core_gateway.CoreGatewayDenied):
                    core_gateway.CoreGatewayConfig.load(
                        path=config_path, expected_owner_uid=os.getuid())

    def test_root_and_accepted_proofs_bind_exact_claims_and_original_deadline(self):
        config = _config()
        fake_stat = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                    st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", return_value=fake_stat), \
             patch.object(core_gateway, "_read_config_current"):
            root = _root_observation(config)
            self.assertIs(root.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=12.0), True)
            self.assertIs(root.verify_current(config, peer_pid=441, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=12.0), False)
            self.assertIs(root.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                listener_identity=(1, 2), now=15.0), False)
            changed = dataclasses.replace(root, peer_uid=1000)
            self.assertIs(changed.verify_current(config, peer_pid=440, peer_uid=1000, peer_gid=981,
                listener_identity=(1, 2), now=12.0), False)
            accepted = _accepted_observation(config, now=12.0)
            self.assertIs(accepted.verify_current(config, now=13.0), True)
            extended = dataclasses.replace(accepted, expires_monotonic=accepted.issued_monotonic + 30)
            self.assertIs(extended.verify_current(config, now=13.0), False)

    def test_core_process_environment_binds_official_source_and_session_reference(self):
        secret = b"private-session-token-value-never-reported-1234"
        environment = {
            b"HOME": b"/home/admin", b"HERMES_HOME": b"/home/admin/.hermes",
            b"PATH": core_gateway_inspector.CORE_PATH.encode(),
            b"HERMES_DISABLE_LAZY_INSTALLS": b"1", b"PYTHONNOUSERSITE": b"1",
            b"PYTHONDONTWRITEBYTECODE": b"1",
            b"PYTHONPATH": str(core_gateway_inspector.CORE_SOURCE).encode(),
            b"CREDENTIALS_DIRECTORY": core_gateway_inspector.CORE_CREDENTIALS_DIRECTORY.encode(),
            b"HERMES_DASHBOARD_SESSION_TOKEN": secret,
        }
        core_gateway_inspector._validate_core_process_environment(environment, secret)
        for key, value in ((b"PYTHONPATH", b"/tmp/unreviewed"),
                           (b"HERMES_DISABLE_LAZY_INSTALLS", b"0"),
                           (b"CREDENTIALS_DIRECTORY", b"/tmp/elsewhere")):
            changed = dict(environment)
            changed[key] = value
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._validate_core_process_environment(changed, secret)
        changed = dict(environment)
        changed[b"PYTHONHOME"] = b"/tmp/python"
        with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
            core_gateway_inspector._validate_core_process_environment(changed, secret)

    def test_source_proof_checks_exact_git_and_reviewed_file_closure(self):
        config = _config()
        expected = {str(core_gateway_inspector.CORE_SOURCE / relative): digest
                    for relative, digest in core_gateway_inspector.CORE_SOURCE_FILES.items()}
        expected[str(config.core_python.parent.parent / "pyvenv.cfg")] = (
            core_gateway_inspector.CORE_PYVENV_CFG_SHA256)
        source_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)

        def digest(path, **_kwargs):
            return expected[str(path)]

        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", side_effect=[
                 (core_gateway_inspector.CORE_SOURCE_REVISION + "\n").encode(), b""]), \
             patch.object(core_gateway_inspector, "_protected_file_sha", side_effect=digest):
            proof = core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        self.assertRegex(proof, r"^[0-9a-f]{64}$")

    def test_source_proof_rejects_dirty_tree_wrong_revision_and_expired_budget(self):
        config = _config()
        source_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", side_effect=[
                 (core_gateway_inspector.CORE_SOURCE_REVISION + "\n").encode(), b" M pm/lock.json\n"]):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir), \
             patch.object(core_gateway_inspector, "_run_source_git", return_value=b"0" * 40 + b"\n"):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() + 5)
        with patch.object(core_gateway_inspector.os, "lstat", return_value=source_dir):
            with self.assertRaises(core_gateway_inspector.CoreInspectionDenied):
                core_gateway_inspector._current_core_source(config, deadline=time.monotonic() - 1)


class CoreGatewayIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_wrong_host_is_denied_before_jwt_or_root_observation(self):
        config = _config()
        policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                              config.allowed_emails, {})

        async def unexpected_jwt(*_args, **_kwargs):
            raise AssertionError("JWT validation must not run for a wrong Host")

        headers = SimpleNamespace(getall=lambda key, default=():
            ["attacker.example.test"] if key == "Host" else ["x"])
        request = SimpleNamespace(headers=headers, method="POST", app={})
        with patch.object(core_gateway, "_validate_jwt", unexpected_jwt):
            with self.assertRaises(core_gateway.CoreGatewayDenied):
                await core_gateway.accept_core_ingress(request, config, policy)

    async def test_http_middleware_serves_finite_current_response(self):
        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        now = time.monotonic()
        accepted = _accepted_observation(config, now=now)
        listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                   st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        real_lstat = os.lstat
        def lstat(path, *args, **kwargs):
            return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)

        hits = []
        async def private_handler(_request):
            hits.append((_request["core_ingress"].principal.subject,
                         _request.headers.get("X-Forwarded-For")))
            return web.Response(text="private core response")

        app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
        app["core_gateway_launch"] = launch
        app["core_listener_identity"] = (1, 2)
        app.router.add_get("/private", private_handler)
        app.on_response_prepare.append(core_gateway._verify_ingress_before_response_bytes)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", side_effect=lstat), \
             patch.object(core_gateway, "_read_config_current"), \
             patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/private", headers={
                    "Host": config.hostname, "X-Forwarded-For": "203.0.113.18",
                    "Forwarded": "for=203.0.113.18;host=untrusted.invalid"})
                self.assertEqual(response.status, 200)
                self.assertEqual(await response.text(), "private core response")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(hits, [("owner-subject", "203.0.113.18")])
            finally:
                await client.close()

    async def test_http_middleware_denies_before_handler_and_late_response(self):
        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        hits = []

        async def private_handler(_request):
            hits.append(True)
            return web.Response(text="private core response")

        async def slow_handler(_request):
            hits.append(True)
            await asyncio.sleep(0.35)
            return web.Response(text="private core response")

        app = web.Application(middlewares=[web.middleware(core_gateway._core_ingress_middleware)])
        app["core_gateway_launch"] = launch
        app["core_listener_identity"] = (1, 2)
        app.router.add_get("/private", private_handler)
        app.router.add_get("/slow", slow_handler)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            with patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress",
                              side_effect=core_gateway.CoreGatewayDenied("denied")):
                denied = await client.get("/private", headers={"Host": config.hostname})
            self.assertEqual(denied.status, 403)
            self.assertEqual(await denied.text(), "Forbidden")
            self.assertEqual(hits, [])

            now = time.monotonic()
            accepted = _accepted_observation(config, now=now, lease_seconds=0.2)
            listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                       st_uid=config.gateway_uid, st_gid=config.gateway_gid)
            real_lstat = os.lstat
            def lstat(path, *args, **kwargs):
                return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)
            with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
                 patch.object(core_gateway.os, "lstat", side_effect=lstat), \
                 patch.object(core_gateway, "_read_config_current"), \
                 patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
                late = await client.get("/slow", headers={"Host": config.hostname})
            self.assertEqual(late.status, 403)
            self.assertEqual(await late.text(), "Forbidden")
            self.assertEqual(hits, [True])
        finally:
            await client.close()

    async def test_core_app_protects_redirect_and_only_reviewed_chat_assets(self):
        from hermes_installer.remote.jarvis_chat_assets import reviewed_chat_asset
        import hermes_installer.remote.jarvis_chat as jarvis_chat

        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        now = time.monotonic()
        accepted = _accepted_observation(config, now=now, lease_seconds=4.5)
        listener = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                   st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            return listener if Path(path) == config.ingress_socket else real_lstat(path, *args, **kwargs)

        with patch.object(jarvis_chat, "build_jarvis_chat_service", return_value=object()), \
             patch.object(jarvis_chat, "install_jarvis_chat_routes"), \
             patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", side_effect=lstat), \
             patch.object(core_gateway, "_read_config_current"), \
             patch.object(core_gateway, "accept_core_ingress", return_value=accepted):
            app = core_gateway.create_core_gateway_app(launch)
            app["core_listener_identity"] = (1, 2)
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                headers = {"Host": config.hostname}
                home = await client.get("/", headers=headers, allow_redirects=False)
                self.assertEqual(home.status, 302)
                self.assertEqual(home.headers["Location"], "/chat")
                self.assertEqual(home.headers["Cache-Control"], "no-store")

                for path in ("/chat", "/chat/", "/chat/assets/app.css", "/chat/assets/app.js"):
                    with self.subTest(path=path):
                        expected_type, expected_body = reviewed_chat_asset(path)
                        response = await client.get(path, headers=headers)
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.headers["Content-Type"], expected_type)
                        self.assertEqual(await response.read(), expected_body)
                        self.assertEqual(response.headers["Cache-Control"], "no-store")
                        if path in {"/chat", "/chat/"}:
                            csp = response.headers["Content-Security-Policy"]
                            self.assertIn("script-src 'self'", csp)
                            self.assertIn("style-src 'self'", csp)
                            self.assertNotIn("unsafe-inline", csp)
                            self.assertNotIn("unsafe-eval", csp)
                for path in ("/chat/assets/not-reviewed.js", "/chat/assets/app.js?x=1",
                             "/chat/assets/%61pp.js"):
                    with self.subTest(path=path):
                        target = URL(path, encoded=True) if "%" in path else path
                        response = await client.get(target, headers=headers)
                        self.assertEqual(response.status, 404)
                        self.assertNotIn(b"JARVIS", await response.read())
            finally:
                await client.close()

    async def test_chat_asset_route_does_not_reveal_page_before_ingress(self):
        import hermes_installer.remote.jarvis_chat as jarvis_chat

        config = _config()
        launch = core_gateway.CoreGatewayLaunch(config, RemotePolicy(
            config.hostname, config.issuer, config.audience, config.allowed_emails, {}))
        with patch.object(jarvis_chat, "build_jarvis_chat_service", return_value=object()), \
             patch.object(jarvis_chat, "install_jarvis_chat_routes"), \
             patch.object(core_gateway, "_read_config_current"), \
             patch.object(core_gateway, "accept_core_ingress",
                          side_effect=core_gateway.CoreGatewayDenied("denied")):
            app = core_gateway.create_core_gateway_app(launch)
            app["core_listener_identity"] = (1, 2)
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                response = await client.get("/chat", headers={"Host": config.hostname})
                self.assertEqual(response.status, 403)
                self.assertEqual(await response.text(), "Forbidden")
            finally:
                await client.close()
