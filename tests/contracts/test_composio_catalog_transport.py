from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qs

import pytest

from hermes_installer.components.composio_catalog_transport import (
    COMPOSIO_CATALOG_POLICY_SHA256,
    COMPOSIO_ORIGIN,
    COMPOSIO_TOOLKIT_VERSION,
    ComposioCatalogTransportDenied,
    RootComposioCatalogTransport,
)


PIN = "20260721_00"
SLUG = "WHATSAPP_FIXTURE_ONLY_DO_NOT_ENROLL"
ROW = {
    "slug": SLUG, "name": "Synthetic", "description": "Fixture only",
    "type": "webhook", "toolkit": {"slug": "whatsapp"},
    "config": {}, "payload": {}, "version": PIN,
}


@dataclass(frozen=True)
class Authorization:
    authorization_handle: str = "opaque-auth-handle"
    credential_reference_id: str = "composio_fixture_project_key"
    operation: str = "composio.whatsapp.catalog.read"
    target: str = "composio:whatsapp:catalog:20260721_00"
    toolkit_version: str = PIN
    request_policy_sha256: str = COMPOSIO_CATALOG_POLICY_SHA256


@dataclass(frozen=True)
class Grant:
    path: str
    query: dict
    expires_monotonic: float = 9999999999.0
    origin: str = COMPOSIO_ORIGIN
    method: str = "GET"
    toolkit_version: str = PIN
    request_policy_sha256: str = COMPOSIO_CATALOG_POLICY_SHA256


class Authority:
    def __init__(self, grants):
        self.grants = list(grants)
        self.used = []
        self.receipts = []

    def authorize_catalog_get(self, authorization_handle, *, trigger_slug=None):
        assert authorization_handle == "opaque-auth-handle"
        grant = self.grants.pop(0)
        expected_path = f"/api/v3.1/triggers_types/{trigger_slug}" if trigger_slug else grant.path
        assert expected_path == grant.path
        self.used.append(grant)
        return grant

    def resolve_project_credential(self, grant):
        assert grant in self.used
        return "synthetic-secret-never-log"

    def record_catalog_exchange(self, grant, *, http_status, response_body):
        assert grant in self.used
        self.receipts.append((grant, http_status, response_body))
        n = len(self.receipts)
        return f"req-{n}", f"resp-{n}"


class Network:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, url, *, method, headers, body, timeout_seconds, max_response_bytes):
        self.calls.append((url, method, dict(headers), body, timeout_seconds, max_response_bytes))
        return self.responses.pop(0)


@dataclass
class Response:
    status: int
    body: bytes


def make_grant(path, query):
    return Grant(path=path, query=query)


def list_query():
    return {"toolkit_slugs": ["whatsapp"],
            "toolkit_versions": {"whatsapp": PIN}, "limit": 50}


def test_transport_is_fixed_https_root_authorized_and_receipted():
    q = list_query()
    auth = Authority([make_grant("/api/v3.1/triggers_types", q)])
    network = Network([Response(200, b'{"items":[],"next_cursor":null}')])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    response = transport.get_json(path="/api/v3.1/triggers_types", query=q,
        credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
        max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    url, method, headers, body, timeout, max_bytes = network.calls[0]
    assert url.startswith(COMPOSIO_ORIGIN + "/api/v3.1/triggers_types?")
    params = parse_qs(urlsplit(url).query)
    assert params == {"toolkit_slugs": ["whatsapp"],
                      "toolkit_versions[whatsapp]": [PIN], "limit": ["50"]}
    assert method == "GET" and body is None and timeout <= 15 and max_bytes == 2 * 1024 * 1024
    assert headers == {"x-api-key": "synthetic-secret-never-log", "accept": "application/json"}
    assert response["items"] == []
    assert response.request_receipt_handle == "req-1"
    assert response.response_receipt_handle == "resp-1"
    assert auth.receipts[0][1] == 200


@pytest.mark.parametrize("path,query", [
    ("https://attacker.example/", list_query()),
    ("/api/v3.1/triggers_types/NOT_LISTED", {"toolkit_versions": {"whatsapp": PIN}}),
    ("/api/v3.1/triggers_types", {**list_query(), "toolkit_versions": {"whatsapp": "latest"}}),
    ("/api/v3.1/triggers_types", {**list_query(), "limit": 1000}),
    ("/api/v3.1/triggers_types", {**list_query(), "x-api-key": "evil"}),
])
def test_transport_rejects_non_catalog_requests_before_network(path, query):
    auth = Authority([])
    network = Network([])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    with pytest.raises(ComposioCatalogTransportDenied):
        transport.get_json(path=path, query=query,
            credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
            max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert not network.calls
    assert not auth.receipts


def test_grant_query_and_policy_mismatch_fail_closed():
    q = list_query()
    wrong = Grant(path="/api/v3.1/triggers_types", query={**q, "limit": 49})
    auth = Authority([wrong])
    network = Network([])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    with pytest.raises(ComposioCatalogTransportDenied, match="query"):
        transport.get_json(path="/api/v3.1/triggers_types", query=q,
            credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
            max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert not network.calls


def test_detail_fetch_requires_catalog_observation_and_gets_its_own_grant():
    q = list_query()
    detail = {"toolkit_versions": {"whatsapp": PIN}}
    auth = Authority([make_grant("/api/v3.1/triggers_types", q),
                      make_grant(f"/api/v3.1/triggers_types/{SLUG}", detail)])
    network = Network([Response(200, (b'{"items":[' + __import__("json").dumps(ROW).encode()
                          + b'],"next_cursor":null}')),
                       Response(200, __import__("json").dumps(ROW).encode())])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    transport.get_json(path="/api/v3.1/triggers_types", query=q,
        credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
        max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    result = transport.get_json(path=f"/api/v3.1/triggers_types/{SLUG}", query=detail,
        credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
        max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert result["slug"] == SLUG
    assert len(auth.receipts) == 2


def test_second_page_requires_exact_root_observed_cursor_and_is_bounded():
    first_query = list_query()
    cursor = "opaque-fixture-cursor"
    second_query = {**first_query, "cursor": cursor}
    auth = Authority([make_grant("/api/v3.1/triggers_types", first_query),
                      make_grant("/api/v3.1/triggers_types", second_query)])
    network = Network([Response(200, b'{"items":[],"next_cursor":"opaque-fixture-cursor"}'),
                       Response(200, b'{"items":[],"next_cursor":null}')])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    transport.get_json(path="/api/v3.1/triggers_types", query=first_query,
        credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
        max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    with pytest.raises(ComposioCatalogTransportDenied, match="next root-observed page"):
        transport.get_json(path="/api/v3.1/triggers_types", query={**first_query, "cursor": "forged"},
            credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
            max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert len(auth.used) == 1
    transport.get_json(path="/api/v3.1/triggers_types", query=second_query,
        credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
        max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert len(auth.receipts) == 2


def test_http_error_response_is_receipted_before_failure():
    q = list_query()
    auth = Authority([make_grant("/api/v3.1/triggers_types", q)])
    network = Network([Response(401, b'{"error":"unauthorized"}')])
    transport = RootComposioCatalogTransport(auth, Authorization(), network=network)
    with pytest.raises(ComposioCatalogTransportDenied, match="HTTP 200"):
        transport.get_json(path="/api/v3.1/triggers_types", query=q,
            credential_reference_id="composio_fixture_project_key", usage="composio-trigger-discovery",
            max_response_bytes=2 * 1024 * 1024, timeout_seconds=15)
    assert len(auth.receipts) == 1
    assert auth.receipts[0][1] == 401
