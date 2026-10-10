from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

import pytest

from hermes_installer.authority import composio_trigger_artifacts as module
from hermes_installer.authority.remote_origin import HMACReceiptSigner
from hermes_installer.protected_enrollment import RootJournalSelection


SLUG = "WHATSAPP_TRIGGER_FIXTURE_ONLY"
VERSION = "20260721_00"
SESSION_ID = "setup-" + "a" * 32
ROW = {
    "slug": SLUG, "name": "Fixture", "description": "Synthetic row",
    "type": "webhook", "toolkit": {"slug": "whatsapp"}, "version": VERSION,
    "config": {"token": {"type": "string"}},
    "payload": {"type": "object", "properties": {"from": {"type": "string"}}},
    "requires_webhook_endpoint_setup": True,
}
BODY = json.dumps(ROW, sort_keys=True, separators=(",", ":")).encode()
REQUEST_BYTES = b"fixture canonical catalog request"


@dataclass
class Exchange:
    receipt_handle: str = "1" * 64
    authorization_handle: str = "2" * 64
    session_handle: str = SESSION_ID
    transaction_handle: str = "transaction-fixture"
    principal_id: str = "principal-fixture"
    project_id: str = "project-fixture"
    toolkit_version: str = VERSION
    operation: str = "composio.whatsapp.catalog.read"
    request_policy_artifact_id: str = module._POLICY_ID
    request_policy_sha256: str = module._POLICY_SHA256
    request_sha256: str = hashlib.sha256(REQUEST_BYTES).hexdigest()
    response_sha256: str = hashlib.sha256(BODY).hexdigest()
    response_size_bytes: int = len(BODY)
    issued_monotonic: float = 10.0
    expires_monotonic: float = 100.0
    selected_slug: str = SLUG


class Exchanges:
    def __init__(self, exchange=None, body=BODY):
        self.exchange = exchange or Exchange()
        self.body = body
        self.reads = []

    def resolve_catalog_exchange_receipt(self, handle):
        assert handle == self.exchange.receipt_handle
        return self.exchange

    def resolve_catalog_request_bytes(self, handle):
        assert handle == self.exchange.receipt_handle
        return REQUEST_BYTES

    def resolve_catalog_response_bytes(self, handle):
        assert handle == self.exchange.receipt_handle
        return self.body

    def read_verified_trigger_detail(self, handle, slug):
        self.reads.append((handle, slug))
        if slug != self.exchange.selected_slug:
            raise ValueError("not selected")
        return self.exchange, self.body


class Sessions:
    def __init__(self):
        self.live = type("Live", (), {})()
        self.live._handle = type("Handle", (), {"session_id": SESSION_ID})()
        self.live._authorization = type("Auth", (), {"transaction_handle": "transaction-fixture"})()

    def resolve_live_session_id(self, session_id):
        assert session_id == SESSION_ID
        return self.live


class StaticCatalog:
    artifacts = {}


@pytest.fixture
def registry(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root-owned Composio CAS fixture requires Linux root")
    journal_path = tmp_path / "journal"
    journal_path.mkdir(mode=0o700)
    artifact_store = tmp_path / "artifacts"
    artifact_store.mkdir(mode=0o700)
    info = journal_path.stat()
    monkeypatch.setattr(module, "ARTIFACT_STAGING_DIRECTORY", artifact_store)
    journal = RootJournalSelection("authority-journal", journal_path, info.st_dev,
                                   info.st_ino, "generation-fixture", "4" * 64)
    exchanges = Exchanges()
    result = module.RootComposioTriggerArtifactRegistry.from_root_setup(
        Sessions(), exchanges, artifact_store, StaticCatalog(), journal,
        HMACReceiptSigner(b"t" * 32), expected_uid=0, monotonic=lambda: 20.0)
    return result, exchanges, journal_path, artifact_store


def test_root_derives_exact_selected_detail_and_keeps_digest_domains(registry):
    issuer, exchanges, journal, artifact_store = registry
    receipt = issuer.persist_selected_trigger_type("1" * 64, SLUG)
    verified = issuer.resolve_selected_trigger_artifact(receipt.receipt_handle,
                                                        issuer.sessions.live)
    document = json.loads(verified.document_bytes)
    semantic = dict(document)
    claimed_semantic_sha = semantic.pop("sha256")
    assert hashlib.sha256(module._canonical(semantic)).hexdigest() == claimed_semantic_sha
    assert hashlib.sha256(verified.document_bytes).hexdigest() == receipt.artifact_sha256
    assert verified.document_bytes.endswith(b"\n")
    assert verified.artifact_id == receipt.artifact_id
    assert verified.schema_sha256 == verified.artifact_sha256 == receipt.artifact_sha256
    assert verified.size_bytes == len(verified.document_bytes)
    assert document["source_request_receipt_handle"] == document["source_response_receipt_handle"] == "1" * 64
    assert document["trigger_slug"] == SLUG
    assert receipt.artifact_id == "composio-whatsapp-trigger-type:" + hashlib.sha256(
        module._canonical({"toolkit_version": VERSION, "trigger_slug": SLUG,
                           "response_sha256": hashlib.sha256(BODY).hexdigest()})).hexdigest()
    assert dict(verified.active_catalog_binding) == {
        "trigger_artifact_id": receipt.artifact_id,
        "trigger_artifact_sha256": receipt.artifact_sha256,
        "trigger_slug": SLUG, "toolkit_version": VERSION,
    }
    assert receipt.response_sha256 == hashlib.sha256(BODY).hexdigest()
    assert (artifact_store / "composio-derived" / "objects" / receipt.artifact_id
            / receipt.artifact_sha256).is_file()
    assert (journal / "composio-trigger-artifacts" / "receipts" / f"{receipt.receipt_handle}.json").is_file()


def test_selected_exchange_is_single_use_and_foreign_slug_fails_closed(registry):
    issuer, exchanges, *_ = registry
    with pytest.raises(module.ComposioTriggerArtifactUnavailable):
        issuer.persist_selected_trigger_type("1" * 64, "OTHER_TRIGGER")
    issuer.persist_selected_trigger_type("1" * 64, SLUG)
    with pytest.raises(module.ComposioTriggerArtifactUnavailable, match="already consumed"):
        issuer.persist_selected_trigger_type("1" * 64, SLUG)


def test_foreign_or_corrupt_detail_cannot_become_an_artifact(registry):
    issuer, exchanges, *_ = registry
    exchanges.body = BODY.replace(b"WHATSAPP_TRIGGER_FIXTURE_ONLY", b"FORGED_TRIGGER")
    with pytest.raises(module.ComposioTriggerArtifactUnavailable):
        issuer.persist_selected_trigger_type("1" * 64, SLUG)


def test_finite_source_projection_and_artifact_identity_are_exact():
    projection = module._detail_projection(ROW, slug=SLUG, toolkit_version=VERSION)
    assert projection["trigger_type"] == "webhook"
    assert projection["config_schema"] == ROW["config"]
    with pytest.raises(module.ComposioTriggerArtifactUnavailable):
        module._detail_projection({**ROW, "unreviewed": True}, slug=SLUG,
                                  toolkit_version=VERSION)
    with pytest.raises(module.ComposioTriggerArtifactUnavailable):
        module._detail_projection(ROW, slug=SLUG, toolkit_version="20260915_00")
    expected_id = "composio-whatsapp-trigger-type:" + hashlib.sha256(
        module._canonical({"toolkit_version": VERSION, "trigger_slug": SLUG,
                           "response_sha256": hashlib.sha256(BODY).hexdigest()})).hexdigest()
    assert len(expected_id) < 256
