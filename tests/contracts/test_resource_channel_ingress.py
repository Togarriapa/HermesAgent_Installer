from __future__ import annotations

import asyncio
import hashlib
import secrets
import sys
import types
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from hermes_installer.authority.resource_channel_ingress import (
    ChannelIngressSelection,
    ChannelIngressUnavailable,
    ComposioV3SelectedChannel,
    ComposioV3WebhookIngress,
    NativeChannelIngressProducer,
)
from hermes_installer.authority.resource_source_controllers import RootResourceSourceEventProof


def _selection(channel: str, scope: str) -> ChannelIngressSelection:
    return ChannelIngressSelection(
        resource_id=f"channel.{channel}", generation="generation-1",
        observer_enrollment_id="observer-1", controller_role_id="role-channel",
        source_issuer_id="issuer-channel", backend_id="backend-channel", channel_name=channel,
        adapter_id=channel, account_binding_digest="a" * 64,
        credential_vault_reference="vault-account-1",
        selected_config_digest="b" * 64, allowed_scopes=(scope,),
    )


class _Issuer:
    def register_source_producer(self, producer, **kwargs):
        self.producer, self.kwargs = producer, kwargs
        return object()

    def mint_source_proof(self, _capability, **kwargs):
        assert self.kwargs["validate_provenance"](kwargs["provenance"])
        self.proof = kwargs
        return RootResourceSourceEventProof(
            producer_handle="p" + secrets.token_urlsafe(32),
            event_id=kwargs["event_id"], resource_id=kwargs["resource_id"],
            resource_generation=kwargs["resource_generation"],
            source_observer_enrollment_id=kwargs["source_observer_enrollment_id"],
            source_kind="native-input", payload=kwargs["payload"],
            verified_provenance=kwargs["provenance"], issuer_token=self.issuer_token,
        )

    issuer_token = object()


@dataclass
class _RuntimeProof:
    enabled: bool = True
    source_revision: str = "7085fbf7753266fc4943c55ac04926186bc90005"
    loaded_module_sha256: str = "c" * 64
    profile_process_handle: str = "profile-proc-1"

    def revalidate(self):
        return self.enabled


class _Registry:
    def __init__(self, issuer):
        self.issuer = issuer
        self.events = []

    def resolve_selected_ingress_controller(self, role_id, issuer_id, backend_id):
        assert (role_id, issuer_id, backend_id) == (
            "role-channel", "issuer-channel", "backend-channel")
        return types.SimpleNamespace(proof_handle="root-ingress-proof-handle")

    def capture_selected_ingress(self, proof_handle, _proof):
        assert proof_handle == "root-ingress-proof-handle"
        assert self.issuer.kwargs["validate_provenance"](self.issuer.proof["provenance"])
        assert isinstance(_proof, RootResourceSourceEventProof)
        self.events.append(_proof)


class _ReplayLedger:
    def __init__(self):
        self.entries = {}
        self.rollbacks = 0

    def begin(self, resource_id, event_id, body_sha256, expires_at):
        assert expires_at > 0
        key = (resource_id, event_id)
        prior = self.entries.get(key)
        if prior is not None:
            return types.SimpleNamespace(state="duplicate", body_sha256=prior[0], event_handle=prior[1])
        reservation = types.SimpleNamespace(state="reserved", body_sha256=body_sha256, key=key)
        self.entries[key] = (body_sha256, None, reservation)
        return reservation

    def commit(self, reservation, event_handle):
        self.entries[reservation.key] = (reservation.body_sha256, event_handle)

    def rollback(self, reservation):
        self.rollbacks += 1
        if self.entries.get(reservation.key, (None,))[0] == reservation.body_sha256:
            self.entries.pop(reservation.key, None)


@dataclass
class _Source:
    platform: str
    chat_id: str
    user_id: str
    message_id: str
    guild_id: str = ""


@dataclass
class _MessageEvent:
    text: str
    source: _Source
    raw_message: object
    message_type: object
    platform_update_id: int | None = None
    timestamp: datetime = datetime(2026, 10, 9, tzinfo=timezone.utc)
    media_urls: tuple[str, ...] = ()
    media_types: tuple[str, ...] = ()


@pytest.fixture
def telegram_sdk(monkeypatch):
    telegram = types.ModuleType("telegram")
    ext = types.ModuleType("telegram.ext")

    class Update:
        pass

    class Application:
        def __init__(self):
            self.handlers = {0: []}

    class TelegramMessageHandler:
        def __init__(self, _filters, callback):
            self.callback = callback

    telegram.Update = Update
    ext.Application = Application
    ext.MessageHandler = TelegramMessageHandler
    monkeypatch.setitem(sys.modules, "telegram", telegram)
    monkeypatch.setitem(sys.modules, "telegram.ext", ext)
    return Update, Application, TelegramMessageHandler


def _producer(selection, issuer, registry, selected=None, account=None, runtime=None):
    current = selected if selected is not None else [selection]
    account = account if account is not None else [selection.account_binding_digest]
    runtime = runtime if runtime is not None else [_RuntimeProof()]
    producer = NativeChannelIngressProducer(
        selection=selection,
        current_selection=lambda: current[0],
        account_binding_reader=lambda _client, _reference: account[0],
        connector_runtime_reader=lambda _client, _adapter, _platform, _revision: runtime[0],
        issuer=issuer,
        controller_registry=registry,
        replay_ledger=_ReplayLedger(),
    )
    return producer, current, account, runtime


def test_telegram_registered_sdk_callback_mints_exact_one_use_native_event(telegram_sdk):
    Update, Application, Handler = telegram_sdk
    selection = _selection("telegram", "-100123456")
    issuer = _Issuer()
    registry = _Registry(issuer)
    producer, *_ = _producer(selection, issuer, registry)
    application = Application()

    class Adapter:
        _app = application

        async def _handle_text_message(self, update, context):
            await self._build_triggered_event(update.message, update, "text")

        async def _handle_command(self, _update, _context):
            return None

        async def _handle_location_message(self, _update, _context):
            return None

        async def _build_triggered_event(self, message, update, _message_type):
            return _MessageEvent(
                text=message.text,
                source=_Source("telegram", str(message.chat.id), str(message.from_user.id),
                               str(message.message_id)),
                raw_message=message, message_type=types.SimpleNamespace(value="text"),
                platform_update_id=update.update_id,
            )

        async def handle_message(self, event):
            self.dispatched = event

    adapter = Adapter()
    for name in ("_handle_command", "_handle_text_message", "_handle_location_message"):
        application.handlers[0].append(Handler(None, getattr(adapter, name)))
    producer.install_telegram(application, adapter)

    message = types.SimpleNamespace(
        text="read the selected task", message_id=81,
        chat=types.SimpleNamespace(id=-100123456),
        from_user=types.SimpleNamespace(id=44),
    )
    update = Update()
    update.message, update.effective_message, update.update_id = message, message, 219
    context = types.SimpleNamespace(application=application)
    asyncio.run(application.handlers[0][1].callback(update, context))

    assert len(registry.events) == 1
    receipt = registry.events[0]
    assert receipt.resource_id == selection.resource_id
    assert receipt.source_observer_enrollment_id == "observer-1"
    assert receipt.payload.startswith(b'{"account_binding_digest":"' + b"a" * 64)
    assert producer.status.accepted == 1
    assert hashlib.sha256(receipt.payload).hexdigest()

    # A reconstructed normalized event outside the registered PTB callback has no provenance.
    forged_event = _MessageEvent(
        text=message.text,
        source=_Source("telegram", str(message.chat.id), str(message.from_user.id),
                       str(message.message_id)),
        raw_message=message, message_type=types.SimpleNamespace(value="text"),
        platform_update_id=update.update_id,
    )
    asyncio.run(adapter.handle_message(forged_event))
    assert len(registry.events) == 1

    # Replaying the same authenticated Update is deduplicated before source receipt minting.
    asyncio.run(application.handlers[0][1].callback(update, context))
    assert len(registry.events) == 1
    assert producer.status.replayed == 1

    message.text = "conflicting payload for the same Telegram update"
    with pytest.raises(ChannelIngressUnavailable, match="replay identity conflicts"):
        asyncio.run(application.handlers[0][1].callback(update, context))
    assert len(registry.events) == 1


def test_telegram_rejects_stale_selection_account_and_application_callback(telegram_sdk):
    Update, Application, Handler = telegram_sdk
    selection = _selection("telegram", "100")
    issuer = _Issuer()
    registry = _Registry(issuer)
    producer, current, account, runtime = _producer(selection, issuer, registry)

    class Adapter:
        _app = None

        async def _handle_command(self, _update, _context):
            return None

        async def _handle_text_message(self, _update, _context):
            return None

        async def _handle_location_message(self, _update, _context):
            return None

        async def _build_triggered_event(self, *_args):
            return None

        async def handle_message(self, _event):
            return None

    adapter = Adapter()
    app = Application()
    adapter._app = app
    for name in ("_handle_command", "_handle_text_message", "_handle_location_message"):
        app.handlers[0].append(Handler(None, getattr(adapter, name)))
    producer.install_telegram(app, adapter)
    callback = app.handlers[0][0].callback

    forged = Update()
    forged.update_id = 1
    forged.message = forged.effective_message = types.SimpleNamespace(
        message_id=2, text="forged", chat=types.SimpleNamespace(id=100),
        from_user=types.SimpleNamespace(id=5))
    with pytest.raises(Exception, match="detached from its live Application"):
        asyncio.run(callback(forged, types.SimpleNamespace(application=Application())))

    wrong_account = _Issuer()
    wrong_registry = _Registry(wrong_account)
    bad_account_producer, *_ = _producer(
        selection, wrong_account, wrong_registry, account=["c" * 64])
    with pytest.raises(Exception, match="account credential is unavailable or mismatched"):
        bad_account_producer._install_client("telegram", Application(), adapter)

    stale_selection = _Issuer()
    stale_registry = _Registry(stale_selection)
    stale_producer, *_ = _producer(
        selection, stale_selection, stale_registry, selected=[_selection("telegram", "100")])
    with pytest.raises(Exception, match="selected channel row is stale"):
        stale_producer._install_client("telegram", Application(), adapter)

    runtime_issuer = _Issuer()
    runtime_registry = _Registry(runtime_issuer)
    runtime_producer, *_ = _producer(
        selection, runtime_issuer, runtime_registry, runtime=[None])
    runtime_app = Application()
    adapter._app = runtime_app
    with pytest.raises(Exception, match="not loaded from the selected pinned Hermes runtime"):
        runtime_producer.install_telegram(runtime_app, adapter)


@pytest.fixture
def discord_sdk(monkeypatch):
    discord = types.ModuleType("discord")

    class Message:
        pass

    discord.Message = Message
    ext = types.ModuleType("discord.ext")
    commands = types.ModuleType("discord.ext.commands")

    class Bot:
        pass

    commands.Bot = Bot
    ext.commands = commands
    monkeypatch.setitem(sys.modules, "discord", discord)
    monkeypatch.setitem(sys.modules, "discord.ext", ext)
    monkeypatch.setitem(sys.modules, "discord.ext.commands", commands)
    return Message, Bot


def test_discord_registered_on_message_requires_current_guild_and_provenance(discord_sdk):
    Message, Bot = discord_sdk
    selection = _selection("discord", "guild-42")
    issuer = _Issuer()
    registry = _Registry(issuer)
    producer, current, account, _runtime = _producer(selection, issuer, registry)

    client = Bot()
    message = Message()
    message.id = 901
    message.content = "summarize this"
    message.author = types.SimpleNamespace(id=52, bot=False)
    message.guild = types.SimpleNamespace(id="guild-42")
    message.channel = types.SimpleNamespace(id=128)

    class Adapter:
        _client = client

        async def handle_message(self, event):
            self.seen_event = event

        async def _dispatch(self, incoming):
            source = _Source("discord", str(incoming.channel.id), str(incoming.author.id),
                             str(incoming.id), guild_id=str(incoming.guild.id))
            await self.handle_message(_MessageEvent(
                text=incoming.content, source=source, raw_message=incoming,
                message_type=types.SimpleNamespace(value="text"),
            ))

    adapter = Adapter()
    async def on_message(incoming):
        await adapter._dispatch(incoming)

    client.on_message = on_message
    producer.install_discord(client, adapter)
    asyncio.run(client.on_message(message))
    assert len(registry.events) == 1
    body = __import__("json").loads(registry.events[0].payload)
    assert body["scope_id"] == "guild-42"
    assert body["sender_id"] == "52"
    assert body["message_id"] == "901"

    # Selection and credential changes are read again by the issuer validator.
    current[0] = _selection("discord", "guild-42")
    assert issuer.kwargs["validate_provenance"](issuer.proof["provenance"]) is False
    current[0] = selection
    account[0] = "d" * 64
    assert issuer.kwargs["validate_provenance"](issuer.proof["provenance"]) is False


def _composio_selection():
    return ComposioV3SelectedChannel(
        id="whatsapp-enrollment", channel_resource_id="channel-whatsapp",
        resource_generation="generation-3", profile_id="profile-main",
        controller_role_id="role-channel", source_issuer_id="issuer-channel",
        composio_enrollment_id="composio-enrollment", composio_user_id="user-1",
        connected_account_id="connected-1", auth_config_id="auth-1",
        toolkit_version="1.0", trigger_artifact_id="trigger-schema",
        trigger_artifact_sha256="d" * 64, trigger_slug="WHATSAPP_MESSAGE",
        trigger_instance_id="trigger-instance", webhook_subscription_id="subscription-1",
        webhook_route_enrollment_id="route-1", webhook_secret_reference_id="vault-webhook-1",
        allowed_user_numbers=("+15551234567",),
        payload_field_bindings={"sender_user_number": "/data/sender/phone"},
        max_event_age_seconds=120, source_observer_enrollment_id="observer-wa",
        backend_id="backend-channel",
    )


def _signed_composio_request(selection, secret, now, *, sender="+15551234567", event_id="evt-1",
                             created_at=None):
    import base64
    import hmac
    import json

    body = json.dumps({
        "id": event_id,
        "type": "composio.trigger.message",
        "metadata": {
            "trigger_slug": selection.trigger_slug,
            "trigger_id": selection.trigger_instance_id,
            "connected_account_id": selection.connected_account_id,
            "auth_config_id": selection.auth_config_id,
            "user_id": selection.composio_user_id,
        },
        "data": {"sender": {"phone": sender}, "text": "fixture only"},
        "timestamp": datetime.fromtimestamp(
            now if created_at is None else created_at, tz=timezone.utc).isoformat(),
    }, separators=(",", ":")).encode()
    timestamp = str(int(now))
    signature = base64.b64encode(hmac.new(
        secret, event_id.encode() + b"." + timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).digest()).decode()
    request = types.SimpleNamespace(
        body=body, method="POST", content_type="application/json",
        headers={"webhook-id": event_id, "webhook-timestamp": timestamp,
                 "webhook-signature": f"v1,{signature}",
                 "x-composio-webhook-version": "V3"},
    )
    return request


class _RouteProof:
    enrollment_id = "route-1"

    def revalidate_request(self, request):
        return getattr(request, "transport_peer", None) == "listener-peer"


class _AccountProof:
    connected_account_id = "connected-1"
    auth_config_id = "auth-1"
    composio_user_id = "user-1"

    def revalidate(self):
        return True


class _SchemaProof:
    artifact_id = "trigger-schema"
    schema_sha256 = "d" * 64

    def revalidate(self):
        return True

    def validate_payload(self, payload):
        return (isinstance(payload, dict) and "sender" in payload
                and isinstance(payload.get("text"), str))


def _composio_ingress(selection, issuer, registry, ledger, now, *, account=None, schema=None):
    secret = b"fixture-secret-not-a-real-credential"
    route = _RouteProof()
    account = account or _AccountProof()
    schema = schema or _SchemaProof()
    ingress = ComposioV3WebhookIngress(
        selection=selection, current_selection=lambda: selection,
        secret_reader=lambda reference: secret if reference == "vault-webhook-1" else None,
        account_binding_reader=lambda _selection: account,
        schema_reader=lambda _artifact, _digest: schema,
        listener_route_reader=lambda request: route,
        backend_reader=lambda _selection: "backend-channel",
        replay_ledger=ledger, issuer=issuer, controller_registry=registry,
        wall_time=lambda: now, monotonic=lambda: now,
    )
    return ingress, secret


def test_composio_v3_webhook_authenticates_and_deduplicates_selected_delivery():
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    request = _signed_composio_request(selection, secret, now)
    request.transport_peer = "listener-peer"

    accepted = ingress.accept_request(request)
    assert accepted.accepted and not accepted.duplicate
    assert len(registry.events) == 1
    assert issuer.proof["resource_id"] == selection.channel_resource_id
    assert b'"text":"fixture only"' in issuer.proof["payload"]
    # The issuer validator is valid only during the accepted root callback;
    # replaying the observation after that callback has returned is rejected.
    assert not ingress.validate_claims(issuer.proof["provenance"])

    duplicate = ingress.accept_request(request)
    assert duplicate.accepted and duplicate.duplicate
    assert duplicate.event_handle is accepted.event_handle
    assert len(registry.events) == 1


@pytest.mark.parametrize("mutate,reason", [
    (lambda request: request.headers.__setitem__("webhook-signature", "v1," + "A" * 43 + "="), "signature is invalid"),
    (lambda request: setattr(request, "transport_peer", "untrusted-peer"), "selected protected route"),
])
def test_composio_v3_rejects_untrusted_route_and_tampered_hmac(mutate, reason):
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    request = _signed_composio_request(selection, secret, now)
    request.transport_peer = "listener-peer"
    mutate(request)
    with pytest.raises(ChannelIngressUnavailable, match=reason):
        ingress.accept_request(request)
    assert not registry.events
    assert not ledger.entries


def test_composio_v3_rejects_sender_outside_protected_allowlist():
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    request = _signed_composio_request(selection, secret, now, sender="+447700900123")
    request.transport_peer = "listener-peer"
    with pytest.raises(ChannelIngressUnavailable, match="outside the selected E.164 allowlist"):
        ingress.accept_request(request)
    assert not registry.events


@pytest.mark.parametrize("created_at", [1_799_000_000.0, 1_799_500_010.0])
def test_composio_rejects_stale_or_implausibly_future_event_timestamp(created_at):
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    request = _signed_composio_request(selection, secret, now, created_at=created_at)
    request.transport_peer = "listener-peer"
    with pytest.raises(ChannelIngressUnavailable, match="age/future-skew bound"):
        ingress.accept_request(request)
    assert not ledger.entries


def test_composio_replay_id_with_different_signed_body_is_rejected():
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    first = _signed_composio_request(selection, secret, now, event_id="same-event")
    first.transport_peer = "listener-peer"
    ingress.accept_request(first)
    conflicting = _signed_composio_request(
        selection, secret, now, sender="+15551234567", event_id="same-event")
    # Alter and correctly re-sign the same provider identity to model an
    # authenticated but conflicting provider retry.
    import base64
    import hmac
    body = conflicting.body.replace(b"fixture only", b"different body")
    timestamp = conflicting.headers["webhook-timestamp"]
    signature = base64.b64encode(hmac.new(
        secret, b"same-event." + timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).digest()).decode()
    conflicting.body = body
    conflicting.headers["webhook-signature"] = f"v1,{signature}"
    conflicting.transport_peer = "listener-peer"
    with pytest.raises(ChannelIngressUnavailable, match="replay identity conflicts"):
        ingress.accept_request(conflicting)
    assert len(registry.events) == 1


@pytest.mark.parametrize("proof,reason", [
    (_AccountProof(), "selected Composio account/session is unavailable or changed"),
    (_SchemaProof(), "selected Composio trigger schema is unavailable or payload did not validate"),
])
def test_composio_requires_current_selected_account_and_schema_proofs(proof, reason):
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()
    registry = _Registry(issuer)
    ledger = _ReplayLedger()
    if isinstance(proof, _AccountProof):
        proof.connected_account_id = "different-account"
        ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now, account=proof)
    else:
        proof.schema_sha256 = "e" * 64
        ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now, schema=proof)
    request = _signed_composio_request(selection, secret, now)
    request.transport_peer = "listener-peer"
    with pytest.raises(ChannelIngressUnavailable, match=reason):
        ingress.accept_request(request)
    assert not registry.events
    assert not ledger.entries


def test_composio_capture_failure_releases_replay_reservation_for_retry():
    now = 1_799_500_000.0
    selection = _composio_selection()
    issuer = _Issuer()

    class FailOnceRegistry(_Registry):
        fail = True

        def capture_selected_ingress(self, proof_handle, proof):
            if self.fail:
                self.fail = False
                raise RuntimeError("fixture capture failure")
            return super().capture_selected_ingress(proof_handle, proof)

    registry = FailOnceRegistry(issuer)
    ledger = _ReplayLedger()
    ingress, secret = _composio_ingress(selection, issuer, registry, ledger, now)
    request = _signed_composio_request(selection, secret, now)
    request.transport_peer = "listener-peer"
    with pytest.raises(RuntimeError, match="fixture capture failure"):
        ingress.accept_request(request)
    assert ledger.rollbacks == 1
    assert not registry.events

    retried = ingress.accept_request(request)
    assert retried.accepted and not retried.duplicate
    assert len(registry.events) == 1
