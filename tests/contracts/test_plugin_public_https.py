from __future__ import annotations

import hashlib
import json
import socket
from types import SimpleNamespace
import pytest

from hermes_installer.components.plugin_local_voice_web import PluginAdapterError, WebResponse
from hermes_installer.components.plugin_public_https import (
    DirectPublicHttpsReader, EnrolledPublicWebScope, PluginWebReadEffectHandler,
    PublicHttpsDenied, PublicReadTarget, _direct_get, make_source_receipt,
)
from hermes_installer.network import HTTPResult


def test_direct_connection_rejects_private_dns_answers_before_connect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1",443))
    ])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_kw: pytest.fail("private address must be denied before connect"))
    with pytest.raises(PublicHttpsDenied, match="private or reserved"):
        _direct_get("https://example.com/", "/", "example.com", 2, 1024)


def test_direct_connection_pins_numeric_peer_verifies_tls_and_never_follows_redirect(monkeypatch):
    connected=[]
    class RawSocket:
        def settimeout(self, _timeout): pass
        def connect(self, address): connected.append(address)
        def getpeername(self): return ("93.184.216.34", 443)
        def close(self): pass
    class TlsSocket:
        def getpeercert(self, binary_form=False): return b"fixture-cert"
        def sendall(self, data): connected.append(data)
        def close(self): pass
    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            assert server_hostname=="example.com"
            return TlsSocket()
    class Response:
        status=302
        def __init__(self, _sock): pass
        def begin(self): pass
        def read(self, _limit): return b""
        def getheaders(self): return [("Location","https://elsewhere.example/"),("Content-Type","text/html")]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34",443))
    ])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_kw: RawSocket())
    monkeypatch.setattr("hermes_installer.components.plugin_public_https.ssl.create_default_context", lambda: Context())
    monkeypatch.setattr("hermes_installer.components.plugin_public_https.http.client.HTTPResponse", Response)
    result=_direct_get("https://example.com/", "/", "example.com", 2, 1024)
    assert result.status==302
    assert result.headers["Location"]=="https://elsewhere.example/"
    assert result.headers["X-Hermes-Connected-IP"]=="93.184.216.34"
    assert result.headers["X-Hermes-TLS-SHA256"]==hashlib.sha256(b"fixture-cert").hexdigest()
    assert connected[0]==("93.184.216.34",443)


def test_one_hop_reader_refuses_unbounded_caller_limits_before_network():
    reader=DirectPublicHttpsReader()
    with pytest.raises(PluginAdapterError,match="response bound"):
        reader.get_one_hop("https://example.com/",timeout=10,max_bytes=2_000_000)


def test_source_receipt_binds_exact_content_destination_peer_and_tls():
    body=b"fixture source"
    response=WebResponse(200,{"content-type":"text/plain"},body,"https://example.com/a",
                         "93.184.216.34",True,False,hashlib.sha256(b"fixture-cert").hexdigest())
    receipt=make_source_receipt(response.final_url,response,body=body,retrieved_at_unix=1_800_000_000,
                               redirect_chain=(response.final_url,),enrollment_id="enrollment-1",
                               generation="generation-1")
    assert receipt.content_sha256==hashlib.sha256(body).hexdigest()
    assert receipt.tls_peer_sha256==hashlib.sha256(b"fixture-cert").hexdigest()
    assert receipt.redirect_chain==(response.final_url,)
    assert receipt.enrollment_id=="enrollment-1"
    bad=WebResponse(200,{},body,response.final_url,"127.0.0.1",True,False,response.tls_peer_sha256)
    with pytest.raises(PluginAdapterError):
        make_source_receipt(response.final_url,bad,body=body,retrieved_at_unix=1_800_000_000,
                            redirect_chain=(response.final_url,),enrollment_id="enrollment-1",
                            generation="generation-1")


def test_root_handler_requires_exact_grant_and_returns_scoped_untrusted_source_receipt():
    url="https://example.com/docs/page"
    scope=EnrolledPublicWebScope("enrollment-1","target-1","generation-1",
        "principal-1","profile-1","public-web",
        (PublicReadTarget("example.com",("/docs",)),))
    reader=DirectPublicHttpsReader()
    reader.get_one_hop=lambda requested, **_kw: WebResponse(
        200,{"Content-Type":"text/plain"},b"trusted test fixture",requested,
        "93.184.216.34",True,False,hashlib.sha256(b"fixture-cert").hexdigest())
    handler=PluginWebReadEffectHandler(scope,reader)
    payload=json.dumps({"schema":1,"adapter_id":"web","action_id":"retrieve",
        "enrollment_id":"enrollment-1","generation":"generation-1",
        "arguments":{"url":url}},sort_keys=True,separators=(",",":")).encode()
    context=SimpleNamespace(principal_id="principal-1",profile_id="profile-1",
                            capabilities=frozenset({"plugin:web"}))
    grant=SimpleNamespace(principal_id="principal-1",profile_id="profile-1",
        capability="plugin:web",target=scope.target,recipient="public-web",
        operation="plugin.web.read",enrollment_id="enrollment-1",
        generation="generation-1",retry_index=0,request_digest=hashlib.sha256(payload).hexdigest())
    response=handler(context=context,authorization=grant,payload=payload,timeout=5,
                     peer_pid=123,cancelled=lambda:False)
    result=json.loads(response["body"])["result"]
    assert result["content"]=="trusted test fixture"
    assert result["untrusted_source"] is True and result["authority"]=="none"
    receipt=result["source_receipt"]
    assert receipt["redirect_chain"]==[url]
    assert receipt["enrollment_id"]=="enrollment-1"
    assert response["receipt_id"]


def test_root_handler_rejects_wrong_generation_and_payload_without_network(monkeypatch):
    url="https://example.com/docs/page"
    scope=EnrolledPublicWebScope("enrollment-1","target-1","generation-1",
        "principal-1","profile-1","public-web",
        (PublicReadTarget("example.com",("/docs",)),))
    reader=DirectPublicHttpsReader()
    monkeypatch.setattr(reader,"get_one_hop",lambda *_a,**_kw: pytest.fail("invalid effect reached network"))
    handler=PluginWebReadEffectHandler(scope,reader)
    payload=json.dumps({"schema":1,"adapter_id":"web","action_id":"retrieve",
        "enrollment_id":"enrollment-1","generation":"generation-1",
        "arguments":{"url":url}},sort_keys=True,separators=(",",":")).encode()
    context=SimpleNamespace(principal_id="principal-1",profile_id="profile-1",
                            capabilities=frozenset({"plugin:web"}))
    grant=SimpleNamespace(principal_id="principal-1",profile_id="profile-1",
        capability="plugin:web",target=scope.target,recipient="public-web",
        operation="plugin.web.read",enrollment_id="enrollment-1",
        generation="generation-2",retry_index=0,request_digest=hashlib.sha256(payload).hexdigest())
    with pytest.raises(PublicHttpsDenied,match="grant"):
        handler(context=context,authorization=grant,payload=payload,timeout=5,
                peer_pid=123,cancelled=lambda:False)
