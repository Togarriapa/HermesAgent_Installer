from __future__ import annotations

import hashlib
import datetime as dt
import http.client
import ipaddress
import ssl
import threading
import time
from dataclasses import replace

from pathlib import Path

import pytest

from hermes_installer.authority.channel_ingress_services import (
    AuthoritySourceReceiptResolver, IngressServiceDenied,
    RootAudioCaptureReceiptResolver, RootAudioCaptureRequest, RootAudioCaptureArtifact,
    RootAudioInputSession, RootInMemoryAudioArtifactCatalog,
    RootIngressDisposition, RootLoopbackHttpIngressListener,
)
from hermes_installer.authority.channel_provenance import AuthenticatedSubjectReceipt
from hermes_installer.authority.source_observers import SourceReceiptHandle
from hermes_installer.authority.types import Sensitivity, SourceReceipt
from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection, HttpIngressSelection,
)


def selected_http():
    return HttpIngressSelection(
        "http-selection", "http-channel", 1, "profile-001", "role-001", "issuer-001",
        "listener-001", "jwt-verifier-001", "session-policy-001", "http-body-v1", 4096, 30,
    )


def listener(*, context=None, handle=None, process=None, host="127.0.0.1"):
    context = context or ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    issuer = type("Issuer", (), {"issue_request_source_receipt":
        lambda self, *_args: SourceReceiptHandle("R"*43)})()
    verifier = type("Verifier", (), {
        "verify_selected_jwt": lambda self, selection, token, session_id: AuthenticatedSubjectReceipt(
            "S"*43, "session-handle-001", "a"*64, time.monotonic()+60, "jwt-verifier-001"),
        "current_selected_subject": lambda self, selection, receipt: receipt,
    })()
    body=b'{"text":"hello"}'
    request_receipt=replace(source_receipt("http-request-receipt"),
                            payload_digest=hashlib.sha256(body).hexdigest())
    authority=FakeAuthorityService({"R"*43:request_receipt})
    resolver=AuthoritySourceReceiptResolver(authority,profile_id="profile-001",
        principal_id="principal-001",uid=501,generation="generation-001",
        native_process_identity="native-identity-001")
    return RootLoopbackHttpIngressListener(
        selected_http(), host=host, port=0, tls_context=context,
        selection_handle=handle or object(), route_id="ingress",
        identity_verifier=verifier, request_receipt_issuer=issuer,
        source_receipt_resolver=resolver,
        process_request=process or (lambda _ticket: RootIngressDisposition.ACCEPTED),
    )


def test_http_listener_requires_mutual_tls_and_loopback_only():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with pytest.raises(ValueError, match="mutual authentication"):
        RootLoopbackHttpIngressListener(selected_http(), host="127.0.0.1", port=0,
            tls_context=context, selection_handle=object(), route_id="ingress",
            identity_verifier=object(), request_receipt_issuer=object(),
            source_receipt_resolver=object(),
            process_request=lambda _ticket: RootIngressDisposition.ACCEPTED)
    with pytest.raises(ValueError, match="IPv4 loopback"):
        listener(host="0.0.0.0")


def test_loopback_listener_ticket_is_root_owned_bounded_and_one_use():
    from types import SimpleNamespace
    handle = object()
    service = listener(handle=handle)
    service._server = SimpleNamespace(server_address=("127.0.0.1", 54321))
    ticket = service._create_ticket(
        method="POST", path="/ingress", host="127.0.0.1:54321", content_type="application/json",
        session_id="S" * 24, access_jwt=b"synthetic-jwt", body=b'{"text":"hello"}',
        request_receipt_handle="R"*43,
    )
    request = service.take_authenticated_request(handle, ticket)
    assert request.listener_enrollment_id == "listener-001"
    assert request.body == b'{"text":"hello"}'
    assert request.access_jwt == b"synthetic-jwt"
    with pytest.raises(IngressServiceDenied, match="unknown or replayed"):
        service.take_authenticated_request(handle, ticket)
    with pytest.raises(IngressServiceDenied, match="not issued"):
        service.take_authenticated_request(object(), service._create_ticket(
            method="POST", path="/ingress", host="127.0.0.1:54321", content_type="application/json",
            session_id="S" * 24, access_jwt=b"synthetic-jwt", body=b'{"text":"hello"}',
            request_receipt_handle="R"*43,
        ))
    service._server = None


def test_http_body_deadline_is_absolute_and_recomputed_for_slow_trickle():
    from types import SimpleNamespace

    now = [10.0]
    service = listener()
    service.monotonic = lambda: now[0]
    service.request_timeout_seconds = 0.5

    class Connection:
        def __init__(self): self.timeouts = []
        def settimeout(self, value): self.timeouts.append(value)

    class Reader:
        def __init__(self, chunks): self.chunks = iter(chunks)
        def read1(self, size):
            now[0] += 0.3
            return next(self.chunks)

    handler = SimpleNamespace(connection=Connection(), rfile=Reader([b"ab", b"cd"]))
    with pytest.raises(IngressServiceDenied, match="absolute deadline"):
        service._read_body(handler, 4)
    assert len(handler.connection.timeouts) == 2
    assert handler.connection.timeouts[1] < handler.connection.timeouts[0]

    now[0] = 20.0
    handler = SimpleNamespace(connection=Connection(), rfile=Reader([b"ab", b"cd"]))
    service.request_timeout_seconds = 1.0
    assert service._read_body(handler, 4) == b"abcd"
    assert len(handler.connection.timeouts) == 2


def test_tls_loopback_ingress_runs_jwt_session_receipt_and_registry_path(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from hermes_installer.authority.channel_provenance import (
        RootSelectedHttpIngressObserver,
    )
    from hermes_installer.components.plugin_channel_provenance import AuthenticatedHttpIngressProducer

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ingress CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(ca_key, hashes.SHA256()))

    def leaf(name, san):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if name == "loopback" else ExtendedKeyUsageOID.CLIENT_AUTH
            ]), critical=False)
            .sign(ca_key, hashes.SHA256()))
        key_path, cert_path = tmp_path/f"{name}.key", tmp_path/f"{name}.crt"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path

    server_cert, server_key = leaf("loopback", x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    client_cert, client_key = leaf("selected-gateway", x509.DNSName("selected-gateway"))
    ca_path = tmp_path/"ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_cert_chain(str(server_cert), str(server_key))
    server_context.load_verify_locations(cafile=str(ca_path))
    client_context = ssl.create_default_context(cafile=str(ca_path))
    client_context.load_cert_chain(str(client_cert), str(client_key))

    body = b'{"text":"synthetic ingress"}'
    subject_receipt = source_receipt("subject-parent")
    request_receipt = replace(source_receipt("http-request", parents=(subject_receipt.receipt_id,)),
                              payload_digest=hashlib.sha256(body).hexdigest())
    subject_handle, request_handle = "U"*43, "R"*43
    authority = FakeAuthorityService({subject_handle: subject_receipt,
                                      request_handle: request_receipt})
    receipts = AuthoritySourceReceiptResolver(
        authority, profile_id="profile-001", principal_id="principal-001", uid=501,
        generation="generation-001", native_process_identity="native-identity-001")
    class IdentityVerifier:
        def verify_selected_jwt(self, selected, token, session_id):
            assert token == b"test.jwt" and session_id == "S"*24
            return AuthenticatedSubjectReceipt(subject_handle, "session-handle-001", "e"*64,
                                               time.monotonic()+60, selected.jwt_verifier_enrollment_id)
        def current_selected_subject(self, selected, receipt):
            assert receipt.receipt_handle == subject_handle
            return receipt
    identity = IdentityVerifier()
    class RequestReceiptIssuer:
        def issue_request_source_receipt(self, selection_handle, session_handle, parent_handle, raw_body):
            assert session_handle == "session-handle-001" and parent_handle == subject_handle
            assert hashlib.sha256(raw_body).hexdigest() == request_receipt.payload_digest
            return SourceReceiptHandle(request_handle)

    selected = selected_http()
    selection_handle = object()
    holder = {}
    def process(ticket):
        observed = holder["producer"].observe(ticket)
        parents = holder["observer"].consume_source_receipts(observed.proof)
        assert parents == ()
        holder["observer"].consume(observed.proof)
        return RootIngressDisposition.ACCEPTED

    service = RootLoopbackHttpIngressListener(
        selected, host="127.0.0.1", port=0, tls_context=server_context,
        selection_handle=selection_handle, route_id="ingress", identity_verifier=identity,
        request_receipt_issuer=RequestReceiptIssuer(), source_receipt_resolver=receipts,
        process_request=process,
    )
    holder["observer"] = RootSelectedHttpIngressObserver(
        selected, selection_handle, service, identity,
        controller_identity_digest="a"*64, service_generation_digest="b"*64,
        route_id="ingress", body_schema_validator=lambda schema, data:
            schema == selected.body_schema_id and data == b'{"text":"synthetic ingress"}', monotonic=time.monotonic,
        source_receipt_resolver=receipts, source_receipt_validator=receipts.validate)
    holder["producer"] = AuthenticatedHttpIngressProducer(
        selected, selection_handle, holder["observer"], clock=time.monotonic)
    try:
        port = service.start()
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=client_context, timeout=2)
        connection.request("POST", "/ingress", body=body,
            headers={"Host": f"127.0.0.1:{port}", "Authorization": "Bearer test.jwt",
                     "X-Hermes-Session-ID": "S"*24, "Content-Type": "application/json",
                     "Content-Length": str(len(body))})
        response = connection.getresponse()
        assert response.status == 202
        response.read()
        connection.close()
    finally:
        service.close()


class Binding:
    uid = 501
    profile_id = "profile-001"
    principal_id = "principal-001"


def source_receipt(receipt_id, *, parents=()):
    now = time.monotonic()
    return SourceReceipt(
        receipt_id=receipt_id, issuer_id="root-issuer", source_kind="native-input",
        principal_id="principal-001", profile_id="profile-001", namespace_id="namespace-001",
        uid=501, origin_id="channel-event", process_generation="generation-001",
        payload_digest=hashlib.sha256(receipt_id.encode()).hexdigest(),
        sensitivity=Sensitivity.PRIVATE, parent_lineage_hash="a"*64,
        policy_revision="policy-001", recipient_ceiling=frozenset(),
        issued_at_monotonic=now, monotonic_expires_at=now + 300.0, signature="root-signature",
        enrollment_id="enrollment-001", native_process_identity="native-identity-001",
        parent_receipt_ids=tuple(parents), nonce="nonce-" + receipt_id,
    )


class FakeAuthorityService:
    def __init__(self, handles):
        self._lock = threading.RLock()
        self._source_receipt_handles = handles
        self.bindings_by_uid = {501: Binding()}
        self.monotonic = time.monotonic
    def _verify_source_receipt(self, receipt, binding):
        assert binding is self.bindings_by_uid[501]
        if receipt.signature != "root-signature":
            raise ValueError("bad signature")


def test_source_receipt_resolver_returns_only_current_signed_full_closure():
    parent = source_receipt("parent-001")
    selected = source_receipt("selected-001", parents=(parent.receipt_id,))
    parent_handle, selected_handle = "P"*43, "S"*43
    service = FakeAuthorityService({parent_handle: parent, selected_handle: selected})
    resolver = AuthoritySourceReceiptResolver(
        service, profile_id="profile-001", principal_id="principal-001", uid=501,
        generation="generation-001", native_process_identity="native-identity-001",
    )
    closure = resolver((selected_handle,))
    assert closure == (parent, selected)
    assert resolver.validate(selected)


def test_source_receipt_resolver_rejects_forged_handle_and_stale_generation():
    receipt = source_receipt("selected-001")
    service = FakeAuthorityService({"S"*43: receipt})
    resolver = AuthoritySourceReceiptResolver(
        service, profile_id="profile-001", principal_id="principal-001", uid=501,
        generation="stale-generation", native_process_identity="native-identity-001",
    )
    with pytest.raises(Exception, match="absent"):
        resolver(("F"*43,))
    with pytest.raises(Exception, match="stale or different owner"):
        resolver(("S"*43,))


def test_selected_jwt_sessions_verify_signature_claims_current_receipts_and_revocation():
    jwt = pytest.importorskip("jwt")
    from jwt.utils import base64url_encode
    from cryptography.hazmat.primitives.asymmetric import rsa
    from hermes_installer.authority.channel_ingress_services import RootSelectedJWTSessionAuthority
    from hermes_installer.authority.source_observers import SourceReceiptHandle
    from hermes_installer.authority.types import canonical_digest
    from hermes_installer.components.plugin_channel_provenance import HttpIngressSelection

    now_wall, now_mono = 1_800_000_000.0, 100.0
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    jwks = {"fixture-kid": {"kty":"RSA","kid":"fixture-kid","alg":"RS256","use":"sig",
        "n":base64url_encode(public.n.to_bytes((public.n.bit_length()+7)//8,"big")).decode(),
        "e":base64url_encode(public.e.to_bytes((public.e.bit_length()+7)//8,"big")).decode()}}
    selection=HttpIngressSelection("http-selection","http-channel",1,"profile-001","role-001",
        "issuer-001","listener-001","jwt-verifier-001","session-policy-001","body-schema-001",4096,30)
    subject_digest=hashlib.sha256(b"known-user").hexdigest()
    root_service=FakeAuthorityService({})
    root_service.monotonic=lambda: now_mono
    receipt_resolver=AuthoritySourceReceiptResolver(root_service,profile_id="profile-001",
        principal_id="principal-001",uid=501,generation="generation-001",
        native_process_identity="native-identity-001")
    class SubjectReceiptIssuer:
        counter=0
        def issue_subject_source_receipt(self,*,selection,session_id,subject_digest,token_fingerprint,
                                         source_payload,expires_monotonic):
            self.counter+=1
            handle=SourceReceiptHandle(f"R{self.counter:042d}")
            row=replace(source_receipt(f"subject-{self.counter}"),
                payload_digest=canonical_digest(source_payload),
                issued_at_monotonic=now_mono,monotonic_expires_at=expires_monotonic)
            root_service._source_receipt_handles[str(handle)]=row
            return handle
    issuer=SubjectReceiptIssuer()
    authority=RootSelectedJWTSessionAuthority(selection,verifier_enrollment_id="jwt-verifier-001",
        owner_generation="generation-001",issuer="https://issuer.example.test",audience="channel-aud",
        jwks=jwks,allowed_subject_digests=frozenset({subject_digest}),receipt_issuer=issuer,
        source_receipts=receipt_resolver,wall_clock=lambda:now_wall,monotonic=lambda:now_mono)
    def token(*,sub="known-user",sid="S"*24,aud="channel-aud",exp=now_wall+90):
        return jwt.encode({"iss":"https://issuer.example.test","aud":aud,"sub":sub,"sid":sid,
            "jti":"fixture-jti-123","iat":now_wall-1,"nbf":now_wall-1,"exp":exp},
            private,algorithm="RS256",headers={"kid":"fixture-kid"}).encode()
    proof=authority.verify_selected_jwt(selection,token(),"S"*24)
    assert authority.verify_selected_jwt(selection,token(),"S"*24) is proof
    assert authority.current_selected_subject(selection,proof) is proof
    assert b"known-user" not in repr(authority._sessions).encode()
    with pytest.raises(Exception,match="signature, claims"):
        authority.verify_selected_jwt(selection,token(sid="T"*24),"S"*24)
    with pytest.raises(Exception,match="signature, claims"):
        authority.verify_selected_jwt(selection,token(sub="unknown-user"),"S"*24)
    with pytest.raises(Exception,match="signature, claims"):
        authority.verify_selected_jwt(selection,token(exp=now_wall-1),"S"*24)
    authority.revoke_session(proof.session_handle)
    with pytest.raises(Exception,match="revoked"):
        authority.current_selected_subject(selection,proof)


def test_root_audio_resolver_binds_current_consent_device_artifact_and_parent_receipts():
    from hermes_installer.authority.source_observers import SourceReceiptHandle
    selection=AudioIngressSelection("audio-selection","audio-channel",1,"profile-001","role-001",
        "issuer-001","device-001","capture-backend-001","d"*64,"session-policy-001",
        16384,10,"pcm16-mono-16000-v1")
    selection_handle=object()
    pcm=bytearray(b"synthetic-pcm!")
    digest=hashlib.sha256(pcm).hexdigest()
    consent_handle, source_handle, capture_handle = "C"*43, "A"*43, "R"*43
    receipts = {handle: source_receipt(f"receipt-{i}") for i, handle in enumerate(
        (consent_handle, source_handle, capture_handle))}
    authority=FakeAuthorityService(receipts)
    source_resolver=AuthoritySourceReceiptResolver(authority,profile_id="profile-001",
        principal_id="principal-001",uid=501,generation="generation-001",
        native_process_identity="native-identity-001")
    session=RootAudioInputSession("S"*43,"profile-001","generation-001","device-001",
        "e"*64,SourceReceiptHandle(consent_handle),time.monotonic()+30)
    artifact=RootAudioCaptureArtifact("audio-artifact-001",digest,len(pcm),
        "audio/pcm;format=s16le;rate=16000;channels=1","profile-001","generation-001",
        "capture-op-001",SourceReceiptHandle(source_handle),SourceReceiptHandle(capture_handle),
        "device-001","capture-backend-001","d"*64,"pcm16-mono-16000-v1",time.monotonic()+30)
    class Sessions:
        current=True
        workflow_result=object()
        request=RootAudioCaptureRequest(session.session_handle,artifact.artifact_id)
        consumed=False
        def take_capture_workflow_result(self,handle,result):
            if handle is not selection_handle or result is not self.workflow_result or self.consumed:
                raise PermissionError("capture workflow result is not root-issued or was replayed")
            self.consumed=True
            return self.request
        def current_input_session(self, handle, session_handle):
            assert handle is selection_handle and session_handle == session.session_handle
            if not self.current: raise PermissionError("consent or device session revoked")
            return session
    class Artifacts:
        consumed=False
        def resolve_capture(self,handle,current_session,artifact_id):
            assert handle is selection_handle and current_session is session and artifact_id==artifact.artifact_id
            return artifact
        def current_capture(self,handle,current_session,current_artifact):
            if self.consumed or current_artifact is not artifact: raise PermissionError("capture consumed")
            return artifact
        def read_capture_bytes(self,handle,current_session,current_artifact,*,maximum_bytes):
            assert maximum_bytes==16384
            return bytearray(pcm)
        def consume_capture(self,handle,current_artifact): self.consumed=True
    sessions, artifacts=Sessions(),Artifacts()
    resolver=RootAudioCaptureReceiptResolver(selection,selection_handle,sessions=sessions,
        artifacts=artifacts,owner_generation="generation-001",source_receipts=source_resolver)
    with pytest.raises(PermissionError, match="root-issued"):
        resolver.take_selected_capture(selection_handle,
            RootAudioCaptureRequest(session.session_handle,artifact.artifact_id))
    sessions.consumed=False
    proof=resolver.take_selected_capture(selection_handle,sessions.workflow_result)
    assert proof.audio_artifact_id==artifact.artifact_id
    read=resolver.read_current_capture(selection_handle,proof,maximum_bytes=16384)
    assert read==pcm
    read[:]=b"\0"*len(read)
    assert len(source_resolver((consent_handle,source_handle,capture_handle)))==3
    sessions.current=False
    with pytest.raises(PermissionError):
        resolver.current_selected_capture(selection_handle,proof)
    sessions.current=True
    resolver.consume_capture(selection_handle,proof)
    with pytest.raises(IngressServiceDenied,match="unknown, consumed"):
        resolver.current_selected_capture(selection_handle,proof)


def test_root_audio_memory_catalog_seals_bounds_and_zeroes_pcm_without_paths():
    selection = AudioIngressSelection("audio-selection", "audio-channel", 1, "profile-001",
        "role-001", "issuer-001", "device-001", "capture-backend-001", "d"*64,
        "session-policy-001", 32000, 60, "pcm16-mono-16000-v1")
    selection_handle = object()
    session = RootAudioInputSession("S"*43, "profile-001", "generation-001", "device-001",
        "e"*64, "C"*43, time.monotonic()+30)
    catalog = RootInMemoryAudioArtifactCatalog(selection, selection_handle,
        owner_generation="generation-001")
    pcm = bytearray(b"\x01\x00" * 16000)
    artifact = catalog.store_capture(selection_handle, session, pcm, operation_id="O"*43)
    assert not any(pcm)
    assert artifact.size_bytes == 32000
    assert artifact.sha256 == hashlib.sha256(b"\x01\x00" * 16000).hexdigest()
    assert not hasattr(artifact, "path")
    assert catalog.resolve_capture(selection_handle, session, artifact.artifact_id) is artifact
    data = catalog.read_capture_bytes(selection_handle, session, artifact, maximum_bytes=32000)
    assert bytes(data) == b"\x01\x00" * 16000
    catalog.consume_capture(selection_handle, artifact)
    assert not catalog._items
    with pytest.raises(IngressServiceDenied, match="stale|consumed"):
        catalog.read_capture_bytes(selection_handle, session, artifact, maximum_bytes=32000)
