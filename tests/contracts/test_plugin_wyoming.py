from __future__ import annotations

import json
import pytest

from hermes_installer.components.plugin_wyoming import (
    WyomingClient, WyomingEndpoint, WyomingEvent, WyomingProtocolError, WyomingSessionService,
    decode_event, encode_event,
)


def packet(header, payload=b""):
    return json.dumps(header, separators=(",", ":")).encode() + b"\n" + payload


def test_event_packet_round_trip_and_exact_payload_bound():
    event=WyomingEvent("audio-chunk", {"rate":16000,"width":2,"channels":1}, b"synthetic-pcm")
    encoded=encode_event(event)
    assert decode_event(encoded) == event
    with pytest.raises(WyomingProtocolError, match="lengths"):
        decode_event(packet({"type":"audio-chunk","payload_length":20}, b"tiny"))


def test_read_event_supports_current_data_and_payload_framing():
    from hermes_installer.components.plugin_wyoming import _read_event

    class FakeSocket:
        def __init__(self, data): self.data=data
        def settimeout(self, _timeout): pass
        def recv(self, size):
            part, self.data=self.data[:size], self.data[size:]
            return part

    raw=packet({"type":"audio-chunk","data":{"rate":16000},"data_length":11,"payload_length":4},
               b'{"width":2}' + b"abcd")
    event=_read_event(FakeSocket(raw), 10**10)
    assert event == WyomingEvent("audio-chunk", {"rate":16000,"width":2}, b"abcd")


def test_endpoint_must_be_root_selected_numeric_local_address():
    endpoint=WyomingEndpoint("wyoming-stt", 1, "127.0.0.1", 10300, "stt")
    assert endpoint.uri == "tcp://127.0.0.1:10300"
    for address in ("8.8.8.8", "203.0.113.8", "169.254.1.2", "localhost"):
        with pytest.raises(ValueError):
            WyomingEndpoint("bad", 1, address, 10300, "stt")


def test_session_service_uses_root_selected_sealed_artifact_and_zeroes_pcm(monkeypatch):
    import hermes_installer.components.plugin_wyoming as module
    import hashlib
    from hermes_installer.components.plugin_channel_provenance import (
        AudioIngressSelection, SelectedAudioIngressProducer,
    )

    pcm = bytearray(b"synthetic-pcm!")
    digest = hashlib.sha256(pcm).hexdigest()
    class Observer:
        def observe_selected_audio_ingress(self, selection_handle, root_capture_record): return proof
        def validate_audio_observation(self, selection, observed, *, now_monotonic):
            if observed is not proof: raise PermissionError
            return {"schema":1,"proof_handle":"audio-proof-0001","selection_id":selection.id,
                "session_handle":"audio-session-0001","consent_receipt_handle":"consent-0001",
                "capture_receipt_handle":"capture-0001","audio_artifact_id":"artifact-0001",
                "audio_sha256":digest,"size_bytes":len(pcm),"format_schema_id":selection.sample_format_schema_id,
                "controller_identity_digest":"a"*64,"service_generation_digest":"b"*64,
                "issued_monotonic":95.0,"expires_monotonic":110.0}
    proof = object()
    selection=AudioIngressSelection("audio-selection","audio-channel",1,"profile-001","role-001",
        "issuer-001","device-001","backend-001","d"*64,"session-policy-001",16384,10,"pcm16-v1")
    producer=SelectedAudioIngressProducer(selection,"selected-handle-001",Observer(),clock=lambda:100.0)
    class Capture:
        def capture_selected_audio(self, handle, session_handle, *, max_bytes, max_seconds):
            assert handle=="selected-handle-001" and max_bytes==16384 and max_seconds==10
            assert session_handle=="session-handle-001"
            return object()
        def discard_selected_capture(self,*_args): pass
    class Store:
        def read_selected_capture(self,handle,observed,*,max_bytes): return pcm
        def consume_selected_capture(self,*_args): pass

    calls=[]
    class Client:
        def __init__(self, endpoint, *, timeout): calls.append(("client",endpoint.role,timeout)); self.role=endpoint.role
        def transcribe(self, audio): calls.append(("stt",audio)); return "synthetic transcript"
        def synthesize(self, text): calls.append(("tts",text)); return b"synthetic-output"
    monkeypatch.setattr(module, "WyomingClient", Client)
    endpoints={
        "stt":WyomingEndpoint("stt",1,"127.0.0.1",10300,"stt"),
        "home_stt":WyomingEndpoint("home",1,"127.0.0.1",10301,"home_stt"),
        "tts":WyomingEndpoint("piper",1,"127.0.0.1",10200,"tts"),
    }
    service=WyomingSessionService(Capture(),Store(),producer,endpoints)
    transcript, observed=service.transcribe_selected_capture("session-handle-001",endpoints["stt"].uri,timeout=15)
    assert transcript=="synthetic transcript" and observed.proof is proof
    assert calls[1][0]=="stt" and calls[1][1] is pcm
    assert pcm==bytearray(len(pcm))
    audio=service.synthesize_local(endpoints["tts"].uri,"hello",timeout=15)
    assert audio==b"synthetic-output"
    with pytest.raises(Exception, match="not root-selected"):
        service.transcribe_selected_capture("session-handle-001","tcp://127.0.0.1:1",timeout=1)


def test_session_service_denies_missing_selected_capture_authority():
    with pytest.raises(TypeError,match="root-selected audio provenance"):
        WyomingSessionService(object(),object(),object(),{})


def test_wyoming_stt_client_describes_selects_and_sends_bounded_pcm(monkeypatch):
    import hermes_installer.components.plugin_wyoming as module
    endpoint=WyomingEndpoint("whisper",1,"127.0.0.1",10300,"stt")
    server=b"".join(encode_event(event) for event in (
        WyomingEvent("info",{"asr":[{"name":"whisper","installed":True}]}),
        WyomingEvent("transcript",{"text":"fixture words"}),
    ))
    class FakeSocket:
        def __init__(self): self.incoming=bytearray(server); self.outgoing=[]
        def settimeout(self,_timeout): pass
        def sendall(self,data): self.outgoing.append(data)
        def recv(self,size):
            part,self.incoming=self.incoming[:size],self.incoming[size:]
            return bytes(part)
    fake=FakeSocket()
    class FakeConnection:
        def __init__(self,*_a): pass
        def __enter__(self): return fake
        def __exit__(self,*_a): pass
    monkeypatch.setattr(module,"_Connection",FakeConnection)
    assert WyomingClient(endpoint,timeout=2).transcribe(b"synthetic-pcm!")=="fixture words"
    sent=[decode_event(packet) for packet in fake.outgoing]
    assert [event.type for event in sent]==["describe","select-program","transcribe",
                                            "audio-start","audio-chunk","audio-stop"]
    assert sent[1].data["name"]=="whisper"
    assert sent[4].payload==b"synthetic-pcm!"


def test_wyoming_tts_client_requires_installed_program_and_fixed_piper_format(monkeypatch):
    import hermes_installer.components.plugin_wyoming as module
    endpoint=WyomingEndpoint("piper",1,"127.0.0.1",10200,"tts")
    server=b"".join(encode_event(event) for event in (
        WyomingEvent("info",{"tts":[{"name":"piper","installed":True}]}),
        WyomingEvent("audio-start",{"rate":22050,"width":2,"channels":1}),
        WyomingEvent("audio-chunk",{"rate":22050,"width":2,"channels":1},b"pcm"),
        WyomingEvent("audio-stop",{}),
    ))
    class FakeSocket:
        def __init__(self): self.incoming=bytearray(server)
        def settimeout(self,_timeout): pass
        def sendall(self,_data): pass
        def recv(self,size):
            part,self.incoming=self.incoming[:size],self.incoming[size:]
            return bytes(part)
    fake=FakeSocket()
    class FakeConnection:
        def __init__(self,*_a): pass
        def __enter__(self): return fake
        def __exit__(self,*_a): pass
    monkeypatch.setattr(module,"_Connection",FakeConnection)
    assert WyomingClient(endpoint,timeout=2).synthesize("hello") == b"pcm"
