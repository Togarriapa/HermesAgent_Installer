"""Bounded client and session bridge for root-selected local Wyoming services."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from hermes_installer.components.plugin_local_voice_web import PluginAdapterError
from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection, ObservedChannelIngress, SelectedAudioIngressProducer,
)

MAX_PACKET_HEADER = 64 * 1024
MAX_PACKET_DATA = 64 * 1024
MAX_AUDIO_INPUT = 900_000
MAX_AUDIO_OUTPUT = 2_000_000
MAX_TEXT = 4000
CHUNK_BYTES = 32 * 1024


class WyomingProtocolError(RuntimeError):
    pass


def _is_trusted_local_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if address.is_loopback:
        return True
    blocks = ((ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
               ipaddress.ip_network("192.168.0.0/16")) if address.version == 4 else
              (ipaddress.ip_network("fc00::/7"),))
    return any(address in block for block in blocks)


@dataclass(frozen=True, slots=True)
class WyomingEndpoint:
    """Endpoint resolved from host-owned enrollment; no model-supplied address."""
    target_id: str
    generation: int
    address: str
    port: int
    role: str

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError:
            raise ValueError("Wyoming endpoint must use a pinned numeric address") from None
        if not _is_trusted_local_address(address):
            raise ValueError("Wyoming endpoint must be a root-selected local address")
        if (not self.target_id or len(self.target_id) > 128 or type(self.generation) is not int
                or self.generation < 1 or type(self.port) is not int or not 1 <= self.port <= 65535
                or self.role not in {"stt", "tts", "home_stt"}):
            raise ValueError("Wyoming endpoint enrollment is malformed")

    @property
    def uri(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"tcp://{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class WyomingEvent:
    type: str
    data: dict[str, Any]
    payload: bytes = b""


class RootSelectedAudioCaptureSource(Protocol):
    """Root device/session/consent reader; worker booleans are not accepted."""
    def capture_selected_audio(self, selection_handle: object, session_handle: object, *, max_bytes: int,
                               max_seconds: int) -> object: ...
    def discard_selected_capture(self, selection_handle: object, capture_record: object) -> None: ...


class OwnedAudioArtifactStore(Protocol):
    """Root-owned sealed capture store; paths and raw audio never cross the API."""
    def read_selected_capture(self, selection_handle: object, proof: object,
                              *, max_bytes: int) -> bytearray: ...
    def consume_selected_capture(self, selection_handle: object, proof: object) -> None: ...


class WyomingClient:
    def __init__(self, endpoint: WyomingEndpoint, *, timeout: float = 15.0):
        if not isinstance(endpoint, WyomingEndpoint):
            raise TypeError("Wyoming requires a host-enrolled endpoint")
        if not 0.1 <= timeout <= 30.0:
            raise ValueError("Wyoming deadline must be between 0.1 and 30 seconds")
        self.endpoint, self.timeout = endpoint, timeout

    def transcribe(self, audio: bytes | bytearray) -> str:
        if self.endpoint.role not in {"stt", "home_stt"}:
            raise WyomingProtocolError("selected endpoint is not an STT service")
        if not isinstance(audio, (bytes, bytearray)) or not audio or len(audio) > MAX_AUDIO_INPUT or len(audio) % 2:
            raise WyomingProtocolError("PCM input must be non-empty, bounded 16-bit mono data")
        deadline = time.monotonic() + self.timeout
        with self._connection() as sock:
            _describe_selected_program(sock, "asr", deadline)
            _write_event(sock, WyomingEvent("transcribe", {"language": "en"}), deadline)
            _write_event(sock, WyomingEvent("audio-start", {
                "rate": 16000, "width": 2, "channels": 1, "timestamp": 0,
            }), deadline)
            for offset in range(0, len(audio), CHUNK_BYTES):
                chunk = bytes(audio[offset:offset + CHUNK_BYTES])
                _write_event(sock, WyomingEvent("audio-chunk", {
                    "rate": 16000, "width": 2, "channels": 1, "timestamp": offset // 32,
                }, chunk), deadline)
            _write_event(sock, WyomingEvent("audio-stop", {"timestamp": len(audio) // 32}), deadline)
            while True:
                event = _read_event(sock, deadline)
                if event.type == "transcript":
                    text = event.data.get("text")
                    if not isinstance(text, str) or len(text) > MAX_TEXT:
                        raise WyomingProtocolError("Wyoming transcript is invalid")
                    return text
                if event.type in {"error", "not-recognized"}:
                    raise WyomingProtocolError("selected Wyoming STT did not produce a transcript")
                if event.type in {"transcript-start", "transcript-chunk", "transcript-stop"}:
                    continue
                raise WyomingProtocolError("unexpected Wyoming STT response event")

    def synthesize(self, text: str) -> bytes:
        if self.endpoint.role != "tts":
            raise WyomingProtocolError("selected endpoint is not a TTS service")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
            raise WyomingProtocolError("TTS text is invalid or oversized")
        deadline = time.monotonic() + self.timeout
        with self._connection() as sock:
            _describe_selected_program(sock, "tts", deadline)
            _write_event(sock, WyomingEvent("synthesize", {"text": text}), deadline)
            audio = bytearray()
            started = False
            while True:
                event = _read_event(sock, deadline, max_payload=MAX_AUDIO_OUTPUT)
                if event.type == "audio-start":
                    rate, width, channels = (event.data.get("rate"), event.data.get("width"),
                                             event.data.get("channels"))
                    # Piper is deliberately configured for one sink format so
                    # the protected playback adapter cannot guess audio traits.
                    if (rate, width, channels) != (22050, 2, 1):
                        raise WyomingProtocolError("Piper output must be 22050 Hz, 16-bit mono PCM")
                    started = True
                elif event.type == "audio-chunk":
                    if not started or not event.payload:
                        raise WyomingProtocolError("Wyoming TTS sent audio before its format")
                    audio.extend(event.payload)
                    if len(audio) > MAX_AUDIO_OUTPUT:
                        raise WyomingProtocolError("Wyoming TTS output exceeds its bound")
                elif event.type == "audio-stop":
                    if not started or not audio:
                        raise WyomingProtocolError("Wyoming TTS returned an empty audio stream")
                    return bytes(audio)
                elif event.type == "error":
                    raise WyomingProtocolError("selected Wyoming TTS returned an error")
                else:
                    raise WyomingProtocolError("unexpected Wyoming TTS response event")

    def _connection(self):
        return _Connection(self.endpoint.address, self.endpoint.port, self.timeout)


class _Connection:
    def __init__(self, address: str, port: int, timeout: float):
        self.address, self.port, self.timeout, self.sock = address, port, timeout, None

    def __enter__(self):
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.address, self.port))
        except OSError:
            sock.close()
            raise WyomingProtocolError("selected local Wyoming endpoint is unavailable") from None
        self.sock = sock
        return sock

    def __exit__(self, *_exc):
        if self.sock is not None:
            self.sock.close()


class WyomingSessionService:
    """Root-only local STT backend consuming a selected sealed audio artifact.

    There is deliberately no ``authorized`` boolean, worker session ID, direct
    microphone API, or playback sink here. A root workflow must first capture
    through its selected device/consent authority and issue a v40 proof.
    """
    def __init__(self, capture_source: RootSelectedAudioCaptureSource,
                 artifact_store: OwnedAudioArtifactStore,
                 ingress: SelectedAudioIngressProducer,
                 endpoints: dict[str, WyomingEndpoint]):
        if not isinstance(ingress, SelectedAudioIngressProducer):
            raise TypeError("voice adapter requires the root-selected audio provenance producer")
        if not all(callable(getattr(capture_source, name, None)) for name in
                   ("capture_selected_audio", "discard_selected_capture")):
            raise TypeError("voice adapter requires the root-selected consent/device capture authority")
        if not all(callable(getattr(artifact_store, name, None)) for name in
                   ("read_selected_capture", "consume_selected_capture")):
            raise TypeError("voice adapter requires the root-owned sealed audio artifact store")
        if set(endpoints) - {"stt", "home_stt", "tts"}:
            raise ValueError("unsupported Wyoming endpoint role")
        for role, endpoint in endpoints.items():
            if not isinstance(endpoint, WyomingEndpoint) or endpoint.role != role:
                raise ValueError("Wyoming endpoint roles must match the root enrollment map")
        if not ingress.selection_handle:
            raise TypeError("protected root audio selection handle is required")
        self.capture_source, self.artifact_store = capture_source, artifact_store
        self.ingress, self.endpoints = ingress, dict(endpoints)
        self._operation_lock = threading.Lock()

    def transcribe_selected_capture(self, session_handle: object, endpoint: str,
                                    *, timeout: float) -> tuple[str, ObservedChannelIngress]:
        """Capture and transcribe one root-observed artifact without retaining PCM."""
        if not self._operation_lock.acquire(blocking=False):
            raise PluginAdapterError("another voice operation is active")
        capture_record = None
        ingress = None
        audio = None
        try:
            selected = next((row for row in self.endpoints.values() if row.uri == endpoint
                             and row.role in {"stt", "home_stt"}), None)
            if selected is None:
                raise PluginAdapterError("requested Wyoming STT endpoint is not root-selected")
            if not isinstance(session_handle, str) or not 8 <= len(session_handle) <= 128:
                raise PluginAdapterError("root voice session handle is missing or malformed")
            selection = self.ingress.selection
            capture_record = self.capture_source.capture_selected_audio(
                self.ingress.protected_selection_handle, session_handle,
                max_bytes=min(selection.max_capture_bytes, MAX_AUDIO_INPUT),
                max_seconds=selection.max_capture_seconds)
            ingress = self.ingress.observe(capture_record)
            claims = self.ingress.proof_claims(ingress.proof)
            audio = self.artifact_store.read_selected_capture(
                self.ingress.protected_selection_handle, ingress.proof,
                max_bytes=min(selection.max_capture_bytes, MAX_AUDIO_INPUT))
            if (not isinstance(audio, bytearray) or not audio or len(audio) != claims["size_bytes"]
                    or len(audio) % 2 or hashlib.sha256(audio).hexdigest() != claims["audio_sha256"]):
                raise PluginAdapterError("root audio artifact differs from its selected capture receipt")
            if not self.ingress.validate_claims(ingress.proof):
                raise PluginAdapterError("audio consent, device selection or capture lease expired")
            transcript = WyomingClient(selected, timeout=min(timeout, 15.0)).transcribe(audio)
            if not self.ingress.validate_claims(ingress.proof):
                raise PluginAdapterError("audio source was revoked while local transcription ran")
            return transcript, ingress
        except PluginAdapterError:
            raise
        except Exception:
            raise PluginAdapterError("root-selected local audio transcription failed closed") from None
        finally:
            if audio is not None:
                for index in range(len(audio)):
                    audio[index] = 0
            if ingress is not None:
                try:
                    self.artifact_store.consume_selected_capture(
                        self.ingress.protected_selection_handle, ingress.proof)
                except Exception:
                    pass
            elif capture_record is not None:
                try:
                    self.capture_source.discard_selected_capture(
                        self.ingress.protected_selection_handle, capture_record)
                except Exception:
                    pass
            self._operation_lock.release()

    def synthesize_local(self, endpoint: str, text: str, *, timeout: float) -> bytes:
        selected = self.endpoints.get("tts")
        if selected is None or selected.uri != endpoint:
            raise PluginAdapterError("requested Piper endpoint is not root-selected")
        return WyomingClient(selected, timeout=min(timeout, 15.0)).synthesize(text)


def encode_event(event: WyomingEvent) -> bytes:
    if not isinstance(event.type, str) or not event.type or not isinstance(event.data, dict):
        raise WyomingProtocolError("invalid Wyoming event")
    if not isinstance(event.payload, bytes) or len(event.payload) > MAX_AUDIO_OUTPUT:
        raise WyomingProtocolError("invalid Wyoming payload")
    header: dict[str, Any] = {"type": event.type}
    if event.data:
        header["data"] = event.data
    if event.payload:
        header["payload_length"] = len(event.payload)
    try:
        encoded = json.dumps(header, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, RecursionError):
        raise WyomingProtocolError("Wyoming event is not valid JSON data") from None
    if len(encoded) > MAX_PACKET_HEADER:
        raise WyomingProtocolError("Wyoming header exceeds its byte limit")
    return encoded + event.payload


def decode_event(header_and_payload: bytes) -> WyomingEvent:
    if not isinstance(header_and_payload, bytes) or len(header_and_payload) > MAX_PACKET_HEADER + MAX_AUDIO_OUTPUT + MAX_PACKET_DATA:
        raise WyomingProtocolError("Wyoming packet exceeds its limit")
    header, sep, tail = header_and_payload.partition(b"\n")
    if not sep or len(header) > MAX_PACKET_HEADER:
        raise WyomingProtocolError("Wyoming packet header is malformed")
    try:
        parsed = json.loads(header)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise WyomingProtocolError("Wyoming packet header is invalid JSON") from None
    if not isinstance(parsed, dict) or set(parsed) - {"type", "data", "payload_length"}:
        raise WyomingProtocolError("Wyoming packet contains unsupported header fields")
    kind, data = parsed.get("type"), parsed.get("data", {})
    payload_length = parsed.get("payload_length", 0)
    if (not isinstance(kind, str) or not kind or not isinstance(data, dict)
            or type(payload_length) is not int or not 0 <= payload_length <= MAX_AUDIO_OUTPUT
            or len(tail) != payload_length):
        raise WyomingProtocolError("Wyoming packet lengths or values are invalid")
    return WyomingEvent(kind, data, tail)


def _write_event(sock: socket.socket, event: WyomingEvent, deadline: float) -> None:
    sock.settimeout(max(0.01, deadline - time.monotonic()))
    try:
        sock.sendall(encode_event(event))
    except OSError:
        raise WyomingProtocolError("Wyoming request write failed") from None


def _describe_selected_program(sock: socket.socket, domain: str, deadline: float) -> None:
    _write_event(sock, WyomingEvent("describe", {}), deadline)
    info = _read_event(sock, deadline)
    if info.type != "info":
        raise WyomingProtocolError("Wyoming service did not answer describe with info")
    programs = info.data.get(domain)
    if not isinstance(programs, list) or not programs:
        raise WyomingProtocolError(f"Wyoming endpoint does not expose the enrolled {domain} service")
    selected = next((row for row in programs if isinstance(row, dict) and row.get("installed") is True
                     and isinstance(row.get("name"), str) and row["name"]), None)
    if selected is None:
        raise WyomingProtocolError(f"Wyoming endpoint has no installed {domain} program")
    _write_event(sock, WyomingEvent("select-program", {"name": selected["name"]}), deadline)


def _read_exact(sock: socket.socket, count: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WyomingProtocolError("Wyoming response exceeded its deadline")
        sock.settimeout(remaining)
        try:
            data = sock.recv(min(65536, count - len(chunks)))
        except OSError:
            raise WyomingProtocolError("Wyoming response read failed") from None
        if not data:
            raise WyomingProtocolError("Wyoming endpoint closed an incomplete response")
        chunks.extend(data)
    return bytes(chunks)


def _read_event(sock: socket.socket, deadline: float,
                max_payload: int = MAX_AUDIO_OUTPUT) -> WyomingEvent:
    header = bytearray()
    while len(header) < MAX_PACKET_HEADER:
        byte = _read_exact(sock, 1, deadline)
        if byte == b"\n":
            break
        header.extend(byte)
    else:
        raise WyomingProtocolError("Wyoming response header exceeds its limit")
    try:
        parsed = json.loads(header)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise WyomingProtocolError("Wyoming response header is invalid JSON") from None
    if not isinstance(parsed, dict) or set(parsed) - {"type", "data", "data_length", "payload_length"}:
        raise WyomingProtocolError("Wyoming response header has unsupported fields")
    data, data_length = parsed.get("data", {}), parsed.get("data_length", 0)
    payload_length = parsed.get("payload_length", 0)
    if (not isinstance(data, dict) or type(data_length) is not int
            or not 0 <= data_length <= MAX_PACKET_DATA or type(payload_length) is not int
            or not 0 <= payload_length <= max_payload):
        raise WyomingProtocolError("Wyoming response lengths are invalid")
    if data_length:
        try:
            extra = json.loads(_read_exact(sock, data_length, deadline))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise WyomingProtocolError("Wyoming response event data is invalid") from None
        if not isinstance(extra, dict) or set(data).intersection(extra):
            raise WyomingProtocolError("Wyoming response data fields conflict")
        data = {**data, **extra}
    payload = _read_exact(sock, payload_length, deadline) if payload_length else b""
    kind = parsed.get("type")
    if not isinstance(kind, str) or not kind:
        raise WyomingProtocolError("Wyoming response event has no type")
    return WyomingEvent(kind, data, payload)
