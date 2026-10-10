from __future__ import annotations

import contextlib
import hashlib
import os
import socket
from types import SimpleNamespace

import pytest

from hermes_installer.authority.channel_ingress_services import RootInMemoryAudioArtifactCatalog
from hermes_installer.authority.local_audio_device import (
    LocalAudioDeviceUnavailable, RootLocalAudioDeviceService,
    RootSelectedAudioArtifactStore, SOUNDDEVICE_VERSION,
)
from hermes_installer.authority.channel_provenance import RootSelectedAudioIngressObserver
from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection, SelectedAudioIngressProducer,
)


def _selection():
    return AudioIngressSelection(
        id="audio-selection-01", channel_resource_id="audio-resource-01", resource_generation=1,
        profile_id="profile-audio-01", controller_role_id="role-audio-01",
        source_issuer_id="issuer-audio-01", device_enrollment_id="device-audio-01",
        capture_backend_artifact_id="capture-backend-01", capture_backend_sha256="a" * 64,
        session_policy_id="session-policy-01", max_capture_bytes=32768,
        max_capture_seconds=2, sample_format_schema_id="pcm16-mono-16000-v1",
    )


class _FakeSoundDevice:
    __version__ = SOUNDDEVICE_VERSION

    def __init__(self):
        self.devices = [
            {"name": "output only", "hostapi": 0, "max_input_channels": 0,
             "default_samplerate": 48000.0},
            {"name": "USB microphone", "hostapi": 0, "max_input_channels": 1,
             "default_samplerate": 16000.0},
        ]
        self.opened = []

    def query_devices(self):
        return list(self.devices)

    def query_hostapis(self):
        return [{"name": "ALSA"}]

    def RawInputStream(self, **kwargs):
        self.opened.append(kwargs)
        return _FakeStream()


class _FakeStream:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def read(self, frames):
        return bytes([0x01, 0x00]) * frames, False

    def close(self):
        self.closed = True


def _tty_response(response: str):
    @contextlib.contextmanager
    def terminal():
        local, peer = socket.socketpair()
        try:
            peer.sendall(response.encode("ascii") + b"\n")
            yield local.fileno()
        finally:
            local.close()
            peer.close()
    return terminal


def test_root_audio_service_requires_tty_choice_then_fresh_consent_and_seals_pcm():
    selection = _selection()
    selection_handle = object()
    clock = SimpleNamespace(now=100.0)
    sd = _FakeSoundDevice()
    catalog = RootInMemoryAudioArtifactCatalog(selection, selection_handle,
        owner_generation="owner-generation-01", monotonic=lambda: clock.now)
    service = RootLocalAudioDeviceService(selection, selection_handle, profile_id="profile-audio-01",
        owner_generation="owner-generation-01", artifact_catalog=catalog,
        sounddevice_module=sd, monotonic=lambda: clock.now)
    service._tty = _tty_response("1")
    enrolled = service.adopt_device_from_tty()
    assert enrolled.device_index == 1  # the root TTY selected the listed microphone, not PortAudio default
    assert enrolled.identity_digest == service.enumerate_devices()[0].identity_digest

    service._tty = _tty_response("CAPTURE")
    session = service.open_input_session()
    record = service.capture_selected_audio(selection_handle, session.session_handle,
                                             max_bytes=selection.max_capture_bytes, max_seconds=2)
    request = service.take_capture_workflow_result(selection_handle, record)
    artifact = catalog.resolve_capture(selection_handle, session, request.artifact_id)
    audio = catalog.read_capture_bytes(selection_handle, session, artifact,
                                       maximum_bytes=selection.max_capture_bytes)
    assert audio == bytearray([0x01, 0x00] * 16384)
    assert artifact.size_bytes == 32768 and artifact.sha256 == hashlib.sha256(audio).hexdigest()
    assert sd.opened == [{"device": 1, "samplerate": 16000, "channels": 1,
                          "dtype": "int16", "blocksize": 1024}]
    assert service.current_input_session(selection_handle, session.session_handle) is session
    service.close_input_session(selection_handle, session.session_handle)
    with pytest.raises(LocalAudioDeviceUnavailable, match="unknown, closed or revoked"):
        service.current_input_session(selection_handle, session.session_handle)
    with pytest.raises(Exception, match="audio artifact is stale, consumed or reconstructed"):
        catalog.read_capture_bytes(selection_handle, session, artifact,
                                   maximum_bytes=selection.max_capture_bytes)
    assert catalog._items == {}


def test_audio_service_denies_unselected_default_drift_wrong_runtime_and_expired_consent():
    selection = _selection()
    selection_handle = object()
    now = [200.0]
    sd = _FakeSoundDevice()
    catalog = RootInMemoryAudioArtifactCatalog(selection, selection_handle,
        owner_generation="owner-generation-01", monotonic=lambda: now[0])
    service = RootLocalAudioDeviceService(selection, selection_handle, profile_id="profile-audio-01",
        owner_generation="owner-generation-01", artifact_catalog=catalog,
        sounddevice_module=sd, monotonic=lambda: now[0], tty_path="/path/that/does/not/exist")
    with pytest.raises(LocalAudioDeviceUnavailable, match="foreground root TTY"):
        service.adopt_device_from_tty()

    service._tty = _tty_response("1")
    service.adopt_device_from_tty()
    sd.devices[1]["name"] = "replacement device"
    service._tty = _tty_response("CAPTURE")
    with pytest.raises(LocalAudioDeviceUnavailable, match="changed"):
        service.open_input_session()

    sd.devices[1]["name"] = "USB microphone"
    service._tty = _tty_response("1")
    service.adopt_device_from_tty()
    service._tty = _tty_response("")
    with pytest.raises(LocalAudioDeviceUnavailable, match="declined"):
        service.open_input_session()

    service._tty = _tty_response("CAPTURE")
    session = service.open_input_session(requested_lease_seconds=1)
    now[0] += 2
    with pytest.raises(LocalAudioDeviceUnavailable, match="no longer current"):
        service.current_input_session(selection_handle, session.session_handle)

    wrong_version = _FakeSoundDevice()
    wrong_version.__version__ = "0.0-unpinned"
    bad_catalog = RootInMemoryAudioArtifactCatalog(selection, selection_handle,
        owner_generation="owner-generation-01")
    bad = RootLocalAudioDeviceService(selection, selection_handle, profile_id="profile-audio-01",
        owner_generation="owner-generation-01", artifact_catalog=bad_catalog,
        sounddevice_module=wrong_version)
    with pytest.raises(LocalAudioDeviceUnavailable, match="pinned source"):
        bad.enumerate_devices()


def test_real_root_audio_proof_resolver_reads_and_consumes_only_current_sealed_artifact():
    selection = _selection()
    selection_handle = object()
    sd = _FakeSoundDevice()
    catalog = RootInMemoryAudioArtifactCatalog(selection, selection_handle,
        owner_generation="owner-generation-01")
    service = RootLocalAudioDeviceService(selection, selection_handle, profile_id="profile-audio-01",
        owner_generation="owner-generation-01", artifact_catalog=catalog,
        sounddevice_module=sd)
    service._tty = _tty_response("1")
    service.adopt_device_from_tty()
    service._tty = _tty_response("CAPTURE")
    session = service.open_input_session()
    record = service.capture_selected_audio(selection_handle, session.session_handle,
                                             max_bytes=selection.max_capture_bytes, max_seconds=2)
    resolver = service.create_capture_receipt_resolver()
    observer = RootSelectedAudioIngressObserver(
        selection, selection_handle, resolver,
        controller_identity_digest="c" * 64, service_generation_digest="d" * 64)
    producer = SelectedAudioIngressProducer(selection, selection_handle, observer)
    observed = producer.observe(record)
    artifact_store = RootSelectedAudioArtifactStore(
        selection, selection_handle, observer, resolver)

    audio = artifact_store.read_selected_capture(
        selection_handle, observed.proof, max_bytes=selection.max_capture_bytes)
    assert len(audio) == 32768 and audio[:2] == b"\x01\x00"
    artifact_store.consume_selected_capture(selection_handle, observed.proof)
    with pytest.raises(LocalAudioDeviceUnavailable, match="stale, replayed"):
        artifact_store.read_selected_capture(
            selection_handle, observed.proof, max_bytes=selection.max_capture_bytes)
    audio[:] = b"\0" * len(audio)
    service.close_input_session(selection_handle, session.session_handle)
    assert catalog._items == {}
