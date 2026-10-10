"""Root-selected local audio device enrollment and consented PCM capture.

The module never chooses PortAudio's default device. A root TTY operator must
select one enumerated input device during enrollment and explicitly approve
each short-lived input session. Device drift, absent TTY, unavailable pinned
runtime, revocation, overrun, or format mismatch fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import select
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .channel_ingress_services import (
    IngressServiceDenied, RootAudioCaptureRequest, RootAudioInputSession,
    RootInMemoryAudioArtifactCatalog,
)
from hermes_installer.components.plugin_channel_provenance import AudioIngressSelection


SOUNDDEVICE_VERSION = "0.5.6"
SOUNDDEVICE_SOURCE_COMMIT = "bd3f0dfe325a45506eea8d97d91949cc4e9dbb4f"
SOUNDDEVICE_SDIST_SHA256 = "8ec9fbfde2e32f020b167e348f3ab3bac6625a5f15af524d790108ac7147a410"
_MAX_SESSION_SECONDS = 60
_FORMAT_SCHEMA = "pcm16-mono-16000-v1"


class LocalAudioDeviceUnavailable(PermissionError):
    """No current root-selected, explicitly consented audio route is usable."""


@dataclass(frozen=True, slots=True)
class AudioDeviceCandidate:
    index: int
    name: str
    host_api: str
    max_input_channels: int
    default_samplerate: int
    identity_digest: str


@dataclass(frozen=True, slots=True)
class RootAudioDeviceEnrollment:
    """Immutable root-owned device choice, bound to the installer selection."""
    selection_id: str
    profile_id: str
    owner_generation: str
    device_enrollment_id: str
    device_index: int
    device_name: str
    host_api: str
    max_input_channels: int
    default_samplerate: int
    identity_digest: str
    _seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _Consent:
    selection_id: str
    profile_id: str
    owner_generation: str
    session_handle: str
    device_identity_digest: str
    consent_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _CaptureResult:
    session_handle: str
    artifact_id: str
    operation_id: str
    session: RootAudioInputSession = field(repr=False)
    _seal: object = field(repr=False, compare=False)


class RootLocalAudioDeviceService:
    """Concrete root service implementing the selected capture/session ports.

    ``selection`` and ``selection_handle`` must come from the protected active
    ingress snapshot. Enrollment is produced only by ``adopt_device_from_tty``;
    session permission is a fresh exact typed grant from ``open_input_session``.
    """

    def __init__(self, selection: AudioIngressSelection, selection_handle: object, *,
                 profile_id: str, owner_generation: str,
                 artifact_catalog: RootInMemoryAudioArtifactCatalog,
                 sounddevice_module: Any | None = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 tty_path: str = "/dev/tty") -> None:
        if (not isinstance(selection, AudioIngressSelection) or selection_handle is None
                or not profile_id or not owner_generation
                or not isinstance(artifact_catalog, RootInMemoryAudioArtifactCatalog)
                or artifact_catalog.selection is not selection
                or artifact_catalog.selection_handle is not selection_handle
                or selection.sample_format_schema_id != _FORMAT_SCHEMA):
            raise ValueError("active protected audio selection and matching private artifact catalog are required")
        self.selection, self.selection_handle = selection, selection_handle
        self.profile_id, self.owner_generation = profile_id, owner_generation
        self.artifact_catalog, self._sounddevice = artifact_catalog, sounddevice_module
        self.monotonic, self.tty_path = monotonic, tty_path
        self._seal = object()
        self._lock = threading.RLock()
        self._enrollment: RootAudioDeviceEnrollment | None = None
        self._sessions: dict[str, tuple[RootAudioInputSession, _Consent]] = {}
        self._workflow_results: dict[int, tuple[object, _CaptureResult]] = {}
        self._session_artifacts: dict[str, tuple[RootAudioInputSession, set[str]]] = {}
        self._capture_busy = False

    def enumerate_devices(self) -> tuple[AudioDeviceCandidate, ...]:
        sounddevice = self._runtime()
        try:
            devices = sounddevice.query_devices()
            host_apis = sounddevice.query_hostapis()
        except Exception:
            raise LocalAudioDeviceUnavailable("PortAudio device enumeration failed") from None
        rows: list[AudioDeviceCandidate] = []
        for index, device in enumerate(devices):
            try:
                if type(device["max_input_channels"]) is not int or device["max_input_channels"] < 1:
                    continue
                name = device["name"]
                host_index = device["hostapi"]
                rate = float(device["default_samplerate"])
                if (not isinstance(name, str) or not name.strip() or type(host_index) is not int
                        or not 0 <= host_index < len(host_apis) or not rate.is_integer()
                        or not 8000 <= rate <= 192000):
                    continue
                host_name = host_apis[host_index]["name"]
                if not isinstance(host_name, str) or not host_name:
                    continue
                candidate = self._candidate(index, name, host_name,
                                            device["max_input_channels"], int(rate))
                rows.append(candidate)
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
        if not rows:
            raise LocalAudioDeviceUnavailable("no usable audio input devices were enumerated")
        return tuple(rows)

    def adopt_device_from_tty(self) -> RootAudioDeviceEnrollment:
        """Show all current input choices and require one explicit human choice."""
        candidates = self.enumerate_devices()
        with self._tty() as fd:
            lines = ["Select a microphone for this protected Hermes profile:"]
            lines.extend(f"{position}. {row.name} ({row.host_api}; {row.max_input_channels} input channels)"
                         for position, row in enumerate(candidates, 1))
            lines.append("Enter one number; blank cancels: ")
            self._write_tty(fd, "\n".join(lines))
            response = self._read_tty_line(fd, deadline=self.monotonic() + 60)
        if not response or not response.isascii() or not response.isdecimal():
            raise LocalAudioDeviceUnavailable("microphone selection was cancelled or invalid")
        choice = int(response)
        if not 1 <= choice <= len(candidates):
            raise LocalAudioDeviceUnavailable("microphone selection is outside the displayed choices")
        selected = candidates[choice - 1]
        # Re-enumerate after the operator's choice and require the exact same
        # complete device row. No system default or fallback is consulted.
        if selected not in self.enumerate_devices():
            raise LocalAudioDeviceUnavailable("audio device changed during enrollment")
        row = RootAudioDeviceEnrollment(
            self.selection.id, self.profile_id, self.owner_generation,
            self.selection.device_enrollment_id, selected.index, selected.name,
            selected.host_api, selected.max_input_channels, selected.default_samplerate,
            selected.identity_digest, self._seal,
        )
        with self._lock:
            self._enrollment = row
        return row

    def open_input_session(self, *, requested_lease_seconds: int = 60) -> RootAudioInputSession:
        if type(requested_lease_seconds) is not int or not 1 <= requested_lease_seconds <= _MAX_SESSION_SECONDS:
            raise LocalAudioDeviceUnavailable("audio session lease is outside its selected bound")
        enrollment = self._current_enrollment()
        if not self._device_is_current(enrollment):
            raise LocalAudioDeviceUnavailable("selected microphone changed; re-enroll the device")
        session_handle = secrets.token_urlsafe(32)
        consent_handle = secrets.token_urlsafe(32)
        issued = self.monotonic()
        expires = issued + requested_lease_seconds
        with self._tty() as fd:
            self._write_tty(fd, (
                f"Hermes will capture up to 30 seconds from selected microphone "
                f"'{enrollment.device_name}' for profile '{self.profile_id}'. "
                "This is an input permission only; it does not identify the speaker. "
                "Type exactly CAPTURE to permit this session, or press Enter to cancel: "
            ))
            response = self._read_tty_line(fd, deadline=min(expires, self.monotonic() + 30))
        if response != "CAPTURE" or not self._device_is_current(enrollment):
            raise LocalAudioDeviceUnavailable("explicit capture permission was declined or device changed")
        consent = _Consent(self.selection.id, self.profile_id, self.owner_generation,
                           session_handle, enrollment.identity_digest, consent_handle,
                           issued, expires, self._seal)
        session = RootAudioInputSession(session_handle, self.profile_id, self.owner_generation,
                                        enrollment.device_enrollment_id, enrollment.identity_digest,
                                        consent_handle, expires)
        with self._lock:
            self._sessions[session_handle] = (session, consent)
            self._session_artifacts[session_handle] = (session, set())
        return session

    def current_input_session(self, selection_handle: object,
                              session_handle: str) -> RootAudioInputSession:
        self._require_selection(selection_handle)
        with self._lock:
            row = self._sessions.get(session_handle)
        if row is None:
            raise LocalAudioDeviceUnavailable("audio session is unknown, closed or revoked")
        session, consent = row
        if (consent._seal is not self._seal or consent.session_handle != session.session_handle
                or consent.selection_id != self.selection.id or consent.profile_id != self.profile_id
                or consent.owner_generation != self.owner_generation
                or consent.device_identity_digest != session.device_identity_digest
                or consent.consent_receipt_handle != session.consent_receipt_handle
                or not consent.issued_monotonic <= self.monotonic() < consent.expires_monotonic
                or not self._device_is_current(self._current_enrollment())):
            self.close_input_session(selection_handle, session_handle)
            raise LocalAudioDeviceUnavailable("audio permission, generation or selected device is no longer current")
        return session

    def close_input_session(self, selection_handle: object, session_handle: str) -> None:
        self._require_selection(selection_handle)
        with self._lock:
            self._sessions.pop(session_handle, None)
            artifact_session, artifact_ids = self._session_artifacts.pop(
                session_handle, (None, set()))
            records = [record for record, (_capture, row) in self._workflow_results.items()
                       if row.session_handle == session_handle]
            for record in records:
                _record, capture = self._workflow_results.pop(record)
                artifact_ids.add(capture.artifact_id)
            for artifact_id in artifact_ids:
                try:
                    artifact = self.artifact_catalog.resolve_capture(
                        selection_handle, artifact_session, artifact_id)
                    self.artifact_catalog.consume_capture(selection_handle, artifact)
                except Exception:
                    pass

    def capture_selected_audio(self, selection_handle: object, session_handle: object, *,
                               max_bytes: int, max_seconds: int) -> object:
        self._require_selection(selection_handle)
        if (type(max_bytes) is not int or not 1 <= max_bytes <= self.selection.max_capture_bytes
                or type(max_seconds) is not int or not 1 <= max_seconds <= min(30, self.selection.max_capture_seconds)):
            raise LocalAudioDeviceUnavailable("capture bounds exceed the protected audio selection")
        session = self.current_input_session(selection_handle, session_handle)
        enrollment = self._current_enrollment()
        if session.device_identity_digest != enrollment.identity_digest:
            raise LocalAudioDeviceUnavailable("audio session is bound to another microphone")
        with self._lock:
            if self._capture_busy:
                raise LocalAudioDeviceUnavailable("another selected microphone capture is active")
            self._capture_busy = True
        pcm: bytearray | None = None
        try:
            pcm = self._capture_pcm(enrollment, max_seconds=max_seconds,
                                    maximum_bytes=min(max_bytes, self.selection.max_capture_bytes))
            if not self.current_input_session(selection_handle, session_handle):
                raise LocalAudioDeviceUnavailable("audio session expired during capture")
            operation_id = secrets.token_urlsafe(32)
            artifact = self.artifact_catalog.store_capture(selection_handle, session, pcm,
                                                           operation_id=operation_id)
            pcm = None  # store_capture transfers bytes and wipes the supplied buffer
            result = _CaptureResult(session_handle, artifact.artifact_id, operation_id, session, self._seal)
            opaque = object()
            with self._lock:
                self._workflow_results[id(opaque)] = (opaque, result)
                self._session_artifacts[session_handle][1].add(artifact.artifact_id)
            return opaque
        finally:
            if pcm is not None:
                pcm[:] = b"\0" * len(pcm)
            with self._lock:
                self._capture_busy = False

    def discard_selected_capture(self, selection_handle: object, capture_record: object) -> None:
        self._require_selection(selection_handle)
        with self._lock:
            row = self._workflow_results.pop(id(capture_record), None)
        if row is None or row[0] is not capture_record:
            return
        capture = row[1]
        session = self.current_input_session(selection_handle, capture.session_handle)
        artifact = self.artifact_catalog.resolve_capture(selection_handle, session, capture.artifact_id)
        self.artifact_catalog.consume_capture(selection_handle, artifact)
        with self._lock:
            self._session_artifacts.get(capture.session_handle, (None, set()))[1].discard(capture.artifact_id)

    def take_capture_workflow_result(self, selection_handle: object,
                                     workflow_result: object) -> RootAudioCaptureRequest:
        self._require_selection(selection_handle)
        with self._lock:
            row = self._workflow_results.pop(id(workflow_result), None)
        if row is None or row[0] is not workflow_result or row[1]._seal is not self._seal:
            raise LocalAudioDeviceUnavailable("capture workflow result is unknown or already consumed")
        capture = row[1]
        try:
            self.current_input_session(selection_handle, capture.session_handle)
        except Exception:
            try:
                artifact = self.artifact_catalog.resolve_capture(
                    selection_handle, capture.session, capture.artifact_id)
                self.artifact_catalog.consume_capture(selection_handle, artifact)
            except Exception:
                pass
            raise
        return RootAudioCaptureRequest(capture.session_handle, capture.artifact_id)

    def _capture_pcm(self, enrollment: RootAudioDeviceEnrollment, *,
                     max_seconds: int, maximum_bytes: int) -> bytearray:
        if sys.byteorder != "little":
            raise LocalAudioDeviceUnavailable("selected audio format requires little-endian PCM host")
        if not self._device_is_current(enrollment):
            raise LocalAudioDeviceUnavailable("selected microphone changed before capture")
        sounddevice = self._runtime()
        maximum_frames = min(max_seconds * 16000, maximum_bytes // 2)
        if maximum_frames < 16:
            raise LocalAudioDeviceUnavailable("selected capture limit is shorter than one millisecond")
        output = bytearray()
        frames_left = maximum_frames
        stream = None
        try:
            stream = sounddevice.RawInputStream(device=enrollment.device_index,
                samplerate=16000, channels=1, dtype="int16", blocksize=1024)
            with stream:
                while frames_left:
                    count = min(1024, frames_left)
                    data, overflowed = stream.read(count)
                    chunk = bytes(data)
                    if overflowed or len(chunk) != count * 2 or len(output) + len(chunk) > maximum_bytes:
                        raise LocalAudioDeviceUnavailable("microphone overflowed or returned malformed PCM")
                    output.extend(chunk)
                    frames_left -= count
        except LocalAudioDeviceUnavailable:
            raise
        except Exception:
            raise LocalAudioDeviceUnavailable("selected microphone capture failed") from None
        finally:
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        if (len(output) % 32 != 0 or not output
                or len(output) > min(maximum_bytes, max_seconds * 32000)):
            output[:] = b"\0" * len(output)
            raise LocalAudioDeviceUnavailable("captured PCM differs from the selected bound")
        return output

    def _device_is_current(self, enrollment: RootAudioDeviceEnrollment) -> bool:
        if enrollment._seal is not self._seal:
            return False
        try:
            current = next(row for row in self.enumerate_devices() if row.index == enrollment.device_index)
        except (StopIteration, LocalAudioDeviceUnavailable):
            return False
        return current == AudioDeviceCandidate(enrollment.device_index, enrollment.device_name,
            enrollment.host_api, enrollment.max_input_channels, enrollment.default_samplerate,
            enrollment.identity_digest)

    def _candidate(self, index: int, name: str, host_api: str,
                   channels: int, rate: int) -> AudioDeviceCandidate:
        identity = hashlib.sha256(json.dumps({"index": index, "name": name,
            "host_api": host_api, "max_input_channels": channels,
            "default_samplerate": rate}, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        return AudioDeviceCandidate(index, name, host_api, channels, rate, identity)

    def _runtime(self) -> Any:
        module = self._sounddevice
        if module is None:
            try:
                import sounddevice as module
            except Exception:
                raise LocalAudioDeviceUnavailable("pinned sounddevice runtime is unavailable") from None
        if (getattr(module, "__version__", None) != SOUNDDEVICE_VERSION
                or not callable(getattr(module, "query_devices", None))
                or not callable(getattr(module, "query_hostapis", None))
                or not callable(getattr(module, "RawInputStream", None))):
            raise LocalAudioDeviceUnavailable("sounddevice runtime is not the pinned source")
        return module

    def _current_enrollment(self) -> RootAudioDeviceEnrollment:
        with self._lock:
            row = self._enrollment
        if (row is None or row._seal is not self._seal or row.selection_id != self.selection.id
                or row.profile_id != self.profile_id or row.owner_generation != self.owner_generation
                or row.device_enrollment_id != self.selection.device_enrollment_id):
            raise LocalAudioDeviceUnavailable("no root-adopted microphone is selected for this profile")
        return row

    def _require_selection(self, handle: object) -> None:
        if handle is not self.selection_handle:
            raise LocalAudioDeviceUnavailable("audio selection handle is not current")

    def _tty(self):
        import contextlib

        @contextlib.contextmanager
        def opened():
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(self.tty_path, flags)
                st = os.fstat(fd)
                if not os.isatty(fd) or not __import__("stat").S_ISCHR(st.st_mode):
                    raise OSError("controlling terminal is not a character device")
                if os.tcgetpgrp(fd) != os.getpgrp():
                    raise OSError("root workflow does not own the foreground terminal")
            except Exception:
                try:
                    os.close(fd)
                except Exception:
                    pass
                raise LocalAudioDeviceUnavailable("foreground root TTY is required for audio choice/consent") from None
            try:
                yield fd
            finally:
                os.close(fd)
        return opened()

    @staticmethod
    def _write_tty(fd: int, value: str) -> None:
        os.write(fd, value.encode("utf-8", "strict"))

    def _read_tty_line(self, fd: int, *, deadline: float) -> str:
        data = bytearray()
        while len(data) <= 16:
            timeout = deadline - self.monotonic()
            if timeout <= 0 or not select.select([fd], [], [], timeout)[0]:
                raise LocalAudioDeviceUnavailable("root TTY audio confirmation timed out")
            chunk = os.read(fd, 1)
            if not chunk or chunk in (b"\n", b"\r"):
                break
            if chunk[0] < 32 or chunk[0] > 126:
                raise LocalAudioDeviceUnavailable("root TTY response contains unsupported characters")
            data.extend(chunk)
        if len(data) > 16:
            raise LocalAudioDeviceUnavailable("root TTY response exceeds its bound")
        return data.decode("ascii")
