"""Optional Jarvis integration with a fail-closed account gate.

The pinned Jarvis application expects an authenticated Claude Code account and
its Claude Agent SDK bridge. This adapter does not acquire or reuse login
material. It sends requests only through Hermes' shared provider dispatcher,
and it invokes an application launcher only after every explicit prerequisite
has been granted.
"""

from __future__ import annotations

import base64
import json
import math
import struct
import wave
from dataclasses import dataclass
from enum import StrEnum
from io import BytesIO
from typing import Callable, Iterable

from hermes_installer.policy import (
    Dispatcher,
    ProviderResponse,
    Sensitivity,
)


SOURCE_URL = "https://github.com/adewaskar/jarvis"
SOURCE_REVISION = "1c4016afdf86f7043efc6882ceffef84ad0d8783"
SOURCE_README_SHA256 = "adb82caba1f6c000b502e08620b6b67a89e866eeab7538303e9847287f86c385"
SOURCE_LICENSE = "MIT"
MAX_SYNTHETIC_AUDIO_BYTES = 64 * 1024
REQUIRED_PREREQUISITES = frozenset(
    {"claude_code_account", "claude_agent_sdk", "node20", "supported_browser", "isolated_runtime"}
)


class AccountEligibility(StrEnum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ActivationDecision:
    ready: bool
    status: str
    missing: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SyntheticVoiceFixture:
    """Fixed local text and a valid short PCM WAV tone used only by tests."""

    transcript: str
    audio_wav: bytes

    def __post_init__(self) -> None:
        if self.transcript != "hello from synthetic voice fixture":
            raise ValueError("Jarvis accepts only the fixed synthetic transcript in fixture mode")
        if not isinstance(self.audio_wav, bytes) or not 44 <= len(self.audio_wav) <= MAX_SYNTHETIC_AUDIO_BYTES:
            raise ValueError("synthetic WAV fixture is outside the allowed size")
        if not self.audio_wav.startswith(b"RIFF") or self.audio_wav[8:12] != b"WAVE":
            raise ValueError("synthetic audio fixture must be a WAV payload")


def make_synthetic_voice_fixture() -> SyntheticVoiceFixture:
    """Create 100 ms of deterministic 440 Hz PCM audio without microphone I/O."""
    sample_rate = 8_000
    frame_count = sample_rate // 10
    frames = b"".join(
        struct.pack("<h", int(3_000 * math.sin(2 * math.pi * 440 * index / sample_rate)))
        for index in range(frame_count)
    )
    buffer = BytesIO()
    with wave.open(buffer, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(sample_rate)
        audio.writeframes(frames)
    return SyntheticVoiceFixture("hello from synthetic voice fixture", buffer.getvalue())


class JarvisIntegration:
    """Policy-mediated request path and account-gated on-demand activation."""

    def __init__(self, dispatcher: Dispatcher):
        self.dispatcher = dispatcher

    @staticmethod
    def activation_decision(
        *, selected_explicitly: bool, account: AccountEligibility, prerequisites: Iterable[str]
    ) -> ActivationDecision:
        if not selected_explicitly:
            return ActivationDecision(False, "not_selected", ("explicit_optional_selection",))
        if account is not AccountEligibility.ELIGIBLE:
            reason = (
                "Claude Code account is ineligible"
                if account is AccountEligibility.INELIGIBLE
                else "Claude Code account eligibility has not been verified"
            )
            return ActivationDecision(False, "account_ineligible", (reason,))
        missing = tuple(sorted(REQUIRED_PREREQUISITES - frozenset(prerequisites)))
        if missing:
            return ActivationDecision(False, "prerequisites_missing", missing)
        return ActivationDecision(True, "ready")

    def activate(
        self,
        *,
        selected_explicitly: bool,
        account: AccountEligibility,
        prerequisites: Iterable[str],
        launcher: Callable[[], object],
    ) -> tuple[ActivationDecision, object | None]:
        """Run the isolated launcher only after the account and dependency gate."""
        decision = self.activation_decision(
            selected_explicitly=selected_explicitly,
            account=account,
            prerequisites=prerequisites,
        )
        if not decision.ready:
            return decision, None
        return decision, launcher()

    def dispatch_synthetic_fixture(self, *, context: object, model: str) -> ProviderResponse:
        """Send deterministic fixture bytes through the shared policy dispatcher."""
        fixture = make_synthetic_voice_fixture()
        payload = json.dumps(
            {
                "messages": [{
                    "role": "user",
                    "content": (
                        "Synthetic voice fixture transcript: " + fixture.transcript
                        + "\nWAV base64: " + base64.b64encode(fixture.audio_wav).decode("ascii")
                    ),
                }],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return self.dispatcher.dispatch(
            context,
            model,
            payload,
            input_tokens=64,
            output_token_limit=64,
            tool_request=False,
        )
