# Native voice source audit

**Evidence boundary:** source-only review of Hermes Agent commit
`7085fbf7753266fc4943c55ac04926186bc90005` (verified with `git rev-parse HEAD`)
and this installer's current Jarvis assets and plan. No Pi runtime, provider
account, phone, or tablet was exercised. This records API candidates, not a
ready or accepted adapter.

## What exists

The pinned source exposes voice controls through its authenticated TUI JSON-RPC
transport (`tui_gateway/methods_voice.py`):

| Method/event | Source behavior | Installer implication |
|---|---|---|
| `voice.toggle(action=status)` | Probes local voice/STT requirements and returns `available`, `audio_available`, `stt_available`, and a details string (lines 623–635). `on`/`off` and `tts` mutate process-wide `HERMES_VOICE` / `HERMES_VOICE_TTS` flags (638–691). | Status is a useful read-only observation. Toggle is process-global, so it cannot be exposed as a per-browser preference. The status probe does not prove account eligibility, route privacy, cost, or phone playback. |
| `voice.record(action=start|stop)` | Starts/stops Hermes' server-side `hermes_cli.voice` continuous recorder, VAD-bounds capture (default cap 120s), emits partial/final transcript/status events, and may pause/resume the process wake listener (714–779). | This captures the Pi's microphone. It does not accept mobile microphone audio. It needs actual Pi audio/STT dependencies and selected-provider route authorization. |
| `voice.tts(text)` | Starts `hermes_cli.voice` speech on the Hermes host and immediately reports `speaking` (781–791). | Output is host playback, with no browser audio-return contract. It is not a tablet/phone response adapter. |
| `wake.start/status/stop/pause/resume` | A single process listener has a transport owner; availability is checked before arming. GUI clients may select client capture (402–408, 460–518, 521–591). | Candidate for a future owner-bound adapter only after target support is proven. The RPC's transport ownership is not yet the Jarvis principal/profile authorization contract. |
| `wake.feed` | Accepts base64 PCM, caps each frame at 64,000 bytes, requires 16 kHz when specified, and calls `feed_audio(owner=caller_transport, ...)` (596–620). | This is wake-detector PCM input, not STT input. Reusing it as general audio upload would be an API/security error. |
| Voice events | `voice.status`, `voice.partial`, `voice.transcript`, `voice.interrupted`, and `wake.detected` have bounded typed payloads (TUI event contracts, lines 656–694). | These could support a finite adapter after ownership, lifecycle, cancellation, and privacy behavior are proved against the installed Pi runtime. |

Hermes' own documentation names different runtime requirements by path:
`sounddevice`, `numpy`, and supported Faster-Whisper for CLI/local STT; cloud STT
providers and separate TTS providers; optional local engines can need native
packages or model downloads. Wake choices include local openWakeWord and sherpa,
or keyed Porcupine; sherpa downloads its English model on first use. The docs
also state target-specific support limits (`website/docs/user-guide/features/
voice-mode.md`, `tts.md`, and `wake-word.md`). Therefore source availability,
provider names marked free, and a Codex subscription do not establish installed
ARM64 dependencies, a working provider account, free operation, or zero extra
metered use. Keep additional metered voice spend at zero unless a separately
authorized route is verified.

## Existing Jarvis browser path

The current browser UI already has a conservative first-use path:

- Speech recognition is shown only when `SpeechRecognition` (or its WebKit
  name) and a secure context are present. The user checks page-local consent and
  taps once; recognition stops when the page is hidden, the user cancels, or a
  turn starts. Final text is inserted into the composer for review before send.
  Unsupported/error cases preserve typing (`jarvis_chat_assets.py`, lines
  546–663, 1207–1217, 1247–1253).
- Browser speech synthesis reads completed replies only after its separate
  setting is on, supports stop/cancel, and stops on navigation or backgrounding
  (lines 502–544, 1219–1227, 1247–1253).
- The UI states that recognition may be processed by the browser/platform
  speech service outside Jarvis and that selected output voices may use a
  platform service. It does not save microphone consent (lines 145–159).

This is a browser/OS service path, not Hermes-native provider selection. Its
actual network, account, and cost behavior remains browser/device-specific.
Do not label it offline or provider-free. The present text fallback remains
available on all devices.

## Finite adapter readiness design

There is not enough evidence to implement a native audio adapter now. If the
installed Pi later passes the gates below, the safe shape is a narrow server
adapter for the authenticated Jarvis conversation service, not raw RPC:

1. Derive the owner, profile, and exact live Hermes session server-side from the
   existing chat principal/conversation binding. Never accept those identifiers
   from browser voice payloads.
2. Expose only typed `status`, explicit one-shot `start`, `stop`, and (only if an
   actual mobile-return channel is proved) bounded audio/result operations.
   Do not expose `cli.exec`, config writes, arbitrary RPC, provider selection,
   or generic audio upload.
3. Require a fresh user gesture and in-memory consent for each capture; bind a
   short capture lease to the principal/session; stop on cancellation, page
   hide, disconnect, timeout, turn completion, or ownership change. Do not
   persist audio or transcripts beyond the existing conversation policy.
4. Default to local STT/TTS only when the installed provider and ARM64 runtime
   are verified and the selected route is proven to add no metered spend.
   Otherwise report unavailable with the missing provider/account/dependency
   and retain browser text. Never fall back to cloud implicitly.
5. Speak replies on the phone only through a verified client playback path.
   Hermes `voice.tts` is server playback; it does not supply returned audio.
6. Keep Android assistant-role/background wake and tablet-specific behavior in
   a separate device phase. Responsive browser support does not prove Android
   `VoiceInteractionService`, locked-screen wake, OEM battery-policy behavior,
   or either named device's support.

No native adapter is marked ready by this source review. The useful immediate
leaf is to keep using the existing browser consent/PTT/review/text-fallback and
cancelable read-aloud path, while the actual next native decision is made from
the identified Pi's installed-runtime and provider observations.

## Pi verification gate

On the identified Pi, using its installed Hermes account and existing local
runtime, first record `hermes --version` and the installed core commit/build
identity. At an existing interactive Hermes prompt, inspect `/voice status` and
`/wake status` without enabling either feature. Record sanitized provider names,
availability, dependency errors, wake engine/capture mode, and whether a
physical input/output device is present; never copy credentials or `.env`
values into the report.

Before a later effect test, confirm an explicit owner grant for microphone use,
an eligible selected STT/TTS provider, zero additional metered routing, and the
Pi's actual hardware/dependency support. Then test one short user-directed
capture followed by cancel/stop and transcript review, one bounded local TTS
playback followed by stop, and failure cases for missing device/provider,
disconnect, lease expiry, and changed session owner. Keep those results
separate from source/fixture evidence. Pixel 10, Honor X5b Plus, and tablet
checks require the actual identified devices and Android account/assistant-role
configuration; Pi evidence cannot accept them.
