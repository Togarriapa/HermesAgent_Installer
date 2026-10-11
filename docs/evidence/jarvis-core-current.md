# Jarvis core runtime evidence

Requirement/task mapping: jarvis-core-platform; BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, VD-T266.5. This is partial acceptance evidence, not a release qualification.

## Verified on the selected Pi

Target: PI-HERMES, Raspberry Pi 5, ARM64, Debian Trixie. Product tests, OpenSpec execution and validators in this checkpoint ran in the Pi browser terminal. Local activity was source editing, Git coordination and artifact packaging.

- Official Hermes source: `7085fbf7753266fc4943c55ac04926186bc90005`, using its PM-managed Python 3.14.7 environment and existing Codex authentication.
- Private core service and durable chat resume across its owned service restart were verified at installer source `8753c8353`.
- Public gateway source `6f4992a25` served a native HTML composer through the existing Cloudflare Access protection at `https://jarvis.togarriapahome.uk/`. An actual new chat returned “My name is Jarvis.” This proves the observed owner chat, not family isolation, phone wake-word support or every capability.
- Installer source `06876bc50f0213ba5c19c5caf744a96237238b4d` imported the offline Resources bundle into the selected Hermes home. Native discovery reported 396 skills; 208 profile records, including 207 internal records, and 88 other declarations were preserved. Existing authentication, configuration and primary identity files retained their exact contents. The private import receipt is on the Pi; it contains no authentication material.
- The focused importer/core tests passed 17 cases. At source `374161cf95965524f0a0d0acef661cfca4ffe5b3`, the integrated core, wizard, importer, dashboard, gateway, chat/history, assets and planning checks passed 92 cases with no skips. The pinned native Hermes environment exercised the isolated 208-profile/396-skill handoff fixture. Earlier three skips were caused by unset optional native-environment test variables, not missing root privileges. Fixtures do not substitute for live capability acceptance.
- Sol's next settings/voice/profile dispatch refinement, published at `b73c9e90c`, passed `validate:specs`, `validate:plan` and all 19 planning tests on the Pi. OpenSpec reported the four artifacts ready and all eight acceptance groups still open.

## Remaining boundaries

Gateway and inspector source `374161cf9` is deployed. The protected public site displayed Chat, Overview, Capabilities and Settings; Overview used stored conversation/turn counts and a seven-day activity graph, and Capabilities loaded 692 catalog records. A stored conversation restored its actual “My name is Jarvis.” reply. A new Codex turn returned the requested “Ready.” and the browser reported reply-audio completion with the selected system voice. This qualifies observed chat/history and browser TTS completion; it does not prove microphone capture, physical phone audio or Android wake-word behavior.

The parallel missions, Bots/channels/schedules, activity/usage and capability/learning handoff was published at `fb8ee8537`. OpenSpec status/apply, both validators and all 19 planning tests passed on the Pi. Implementations and their separate acceptance remain open.

Skill discovery is distinct from internal profile routing, plugin authentication, adapter effects and enrichment by additional repositories. The import receipt deliberately leaves functional, enabled and target-verified states false. Private prompt records do not appear as family-selectable profiles and do not provide a process or filesystem sandbox.

Browser voice, effective settings projection, Bots/channel configuration, full capability parity, Android assistant/wake-word behavior, fresh installation, boot qualification and complete resource dispatch remain open. Home Assistant live configuration is deferred. Owned Desktop retirement waits for replacement security, restart and recovery evidence; shared services, user data and recovery backups must survive it.

The deployment used the authorized Pi root browser shell. It preserved the private core service, PM runtime, credentials, selected Hermes home and shared tunnel, and retained protected gateway/inspector unit and configuration backups before switching their reviewed source path. Fresh boot qualification and complete release acceptance remain pending.
