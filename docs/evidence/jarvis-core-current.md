# Jarvis core runtime evidence

Requirement/task mapping: jarvis-core-platform; BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, VD-T266.5. This is partial acceptance evidence, not a release qualification.

## Verified on the selected Pi

Target: PI-HERMES, Raspberry Pi 5, ARM64, Debian Trixie. Product tests, OpenSpec execution and validators in this checkpoint ran in the Pi browser terminal. Local activity was source editing, Git coordination and artifact packaging.

- Official Hermes source: `7085fbf7753266fc4943c55ac04926186bc90005`, using its PM-managed Python 3.14.7 environment and existing Codex authentication.
- Private core service and durable chat resume across its owned service restart were verified at installer source `8753c8353`.
- Public gateway source `6f4992a25` served a native HTML composer through the existing Cloudflare Access protection at `https://jarvis.togarriapahome.uk/`. An actual new chat returned “My name is Jarvis.” This proves the observed owner chat, not family isolation, phone wake-word support or every capability.
- Installer source `06876bc50f0213ba5c19c5caf744a96237238b4d` imported the offline Resources bundle into the selected Hermes home. Native discovery reported 396 skills; 208 profile records, including 207 internal records, and 88 other declarations were preserved. Existing authentication, configuration and primary identity files retained their exact contents. The private import receipt is on the Pi; it contains no authentication material.
- The focused importer/core tests passed 17 cases. The integrated installer, wizard, importer, dashboard, gateway, chat/history and asset contracts passed 69 cases, with three root-dependent cases skipped under the admin account. These fixtures do not substitute for live acceptance.
- Sol's next settings/voice/profile dispatch refinement, published at `b73c9e90c`, passed `validate:specs`, `validate:plan` and all 19 planning tests on the Pi. OpenSpec reported the four artifacts ready and all eight acceptance groups still open.

## Remaining boundaries

The history retry repair and new Overview, Capabilities and Settings views are source-complete and Pi-tested at `06876bc50`, but are not deployed by this checkpoint. The current public gateway still uses `6f4992a25`; its history reload problem remains a deployment target.

Skill discovery is distinct from internal profile routing, plugin authentication, adapter effects and enrichment by additional repositories. The import receipt deliberately leaves functional, enabled and target-verified states false. Private prompt records do not appear as family-selectable profiles and do not provide a process or filesystem sandbox.

Browser voice, effective settings projection, Bots/channel configuration, full capability parity, Android assistant/wake-word behavior, fresh installation, boot qualification and complete resource dispatch remain open. Home Assistant live configuration is deferred. Owned Desktop retirement waits for replacement security, restart and recovery evidence; shared services, user data and recovery backups must survive it.

The latest Pi browser session runs as admin and requires manual sudo authentication for the pending gateway deployment. A prepared source artifact exists; no protected production files were changed from this unprivileged session.
