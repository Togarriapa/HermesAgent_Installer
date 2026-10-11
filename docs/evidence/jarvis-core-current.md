# Jarvis core runtime evidence

Requirement/task mapping: `jarvis-core-platform`; BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, VD-T266.5. These are observed partial results, not release qualification.

## Selected Pi and source

PI-HERMES is a Raspberry Pi 5 running ARM64 Debian Trixie. Product tests, validators, OpenSpec commands and runtime checks run only through its browser terminal. Local work is source/spec editing, Git coordination and artifact packaging.

Official Hermes remains the unmodified `7085fbf7753266fc4943c55ac04926186bc90005` generation, with PM-managed Python 3.14.7 and existing Codex authentication. The owned isolated core listens on `127.0.0.1:8766`. Public gateway and inspector source `8cfbee0a4` is deployed at <https://jarvis.togarriapahome.uk/> behind Cloudflare Access email OTP and origin JWT/ownership/expiry checks.

The integrated Pi suite at `8cfbee0a4` passed **178 tests**, with 17 warnings and no skips. OpenSpec status/apply and both spec/plan validators passed. All eight broad acceptance groups remain open. Private test logs reside under `/var/tmp/hermes-jarvis-core-checks-20261011/`; deployment logs and protected rollback copies are under `/var/tmp/hermes-jarvis-deploy-8cfbee0a4/`.

## Observed public behavior

The authenticated interface displayed Chat, Sessions, Overview, Capabilities, Settings, Missions, Bots, Logs, Integrations, Learning, Tools & Skills and Files. Menu visibility does not qualify every operation within those menus.

- An actual owned Codex chat returned **“I'm Jarvis, your assistant.”** The deployed adapter resumes its durable session and submits on the same WebSocket, atomically binding the actual runtime session before submission. A longer idle/reaping scenario still needs observation after this fix.
- Stored conversations restored actual message history. Overview displayed observed service/listener status, owned conversation/turn counts and a seven-day turn graph.
- Native discovery and the public Tools & Skills panel reported **449 skills: 53 stock plus all 396 bundled Resources skills**, and 63 toolsets/1,348 tool metadata entries. Discovery is distinct from successful use or effective permission to invoke a tool.
- The offline import preserved 208 source profile records, including 207 internal records, and 88 other declarations. Existing authentication, configuration and primary identity bytes were preserved. Internal profiles are not family-selectable identities or process/filesystem sandboxes.
- Missions saved and previewed a harmless owned draft. Execution was unavailable pending the native dispatcher/parent-turn integration. No mission was launched.
- Logs displayed a real owned `message.complete` event and native usage counters. Cost and browser-tool attribution stayed unknown; no invented values or arbitrary raw tool output were exposed.
- A prior browser TTS run reported spoken-reply completion. Physical phone microphone/audio and Android assistant/wake-word behavior remain unqualified.

## Remaining acceptance

Resources root discovery-receipt refresh is pending the verified PM ancestor-mode repair. Live native skill discovery is observed, but full internal routing, imported plugin effects, external authentication and enrichment remain open. Model controls, richer voice settings, capability details and activity charts require their matching source tests and public browser checks.

Family concurrency/isolation, mission execution, Bots/channel configuration, browser-use controls, native learning effects, full capability parity, fresh installation, restart/recovery and boot qualification remain open. Home Assistant is deferred. The gateway is not boot-qualified. Owned retired-runtime cleanup must preserve shared services, PM/runtime data, credentials, selected Hermes home and recovery copies.

Deployments preserve the private core process unless an explicitly verified owned-core restart is required. Gateway/inspector/tunnel source changes retain protected unit/configuration backups and check that only identified owned services are changed.
