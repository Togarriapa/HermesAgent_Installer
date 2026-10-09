# Compatibility and evidence limits

As of 9 October 2026, the local fixture-level installer foundation and read-only preflight exist. No privileged Pi installation, account setup, enabled service, or native Desktop session has been executed. The local results below establish their named fixture contracts only.

| Area | Planned supported path | Current evidence / limit |
| --- | --- | --- |
| Development | Node24.6.0, exact OpenSpec1.14.1, CI Python3.12.12 for planning checks | Local installed Node/OpenSpec validated; lock audit finding recorded |
| Installer orchestration | typed Python 3.11+ with standard-library runtime; Linux ARM64, Debian 11/12/13 or Ubuntu 20.04/22.04/24.04/26.04, glibc>=2.28, active systemd, FHS directories | Compatibility gate encoded and fixture-tested; not exercised on Pi. This curated installer matrix is deliberately narrower than upstream's general Linux ARM64 Tier 1 statement. |
| Hermes Agent | canonical pinned PM-managed Python3.14/toolchain | Primary source inspected, install not run |
| Hermes Desktop | official compatible artifact or ARM64 source build, real user graphical session | Observed Linux packaging disabled; native window/backend/tool acceptance pending Pi |
| Existing installation | ownership-preserving adoption, no unrelated service replacement | Prepopulated fixture workflow planned |
| Registry | full eight-root pipeline, enforced host ceiling and Hermes-only topology | Source contract inspected; adapter/broker not yet implemented |
| Codex | documented subscription auth, bounded coding task; optional supported app-server inference | App-server loses Hermes agent-context tools; coordinator default runtime retained |
| Claude Free | inventory/eligibility reporting | Actual access pending; no automatic API/Code assumption |
| Nemotron3 Ultra Free | exact text/tool route for non-sensitive data only | Public catalog/terms checked; live account inference/tool test pending |
| GLM-5.2 / Colibri | native ARM64 source build, pinned149-file artifact+MTP, bounded experimental loopback service | Metadata identified; no download/engine/Pi benchmark; default only after thresholds |
| Coral | detected USB or PCIe isolated runtime plus actual compiled-model delegate inference | No target/device identified; enumeration would not pass |
| Skill packs | complete trees/refs/assets; tested host hooks where supported | Per-item adapter/functional contracts planned; source metadata not operational proof |
| OpenViking | native catalog integration plus separate sanitized isolated server | Capture/extraction/embedding/cross-session target tests pending |
| Other memory choices | one owner per user/profile, retrieval sources separately scoped | Agent Memory selected as rohitg00/agentmemory by authorized star policy; claude-mem worker/integration reviewed during implementation |
| Google MCP | official preview if eligible, separately selected labeled community option | Account/preview/scopes/resource selection pending |
| Figma/RevenueCat/HA | official endpoints/existing instance, read-only selected-resource tests | Credentials/account/project/file/entity pending |
| Playwright/browser/render/native extensions | pinned native ARM64 dependencies and sandbox | x86 fixtures, native ARM64 and physical Pi proofs remain separate |
| Config, CLI, preflight and state foundation | blank remote hostname until selected; explicit secret references; read-only host discovery; owned root, lock and SQLite journal | 20 local contract tests passed; no installer-owned service generation or installation handler is complete |
| Command execution | allowlisted read-only probes, argument arrays, fixed system binary paths, minimal environment, output/time bounds and descendant cleanup | Fixture contracts pass. This interface does not claim to sandbox arbitrary component processes; unreviewed executables are rejected. |
| Local network probe | bounded DNS and certificate-verifying HTTPS HEAD to the official GitHub host, using configured system proxy settings | On this development Mac, DNS succeeded but TLS certificate validation failed; preflight reports pending and does not bypass verification. |

An unresolved license, unmediated authority, missing model modality, incompatible account or architecture yields exact unavailable/pending status for that capability. It never removes the item from scope. Instruction/reference-only status is explicit where upstream support is limited. Cloud image/browser/transcription/embedding/extraction are disabled until compatible privacy policy and explicit budget/account configuration.

Initial measurable thresholds for experimental interactive GLM: warm TTFT<=30s, generation>=1token/s, core-chat p95<=10s under auxiliary load, no OOM/throttle failure. These proposed configurable thresholds must be recorded before tests; no performance guarantee or measured result exists. Record cold/warm memory/SSD/prompt/generation/tool-call metrics and failures.

See planning/blockers.json for exact unblocking inputs. All independent code, fixture, documentation and executable target-verifier work remains required despite missing target/accounts.

The local Linux ARM64 matrix requires the upstream runtime's glibc, systemd, and Filesystem Hierarchy Standard environment, plus the listed Debian-family/Ubuntu release versions for the installer's apt-oriented adapters. Hermes upstream lists Linux/aarch64 as Tier 1 and describes glibc+systemd+FHS distributions as likely to work; it does not publish this exact curated installer release matrix. The Pi OS version, active service manager, user graphical session, storage transport, and optional Coral device must still be measured on the target.

## Protected remote Desktop addition

The wizard asks an empty hostname input and hidden scoped Cloudflare token/reference, then automates exact owned tunnel/DNS/Access email-code allowlist setup. Official cloudflared2026.10.0 ARM64 asset/digest is pinned; token-file avoids command-line leakage. Active-zone/certificate and Zero Trust enrollment are checked before exposure. Xpra seamless native Linux ARM64 Debian support is tier3; dedicated official-app-only window/process confinement and browser pixels/control must be proven on the Pi. Desktop/shadow modes, generic start-command client, --no-sandbox and web-dashboard substitution cannot pass. HTTP/assets/WS JWT denial and active-socket expiry/revocation<= configured 60 s lease are separate live AC13..15. No target/Cloudflare token or actual DNS mutation evidence exists.
