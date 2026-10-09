# Build a complete Hermes installer for my Raspberry Pi 5

You are the engineering agent responsible for building, testing, and documenting this installer using OpenSpec throughout development. Implement a usable project with real installation and integration logic, a guided setup experience, diagnostics, and recovery. Continue through implementation and verification; a proposal or a script that only clones repositories is insufficient.

Use the repository/workspace supplied with this task. If none exists, create a local project named `hermes-pi-installer`. Keep installer development separate from my resource registry. Do not assume that the resource repository is the destination for your code. Follow the workspace's contribution rules and commit completed work when authorized. Publishing, deployment, and changes to unrelated repositories require an identified, authorized destination.

The research seeds below were checked on **9 October 2026**. Recheck upstream documentation, supported installation methods, account eligibility, releases, and model catalogs while implementing. Record immutable revisions rather than treating these observations as permanent guarantees.

## 0. Mandatory development workflow: OpenSpec

Develop this entire installer project using **[Fission-AI/OpenSpec](https://github.com/Fission-AI/OpenSpec)**. OpenSpec must guide the development lifecycle, including changes made after the first version.

### Initialize and preserve project context

Pin a verified version of `@fission-ai/openspec` in the development toolchain and use its supported Node.js version. Inspect the official [CLI reference](https://github.com/Fission-AI/OpenSpec/blob/main/docs/cli.md) and generated instructions before choosing commands. Initialize the installer repository for the coding agent actually doing the development; current tool IDs include `codex`, `claude`, and `hermes`. Preserve any existing OpenSpec setup and project-specific instructions.

Use `openspec/config.yaml` for the project's hardware constraints, architecture conventions, integration rules, and definition of done. Reference this workflow from the installer repository's agent/contributor instructions. OpenSpec is a development dependency; using it does not require an additional always-running service or mandatory end-user installation on the Pi.

### Capture requirements and organize changes

Translate the complete prompt into traceable OpenSpec requirements and a scoped backlog before implementation. Keep implemented behavior in `openspec/specs/<capability>/spec.md`; represent proposed additions and modifications in active changes under `openspec/changes/<change-id>/`.

Use the selected schema's actual artifacts. With the standard `spec-driven` schema, maintain `proposal.md`, delta `specs/`, `design.md`, and `tasks.md` for each substantive change. Write concrete requirements and `WHEN`/`THEN` scenarios covering normal operation and meaningful failure cases.

Split the work into coherent changes covering installer/bootstrap and Desktop; resource-registry import; providers, credentials, budgets, and privacy; Colibri/Coral; skills, memory, and auxiliary applications; MCP connections; lifecycle/recovery; and verification/documentation. Keep dependency ordering explicit. Independent agents may implement separate changes or tasks in isolated worktrees, with one owner coordinating shared specifications and integration.

Every requested component, alias, and acceptance criterion must map to an OpenSpec requirement, implementation task, and test or explicitly recorded blocker. Link code changes and verification evidence back to their change IDs and requirements. Keep `tasks.md` current; distinguish implementation completed from live account/hardware verification pending.

### Implement from the specifications

Use the installed agent's generated OpenSpec workflows to propose, implement, and update changes. Consult `openspec status` and `openspec instructions` when deciding what to do next. Adapt plans and specifications when technical discoveries justify it, recording why and preserving the requested scope. Do not weaken requirements merely to make incomplete functionality pass.

Agent workflow names differ between hosts. Follow the installed integration instead of assuming every host accepts Claude-style `/opsx:*` commands. If using `/opsx:verify`, first enable a workflow profile that includes it; otherwise perform the same evidence-based implementation review directly.

Develop autonomously within the authorized scope. Prepare and inspect the specifications, then continue into implementation without asking for routine approval at each artifact or task. Ask only for missing source identities, account interaction, or material decisions already identified elsewhere in this prompt.

### Validate, verify, and archive accurately

Add strict OpenSpec validation to local development and CI. The current documented commands are:

```bash
openspec validate <change-id> --type change --strict --no-interactive
openspec validate --all --strict --no-interactive --json
```

Treat `<change-id>` as the actual active change identifier. Confirm command support against the pinned version. Specification validation and artifact-completion status do not establish that code works; independently compare implementation and test results with the requirements, scenarios, and design.

Fix implementation/specification drift before declaring a change complete. Archive verified changes with the documented workflow, merging their deltas into the canonical specs and retaining dated history. For authorized non-interactive completion, the current CLI supports `openspec archive <change-id> --yes`. Do not disable validation to force completion.

Keep genuinely unfinished changes active with precise blockers and next actions. Completed independent changes may be archived, but unavailable credentials, unperformed Pi tests, or missing dependencies must never be ticked as passed. Deliver the OpenSpec configuration, canonical specs, active changes, archive, task status, and verification mapping with the repository.


## 1. Intended result

Build an installer for this machine:

- Raspberry Pi 5 with 16 GB RAM.
- 1 TB SSD. Detect its actual usable capacity, free space, filesystem, mount, and connection type.
- Google Coral TPU. Detect whether it is USB or PCIe/M.2 before choosing drivers.
- A supported 64-bit Linux installation, preferably Raspberry Pi OS with a desktop when compatible with the selected dependencies.

Install **Hermes Desktop and its Hermes Agent backend**, preinstall my profiles and skills, and integrate the requested projects and MCP connections to the extent their real upstream capabilities and my accounts permit.

The result must work for both a fresh supported system and a machine with an existing installation. Preserve existing user data, configurations, credentials, memories, and unrelated services. Detect existing Home Assistant, model servers, speech services, and occupied ports before making changes. Do not reimage the machine, format storage, or replace an existing service as a side effect of routine installation.

Use English for the installer and documentation. Default new installer-owned schedules and displayed times to `Europe/Lisbon`, while preserving an existing host timezone unless the user selects a change.

Default to **zero additional metered spending**. Existing subscription access can be used through supported authentication. Any paid model, cloud browser, image generation, embedding, transcription, or other paid API must remain disabled until a budget and account are deliberately configured.

## 2. Hardware and upstream realities

### Hermes Desktop

Use [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) as the canonical upstream. Read its current [Desktop README](https://github.com/NousResearch/hermes-agent/blob/main/apps/desktop/README.md), build instructions, installation guide, and [platform support](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support).

The research snapshot lists Linux aarch64 as a supported agent platform and documents `hermes desktop` for building/launching the official GUI against an existing install. It also says Linux desktop release packaging is currently disabled. Therefore:

- Prefer an official compatible release if one exists at implementation time; otherwise implement and verify the official ARM64 source-build path.
- Resolve Agent and Desktop versions separately when upstream releases them separately.
- Verify the native window opens under the actual graphical session, connects to the intended backend, displays imported resources, and completes a conversation.
- Run the desktop under the intended desktop user. Use appropriate user-session startup; a headless system service is not a graphical login session.
- If native Desktop is blocked, retain a working supported agent and offer its browser interface or a documented remote-Desktop connection as a clearly labeled fallback. Do not label that fallback “Desktop installed.” Record the exact failure and recovery route.
- Do not silently substitute a community fork, an unrelated Hermes application, or an unofficial Python package.

### Coral

Coral accelerates compatible, compiled, fully quantized TensorFlow Lite workloads; it does not provide a general accelerator for GLM/Colibri or remote Nemotron inference. Follow [Coral's compatibility documentation](https://coral.ai/docs/edgetpu/models-intro/) and the setup guide for the detected device.

Install the appropriate runtime and permissions in an isolated dependency environment. Do not downgrade Hermes or the host Python to satisfy older PyCoral packages. Test actual TPU inference with a small official compiled sample model and record that the TPU delegate was used; device enumeration alone is insufficient. Keep Coral inference separate from LLM model routing. Do not install surveillance or camera services merely to give the TPU a workload.

Check available memory, CPU architecture/features, thermals/throttling, storage health where supported, and device access. Never infer performance from the presence of a TPU or a nominal 16 GB RAM label.

## 3. My resource repository is the baseline

Source: **[Togarriapa/HermesAgent_Resources](https://github.com/Togarriapa/HermesAgent_Resources)**.

This is a custom declarative registry, not simply a directory of native Hermes skills. Inspect `README.md`, `catalog.yaml`, `SPEC.md`, `RUNTIME_IMPORT.md`, `TOPOLOGY.md`, `ORCHESTRATION.md`, `PROFILE_MATRIX.md`, `INTEGRATION_MATRIX.md`, `EXTERNAL_INTEGRATIONS.md`, `QUALITY_POLICY.yaml`, and the supplied validators/materializer.

Build a version-aware importer that:

1. Fetches a pinned commit without executing fetched content during discovery.
2. Discovers resources from the catalog's declared manifest roots rather than a hard-coded list. Include Profiles, Skills, Plugins, MCPs, Bundles, Channels, Crons, and Webhooks in the inventory.
3. Runs the repository's applicable validation tools, resolves dependency selectors and inheritance, and materializes effective specifications using its existing tooling where appropriate.
4. Produces an explicit crosswalk from the custom schema to the installed Hermes version's real profiles, skills, plugins, tool configuration, and runtime mechanisms. Generate an adapter where required; do not assume native Hermes understands `hermes.togarriapa/v1` YAML.
5. Preserves provenance, resource identities, versions, supporting files, and source paths. Keep generated artifacts separate from pristine source and private/local overlays.
6. Makes all valid declared profiles and skills discoverable. Report dependencies that prevent a particular capability from becoming usable. Do not fabricate MCP servers or provider implementations from their declarative names.
7. Enforces relevant execution boundaries through actual runtime controls, not merely persona text. Native Hermes profiles separate state; do not assume they provide filesystem or process sandboxing.
8. Activates a validated generation atomically and retains a rollback target. Updates must preserve local/private learning and quarantine conflicting or permission-expanding changes.

Preserve the repository's intended topology: **user → Hermes → Orchestrator → internal specialists/teams → Orchestrator → Hermes**. Specialists must not become independent user-facing channels. Preserve the declared response contract, scoped recruitment, contributor reporting, and material dissent where applicable. Use resource-aware limits on concurrent agents rather than launching a process for every profile at boot.

The repository's materializer explicitly does not apply host authorization. Finish that integration in the runtime adapter and test it. For example, if enabling its homelab administration capability, enforce its Authentik identity/group and bounded-broker requirements. If those dependencies are absent, leave that capability unavailable and report why; do not replace the checks with an instruction to the model.

Importing registry definitions must not automatically enable every scheduled task, financial integration, outbound messaging channel, webhook, or external account. Register those definitions and activate only the capabilities selected and configured for this installation. Distinguish **text-core readiness**, **individual resource readiness**, and **full registry compliance**. Missing required dependencies must not be silently rewritten as optional or counted as compliant.

## 4. Requested projects: preserve every item

The following is the seed inventory. Links identify inspected upstream projects or explicitly marked candidates; they do not certify Raspberry Pi functionality. Revalidate redirects, ownership, licenses, install instructions, and ARM64 dependencies at the pinned revision. Do not assume a default branch named `main`.

### Engineering, research, orchestration, and memory

| Requested name | Source or resolution seed | Required handling |
| --- | --- | --- |
| affaan-m/ECC; ecc | [affaan-m/ECC](https://github.com/affaan-m/ECC) | One component with both aliases. Integrate compatible skills and supported host features; audit hooks separately. |
| jakeschincariol/replica-skill | [Jakeschincariol/replica-skill](https://github.com/Jakeschincariol/replica-skill) | Install complete skill directories and helper scripts; adapt host-specific references. |
| safishamsi/graphify | [Graphify-Labs/graphify](https://github.com/Graphify-Labs/graphify) | Verified moved upstream; preserve the original alias. CLI/skills and optional MCP. Its Python distribution is `graphifyy`; verify its Hermes installer. |
| public-apis/public-apis | [public-apis/public-apis](https://github.com/public-apis/public-apis) | Searchable reference catalog. Do not provision every API it lists. |
| adewaskar/jarvis | [adewaskar/jarvis](https://github.com/adewaskar/jarvis) | Separate voice application with Claude Code assumptions; implement an explicit optional integration and expose unmet account requirements. |
| OmniRoute; omniroute | [diegosouzapw/OmniRoute](https://github.com/diegosouzapw/OmniRoute) | One routing service with deduplicated aliases; verify its ARM64 path and restrict configured providers/fallbacks. |
| PonyTail | [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) | Portable coding/review skill plus supported host features; preserve the user registry's orchestration. |
| Addy Osmani's Agent Skills | [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | Preserve shared root references as well as individual skill folders. |
| claude-mem | [thedotmack/claude-mem](https://github.com/thedotmack/claude-mem) | Memory service; verify the current Hermes capture/search integration, worker, and persistence. |
| Browser Use | [browser-use/browser-use](https://github.com/browser-use/browser-use) | Install supported skills/library/CLI and a compatible local browser; cloud browser access is a separate option. |
| Agent Memory | **Unresolved identity.** Candidate: [rohitg00/agentmemory](https://github.com/rohitg00/agentmemory) | Keep the requested name pending until the intended repository is selected. Candidate has Hermes integration; do not silently choose it. |
| Scientific Agent Skills | [K-Dense-AI/scientific-agent-skills](https://github.com/K-Dense-AI/scientific-agent-skills) | Preinstall skill content; resolve scientific dependencies by feature/environment rather than one enormous global installation. |
| Diagram Design | [cathrynlavery/diagram-design](https://github.com/cathrynlavery/diagram-design) | Preserve skill, references, assets, and rendering/export helpers. |
| Antropic Cybersecurity Skills | Matching project: [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Label it as third-party, not Anthropic-owned. Install procedures as skills; do not execute security exercises during setup. |
| Awesome Harness Engineering | **Unresolved identity.** Candidates: [ai-boost](https://github.com/ai-boost/awesome-harness-engineering), [walkinglabs](https://github.com/walkinglabs/awesome-harness-engineering) | Resolve the intended catalog; expose it as reference material rather than an always-running service. |
| Open Viking | [volcengine/OpenViking](https://github.com/volcengine/OpenViking) | Context/memory service; inspect its [native Hermes integration](https://docs.openviking.ai/en/agent-integrations/05-hermes), including extraction and embedding requirements. |
| Panniantong/agent-reach | [Panniantong/Agent-Reach](https://github.com/Panniantong/Agent-Reach) | CLI/skills and per-channel diagnostics. Verify packages from upstream; avoid an unrelated same-name package. |
| superpowers | [obra/superpowers](https://github.com/obra/superpowers) | Prefer its documented Hermes integration. Test actual hooks/bootstrap behavior for the pinned host. |
| gstack | [garrytan/gstack](https://github.com/garrytan/gstack) | Research snapshot labels Hermes instruction-only. Preserve that limitation unless current upstream and tests establish more. |
| ruflo | [ruvnet/ruflo](https://github.com/ruvnet/ruflo) | Supported adapter/MCP or isolated optional runtime; test native dependencies on ARM64 and avoid a competing default orchestrator. |
| Open Executive | [SenteLabsAI/OpenExecutive](https://github.com/SenteLabsAI/OpenExecutive) | Separate application with its own agents and provider assumptions; integrate explicitly and run on demand. |

### Design, writing, knowledge, and media

| Requested name | Source or resolution seed | Required handling |
| --- | --- | --- |
| ui-ux-pro-max | [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | Skill, search data, and Python helpers; verify current installer package names. |
| taste-skill | [Leonxlnx/taste-skill](https://github.com/Leonxlnx/taste-skill) | Selectable design skills; preserve task-specific style choice. |
| awesome-design | **Unresolved identity.** Candidate: [bergside/awesome-design-skills](https://github.com/bergside/awesome-design-skills) | Preserve as pending source selection; do not guess from a generic name. |
| emil kowalski/impeccable | Impeccable: [pbakaus/impeccable](https://github.com/pbakaus/impeccable); Emil's separate pack: [emilkowalski/skills](https://github.com/emilkowalski/skills) | Correct the attribution explicitly. Current Hermes support provides skills/command routing, without the native design hook. Verify ARM64 engine assets. Offer Emil's separate pack for selection; these are different repositories. |
| hyperframes | [heygen-com/hyperframes](https://github.com/heygen-com/hyperframes) | Skills plus an on-demand video renderer; validate Node, FFmpeg, and browser dependencies. |
| humanizer | [blader/humanizer](https://github.com/blader/humanizer) | Portable writing skill. |
| obsidian-skills | [kepano/obsidian-skills](https://github.com/kepano/obsidian-skills) | Portable file-format skills; separately validate optional desktop/CLI tools and approved vault paths. |
| banana-claude | [AgriciDaniel/banana-claude](https://github.com/AgriciDaniel/banana-claude) | Claude-oriented image plugin requiring a compatible adapter/client and separately configured Gemini credentials/billing. No automatic paid generation. |
| screenshot to code | [abi/screenshot-to-code](https://github.com/abi/screenshot-to-code) | Separate web application/model integration, not automatically a skill. Validate its vision-model requirements. |
| scrapegraph-ai | [ScrapeGraphAI/Scrapegraph-ai](https://github.com/ScrapeGraphAI/Scrapegraph-ai) | Local library/tool adapter. Its current `pyproject.toml` requires Python `>=3.12,<4.0`; resolve an isolated runtime. Distinguish it from separately offered cloud/MCP products and billing. |
| book-to-skill | **Unresolved identity.** Candidates: [virgiliojr94/book-to-skill](https://github.com/virgiliojr94/book-to-skill), [apple-ouyang/book-to-skill](https://github.com/apple-ouyang/book-to-skill) | Resolve before activation; preserve extraction/generation dependencies and test generated Hermes skill discovery. |
| apple-design | **Unresolved identity.** Candidate: [dickwu/apple-design-skill](https://github.com/dickwu/apple-design-skill) | Design-reference skill, not Apple-owned software or an Xcode toolchain. Resolve the intended project. |
| latent-spaces/brag | [latent-spaces/brag](https://github.com/latent-spaces/brag) | Launch-video skill and compatible render stack; reuse Hyperframes dependencies and validate optional narration separately. |

### MCP connections

| Requested connection | Source | Required handling |
| --- | --- | --- |
| Figma MCP | [Official remote MCP documentation](https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/) | Prefer the official remote server, currently `https://mcp.figma.com/mcp`; authenticate and test actual account capabilities. |
| Playwright MCP, written “playright” | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | Local official MCP using a pinned `@playwright/mcp` package and verified ARM64 browser. |
| Revenue Cat MCP | [Official RevenueCat setup](https://www.revenuecat.com/docs/tools/mcp/setup) | Current remote endpoint `https://mcp.revenuecat.ai/mcp`; supported OAuth or scoped API v2 credentials. |
| Google | [Official Workspace MCP documentation](https://developers.google.com/workspace/guides/configure-mcp-servers) | Check account eligibility and requested services. At research time official remote servers require Developer Preview access. |
| Home Assistant | [Official MCP Server integration](https://www.home-assistant.io/integrations/mcp_server/) | Connect to the existing instance using its documented `/api/mcp` or `/api/mcp/assist` endpoint and supported authentication. |

For personal Google accounts or unavailable official preview access, evaluate the explicitly community-maintained [taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp). Offer its reviewed integration as a labeled option. Do not describe it as Google's official server.

Ambiguous names must remain present in the manifest with candidate URLs and an exact next step. Build all independent functionality while awaiting selection. Add a source-override mechanism so resolving a name does not require editing installer code. Do not omit requested items to make the completion report appear cleaner.

## 5. Model and account integration

### Nemotron 3 Ultra Free / OpenRouter

Requested remote model: **Nemotron 3 Ultra Free**. Research-time OpenRouter identifier:

```text
nvidia/nemotron-3-ultra-550b-a55b:free
```

Check the [live model entry](https://openrouter.ai/nvidia/nemotron-3-ultra-550b-a55b:free), model catalog, supported parameters, context/output limits, token prices, account access, and rate limits during configuration. Perform an actual minimal inference and tool-calling test. Do not infer entitlement from a model appearing in a catalog or enforce unsupported parameters such as structured-output modes without checking them.

Handle unavailable models, expired keys, 429 responses, `Retry-After`, timeouts, and cancellation with bounded retries and clear status. Configure an explicit fallback allowlist; never silently choose a paid model or remove the `:free` suffix. Limit provider use across all agents collectively.

The researched free endpoint excludes confidential/personal submissions and logs usage for specified provider purposes. Recheck these conditions and enforce compatible data routing. Private Google content, Home Assistant data, personal memory, private repositories, tool results, and extracted summaries must not be sent to an incompatible free route. Apply this to system context, memory extraction, background work, retries, and fallbacks as well as the initial message.

Provide separate public/non-sensitive and private-capable execution configurations. Route private work only through a locally running model or another configured provider whose applicable terms and user settings permit it. If none is usable, show a specific unavailable route rather than leaking private context through a fallback.

### GLM-5.2 through Project Colibrì

Use [JustVugg/colibri](https://github.com/JustVugg/colibri), its current [quickstart](https://github.com/JustVugg/colibri/blob/main/docs/quickstart.md), and verified GLM-5.2 model artifacts.

Preserve **GLM-5.2** as the requested model. At research time the recommended converted package is approximately 429 GB, and upstream lists 16 GB minimum / 24 GB recommended or measured-ready RAM. Its published low-memory laptop result is not a Pi benchmark. Do not assert acceptable performance on this Pi without measurement.

Implement the complete experimental local-model path:

- Build the engine for actual Linux ARM64; do not download an x86-only Linux binary.
- Resolve a supported, licensed, revision-pinned model artifact and quantization, including any required MTP data. Never silently substitute GLM-5.3 or a smaller model.
- Show total download, temporary/conversion, final-storage, and update/rollback space requirements before the user selects the large download. Support an existing model path and resumable integrity-checked downloads.
- Reserve space for the OS, Hermes, user data, caches, logs, and recovery. Avoid duplicating hundreds of gigabytes solely to create a generic backup.
- Measure memory use, SSD throughput, first-token latency, prompt processing, token generation, and tool-use behavior on this host. Distinguish cold and warm tests.
- Give the model a bounded, cancellable service and an authenticated/loopback API adapter appropriate to the current Colibri server.
- Keep Desktop responsive. Restrict concurrent local inference and suspend competing installer-managed heavy workloads where necessary. Do not promise that swap solves insufficient physical RAM.
- Enable it as an interactive default only if measured behavior satisfies documented, configurable acceptance thresholds. Otherwise retain an explicitly experimental/manual route with its measured limitations.

Build this support even if the target hardware is unavailable during development. Clearly separate implementing the installation path from having downloaded and tested the model on the actual Pi. An optional smaller model can be offered separately; it must never count as the requested GLM model passing.

### OpenAI Codex

Connect my existing Codex access through supported [OpenAI authentication](https://developers.openai.com/codex/auth) and the installed Hermes version's documented provider/integration mechanisms. Distinguish ChatGPT/Codex subscription sign-in from separately billed OpenAI API-key usage.

Implement host-managed authentication, including an appropriate browser/device-code or headless workflow. Reuse supported credential references; do not copy reusable OAuth credentials into each profile, repository, container image, or agent workspace. Preserve refresh-token ownership and revocation behavior.

Support Codex as a bounded coding tool for relevant profiles, and as an inference provider only through a documented supported integration. Do not invent a generic OpenAI-compatible API by replaying subscription tokens. Validate actual inference or a small coding task inside a temporary workspace; report authentication, entitlement, quota, and functional status separately.

### Claude Free

Retain my requested **Claude Free account** in the setup inventory, but do not promise that a consumer free login provides Claude Code, Anthropic API, or third-party inference access. Check current [Anthropic authentication documentation](https://code.claude.com/docs/en/authentication) and applicable third-party account rules.

If the account is ineligible, mark automatic Claude inference unavailable and explain the supported account/API alternatives without purchasing anything. Continue installing the rest. Do not use cookie extraction, session scraping, identity spoofing, or an unofficial web-to-API bridge. Applications such as Jarvis or Banana with additional client/provider requirements need their own honest dependency status.

### OmniRoute

Install/configure the verified OmniRoute component as the selected routing layer where its supported features help. Avoid stacking redundant gateways around native Hermes providers. If a direct provider connection is required, document that route while retaining OmniRoute's explicit component status.

Apply model allowlists, capability checks, privacy eligibility, aggregate budgets, bounded retries, health checks, and loop prevention through the actual dispatch path. Do not let a proxy's default fallback, compression feature, or advertised free-provider list override those requirements or corrupt tool calls.

## 6. Skill, memory, and workload integration

Use the installed Hermes version's documented [skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills), [profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles), and [MCP](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp) interfaces. Prefer existing supported integration mechanisms over custom replacements.

Preinstall compatible skill definitions and references on SSD, then load relevant content by profile/task. Do not concatenate every repository's `AGENTS.md`, `CLAUDE.md`, personality file, or design rules into one global prompt. Preserve source licenses, full relative paths, helper scripts, assets, and shared references. Resolve duplicate names deterministically and retain original names/aliases in the catalog.

For host-specific plugins, distinguish portable instructions from executable hooks, slash commands, tool bindings, and enforced behaviors. Implement an adapter where practical, with a test demonstrating its behavior. If a required feature is unsupported, report the exact limitation; installing Markdown must not count as executing a hook.

Use **one owner of automatic long-term memory capture per active profile**. Preserve native working/session memory. Make OpenViking, claude-mem, and the selected Agent Memory integration available as separate choices or scoped retrieval sources. Do not attach several automatic capture/injection systems to the same conversation by default.

Keep memory stores namespaced by user/profile, preserve provenance, prevent recursive ingestion of generated memories, and provide export/backup/removal controls. Validate the selected provider by storing a synthetic fact, completing extraction, restarting, and retrieving it in a new session. A configured or “available” status is not sufficient proof. Check the data eligibility and costs of embedding and extraction providers separately.

Keep independent applications such as Jarvis, OpenExecutive, Ruflo, and screenshot-to-code isolated. Connect them through supported interfaces or documented adapters without replacing Hermes as the user-facing coordinator. Scientific environments, browsers, graph processing, media rendering, and additional databases should start on demand with measured limits. Skill availability does not require every heavyweight service to run at boot.

Match capabilities to tasks: a text-only model does not supply screenshot understanding, image generation, speech, or embeddings merely because a skill asks for them. Add explicit capability checks and supported-provider configuration for these operations. Do not mark such tasks operational until a compatible endpoint is configured and tested.

## 7. Guided setup and component lifecycle

Provide a simple entry point, such as `./install.sh`, backed by maintainable modular code. A thin shell bootstrap plus typed Python orchestration is a reasonable default; use another stack only if it materially improves reliability. Avoid a single giant shell script.

The wizard must handle fresh install, existing-install adoption, component selection, storage/model paths, account setup, diagnostics, and recovery. Reuse Hermes Desktop settings where practical. A second full management application is not required; a clear terminal wizard and lifecycle CLI are sufficient.

For every required setting, show what it is, why it is needed, the official setup link, concrete steps to obtain it, and a connection test. Collect secrets through secure input and supported credential storage. Allow “configure later” and resume without repeating successful setup. Explain account/billing prerequisites before asking for a key.

Provide interactive and documented non-interactive operation with a validated config file, secret references, useful exit codes, and readable/JSON output. Implement these lifecycle capabilities through clear commands:

- Plan/dry-run; install; resume; status; doctor; verify.
- Configure/test a provider or MCP; select a memory provider; resolve a source URL.
- Enable/disable/start/stop a component; inspect redacted logs.
- Check/apply updates; rollback; backup/restore; uninstall.

Preflight must detect OS/distribution/version, ARM64 architecture, available RAM, graphical session, user/sudo context, package-manager locks, network/DNS/TLS, disk capacity, existing installs, services, ports, and device access. Select supported dependency versions; do not globally replace the system Python or Node to satisfy one component.

Use isolated environments for incompatible Python/Node/native dependencies. Prefer native ARM64 packages; use containers only where their compatible images and isolation justify them. Check native extensions, browser binaries, shared libraries, and transitive dependencies. Do not silently use x86 emulation as the Pi solution.

Keep application data, model files, component environments, source snapshots, logs, backups, and private overlays in documented locations. Use a single configuration source of truth and generated service definitions. Avoid writing through symlinks outside managed roots or overwriting existing user settings.

Use appropriate systemd/user-session supervision with startup ordering, restart limits, health probes, timeouts, log rotation, and clean shutdown. Detect already-managed services to prevent duplicate listeners, model processes, jobs, and memory workers. Start with conservative, configurable concurrency—for example, one browser worker and a small cloud-agent pool—and tune from measurements.

Installations must be idempotent and resumable, with process locks and per-step checkpoints. Stage downloads, validate artifacts, and atomically switch compatible generations. Upgrades must preview relevant config/schema/permission changes and preserve user modifications. Take consistent database backups and support version-compatible restoration. Uninstall removes installer-owned software while retaining user data by default.

Bind management interfaces to loopback by default. Remote access must have authentication and appropriate encrypted transport. Keep services unprivileged where possible, limit filesystem/network/tool scopes, and keep secrets out of source, command lines, screenshots, logs, and diagnostic bundles. Preserve OAuth callback validation and credential ownership.

## 8. MCP-specific setup and verification

For every MCP, determine real transport, endpoint, protocol/client compatibility, authentication, tool schema, and prerequisites. Implement MCP initialization, tool discovery, an appropriate harmless functional call, reconnect, timeout, and revoked-credential behavior. Merely writing a config entry is not a passing test.

**Google:** let me select services such as Gmail, Drive/Docs/Sheets, Calendar, and Contacts. Check personal versus Workspace-account eligibility and official preview access. Guide OAuth consent, enabled APIs, callback configuration, refresh behavior, and minimal scopes. Start with read-only operations. Do not send messages, create meetings, or modify documents as installation tests.

**Home Assistant:** use my existing instance, its current official MCP integration, and explicitly exposed entities. Guide authentication and test reading an appropriate entity/state. Do not install a replacement HA instance or issue real device-control commands during setup. Preserve the resource registry's control boundaries.

**Figma:** use the official remote endpoint where available, guide login, verify plan/tool availability, and test access to a file I select. Do not require unofficial Figma desktop packages on the Pi.

**Playwright:** install a supported headless ARM64 browser and create isolated browser profiles. Test a local fixture page with navigation, an accessibility snapshot, and a screenshot. Preserve the browser sandbox; any platform-specific limitation needs a documented supported resolution. Do not import personal browser cookies automatically.

**RevenueCat:** use the official remote server and my selected project, with scoped OAuth or API credentials. Prefer read-only setup tests. Do not change products, entitlements, customer records, billing, or subscriptions to prove the connection works.

Use tool allowlists and bounded discovery/startup concurrency. Cache or lazily initialize servers where Hermes supports it, while validating first-use failure handling. One slow optional server must not leave a basic chat request hanging indefinitely.

## 9. Manifest and truthful status reporting

Create a machine-readable manifest and a human-readable integration matrix. Every requested project, alias, model, account, and MCP must be represented.

Record source URL and identity confidence, immutable revision/artifact digest, license, component type, target architecture, runtime dependencies, adapter/entry point, install/data paths, credential references, enabled capabilities, privacy/budget rules, estimated/measured resource use, verification evidence, and rollback/uninstall behavior. Do not put secret values in the manifest.

Keep these states separate: source resolved; downloaded; installed; discoverable; configured; authenticated; reachable; functionally tested; enabled; and tested on the actual target hardware. Also record pending source, pending credentials, incompatible account, unsupported platform, instruction-only/reference-only, experimental, disabled, and failed where relevant.

A partial setup can be useful, but the final report must say exactly what works and what remains pending. Include the error, evidence, practical next step, and exact resume command for each blocked item. Never turn missing functionality into a green success label.

## 10. Tests and acceptance criteria

Build meaningful automated tests around the installer's failure modes and integration contracts. Use local fixtures and synthetic data. Pin CI dependencies and document which tests run on x86, native ARM64, emulation, or the physical Pi; these are different kinds of evidence.

At minimum verify:

1. Fresh install and adoption of an existing supported install; no loss of unrelated files/configuration.
2. A second run creates no duplicate services, profiles, skills, jobs, accounts, or MCP entries.
3. Interrupted download/install resumes; package/network/DNS failures and disk exhaustion produce actionable errors and recoverable state.
4. Failed updates preserve the prior working generation; database backup and compatible restore actually work.
5. Registry discovery/validation, source-to-runtime mapping, missing dependency handling, inheritance, skill reference integrity, and profile isolation.
6. Actual enforcement of enabled registry boundaries, including denial tests; prompt text alone must not pass these tests.
7. Native Desktop launch, backend connection, a basic “Hello” response, cancellation, restart, and one harmless tool workflow.
8. Provider inference and tool calls, account-ineligible states, rate limiting, no unapproved paid fallback, and private-data routing—including memory extraction and retries.
9. GLM-5.2 artifact identity, actual ARM64 engine execution, measured resource/performance report, and a bounded failed/too-slow path. A small test model must not substitute for this target test.
10. Coral inference on the TPU, with an honest pending-hardware result when the device is unavailable.
11. MCP functional tests, Playwright fixture screenshot, and the selected memory provider's cross-session retrieval test.
12. Representative end-to-end tests for each integration class, plus a concrete verification method/status for every individual component. Heavy browser/render/indexing workloads must leave core chat usable within documented limits.

Add a coverage check mapping every item in this prompt to its OpenSpec requirement/change, manifest entry, implementation task, and test or explicit blocker. Preserve the ECC and OmniRoute duplicates as aliases while keeping all unique requested components. Run strict OpenSpec validation in CI and review implementation against its scenarios; specification validation alone does not satisfy these functional acceptance criteria.

Do not run the privileged host installer on the development machine just because shell access exists. Use isolated test environments. Execute on my physical Pi only when it has been identified and access is authorized. If hardware or credentials are unavailable, finish the code, fixtures, documentation, and executable target-verification workflow, then report exactly which live tests remain unperformed.

## 11. Required deliverables and completion workflow

Deliver a complete repository containing:

- Pinned OpenSpec development tooling, project configuration, canonical specifications, active/archived changes, task status, and requirement-to-test evidence mapping.
- Installer entry point and modular implementation; no placeholder handlers for features claimed complete.
- Configuration schema, example configuration, secure credential-reference templates, and a lock/provenance manifest.
- Registry importer/adapters and generated integration coverage report.
- Service definitions and component-specific lifecycle support.
- A concise quick start plus detailed installation, account setup, recovery, update, backup/restore, and troubleshooting documentation.
- Automated tests, CI configuration, and an honest verification report with hardware/account limitations.
- `SOURCES.md` and `COMPATIBILITY.md` recording dated primary evidence, selected revisions, source ambiguities, tested platforms, and unsupported features.

Work in stages: inspect and resolve sources; initialize OpenSpec and capture the complete scope; establish the target compatibility matrix; create scoped proposals, specifications, designs, and tasks; build the installer and registry adapter; implement providers/MCPs/components; validate specifications and verify implementation; fix defects and reconcile specifications; archive completed changes; finish documentation and handoff. Maintain the OpenSpec task checklist and keep progressing through unblocked work. Make routine engineering choices autonomously; ask only for genuinely missing source identities, credentials/account interaction, or decisions that cannot be safely inferred.

Finish with the project location, exact install/resume/verify commands, what is verified functional, what remains pending and why, and the evidence supporting readiness. The definition of done is a reproducible installer with demonstrable integrations and explicit limits—not the number of repositories downloaded.
