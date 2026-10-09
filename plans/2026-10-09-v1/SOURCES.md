# Dated primary source evidence — 9 October 2026

Metadata checks pin identities/revisions/licenses; they do not establish ARM64 functionality, account entitlement or installed behavior. The five initially ambiguous names are selected by the user-authorized most-starred policy; dated evidence and source override history remain explicit. `planning/source-revisions.json` is the machine-readable metadata inventory; README path/digests and observed host mentions are in `planning/source-readme-evidence.json`.

## Canonical upstream and installer workflow

- [OpenSpec CLI reference](https://github.com/Fission-AI/OpenSpec/blob/main/docs/cli.md); installed exact npm version1.14.1, Node24.6.0 (package engine >=20.19.0). Codex initialization generated six skills in .agents/skills, core profile; no verify workflow generated. Actual CLI instructions/status snapshots are evidence/planning/. The pinned package supplies the authoritative installed schema.
- [Hermes Desktop README](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/apps/desktop/README.md), [build guide](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/apps/desktop/BUILDING.md), [installation](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/website/docs/getting-started/installation.md), [platform support](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support): official existing-install `hermes desktop`, source build/user-session path; observed Linux release packaging disabled. Current supported runtime is PM-managed Python3.14; pyproject's wider interpreter range is updater compatibility, not runtime assurance. No native Pi proof has run.
- [Hermes profile contract](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/website/docs/user-guide/profiles.md), [skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills), [MCP](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp), [memory providers](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/website/docs/user-guide/features/memory-providers.md), [Codex runtime](https://github.com/NousResearch/hermes-agent/blob/7085fbf7753266fc4943c55ac04926186bc90005/website/docs/user-guide/features/codex-app-server-runtime.md): native profile state separation is not host sandboxing; shared HERMES_HOME writers prohibited. Codex app-server is supported opt-in but removes delegate_task/memory/session_search/todo. One active external memory provider; OpenViking server environment must be sanitized and lazy installs disabled.
- [Registry import contract](https://github.com/Togarriapa/HermesAgent_Resources/blob/113f42d33be9e0c8f0f47f5ca998e687323dec83/RUNTIME_IMPORT.md), catalog/SPEC/TOPOLOGY/ORCHESTRATION/PROFILE_MATRIX/INTEGRATION_MATRIX/EXTERNAL_INTEGRATIONS/QUALITY_POLICY and validators were inspected. Catalog2.3.1 has eight nonrecursive declared roots; host authorization must be applied after materialization. Authentik checks and bounded brokers are real runtime requirements. No registry source content is redistributed here; no root license detected.
- [Colibri quickstart](https://github.com/JustVugg/colibri/blob/bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850/docs/quickstart.md): Linux ARM64 source build required; prebuilt Linux binary is x86_64. 16GB minimum/24GB recommended and about430GB model are upstream claims, not Pi measurements. [Exact GLM-5.2 artifact](https://huggingface.co/mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp/tree/6bbb01ed3e515a8730b694dfae73aadfd6774581) metadata pins149 files/429276220139 bytes, declared MIT/base model zai-org/GLM-5.2 and LFS digests including MTP. `planning/glm52-artifact-metadata.json` records these; verify card/config/license before activation. No model downloaded.
- [Coral compatible models](https://coral.ai/docs/edgetpu/models-intro/), [USB setup](https://coral.ai/docs/accelerator/get-started/), [PCIe setup](https://coral.ai/docs/m2/get-started/): separate compiled quantized TFLite delegate inference; no general LLM acceleration.

## Accounts, routing and MCP

- [OpenRouter exact free endpoint](https://openrouter.ai/nvidia/nemotron-3-ultra-550b-a55b:free) prohibits confidential/personal uploads and logs for NVIDIA purposes. Public live catalog snapshot in planning/openrouter-nemotron.json reports text-only, zero prompt/completion prices, tools/tool_choice,1M context/65536 max completion; response_format absent. Refresh at configuration; catalog does not prove actual account entitlement.
- [OpenAI Codex authentication](https://developers.openai.com/codex/auth) distinguishes subscription access from billed API-key usage. Use upstream supported host auth/refresh ownership, never a token replay bridge.
- [Anthropic authentication](https://code.claude.com/docs/en/authentication): evaluate actual account eligibility; Claude Free must not be assumed to grant Code/API access. No purchase or consumer-cookie bridge.
- [Google official MCP](https://developers.google.com/workspace/guides/configure-mcp-servers): current Developer Preview prerequisite plus Google Cloud project; personal-account eligibility unverified. The community option is explicit and independently reviewed, never labeled official.
- [Home Assistant official MCP](https://www.home-assistant.io/integrations/mcp_server/): stateless Streamable HTTP, /api/mcp or /api/mcp/assist; base admin access differs from Assist. OAuth client identity/redirect and metadata rules must be respected. Use existing selected exposed entity read only.
- [Figma remote MCP](https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/): official https://mcp.figma.com/mcp with selected file/account-plan validation.
- [RevenueCat MCP](https://www.revenuecat.com/docs/tools/mcp/setup): official https://mcp.revenuecat.ai/mcp, scoped OAuth/APIv2 credentials and selected-project read-only checks.
- [Playwright MCP](https://github.com/microsoft/playwright-mcp): pin package and native ARM64 sandboxed browser; local fixture navigation/accessibility/screenshot.

## Immutable repository seeds

| Seed | Canonical identity | Default branch | Commit | Detected license |
| --- | --- | --- | --- | --- |
| AgriciDaniel/banana-claude | AgriciDaniel/banana-claude | main | `6a2b1b51fdcc35932184f06e513646a6f6f4f7d8` | MIT |
| DietrichGebert/ponytail | DietrichGebert/ponytail | main | `9cc65d03aa2da1db7121b912d03596409ee340b8` | MIT |
| Fission-AI/OpenSpec | Fission-AI/OpenSpec | main | `9111a7654d7800391459431fff4eaf66e33a3d2e` | MIT |
| Graphify-Labs/graphify | Graphify-Labs/graphify | v8 | `5b74d7d74911cf435c8f1636b6f96ea202cc6246` | Apache-2.0 |
| Jakeschincariol/replica-skill | Jakeschincariol/replica-skill | main | `77c9436fb3d18c3d58169efb8caf4fe906b0dc51` | MIT |
| JustVugg/colibri | JustVugg/colibri | main | `bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850` | Apache-2.0 |
| K-Dense-AI/scientific-agent-skills | K-Dense-AI/scientific-agent-skills | main | `92ace75ac21efe19a620434e0ca4e356081fe807` | MIT |
| Leonxlnx/taste-skill | Leonxlnx/taste-skill | main | `18dfc928b135629e0eddfdd445a06400d04ed439` | MIT |
| NousResearch/hermes-agent | NousResearch/hermes-agent | main | `d2639c0dc85a78564ed31c0ab218fe6ee2cbd4c7` | MIT |
| Panniantong/Agent-Reach | Panniantong/Agent-Reach | main | `94f06c1969dfc1834001269d79d3ad0972d9dee6` | MIT |
| ScrapeGraphAI/Scrapegraph-ai | ScrapeGraphAI/Scrapegraph-ai | main | `194055e203afce41ed4e70365dbc416bad756115` | MIT |
| SenteLabsAI/OpenExecutive | SenteLabsAI/OpenExecutive | main | `303d45eaa0b2323f2e9646d19bf35dbcc98c6d71` | Apache-2.0 |
| Togarriapa/HermesAgent_Resources | Togarriapa/HermesAgent_Resources | main | `113f42d33be9e0c8f0f47f5ca998e687323dec83` | not detected — review required |
| abi/screenshot-to-code | abi/screenshot-to-code | main | `d026163f586dfa8c5c10d28c36edd59a9d3b0e88` | MIT |
| addyosmani/agent-skills | addyosmani/agent-skills | main | `1401c8b8030e023baeebb31781a6653fe8e93026` | MIT |
| adewaskar/jarvis | adewaskar/jarvis | main | `1c4016afdf86f7043efc6882ceffef84ad0d8783` | MIT |
| affaan-m/ECC | affaan-m/ECC | main | `ef648e01899ba3e8dc6371642deaaf64b4477775` | MIT |
| ai-boost/awesome-harness-engineering | ai-boost/awesome-harness-engineering | main | `6826dfaaaa6a996507336e4539f4b88d2fff709e` | NOASSERTION |
| apple-ouyang/book-to-skill | apple-ouyang/book-to-skill | main | `a24960ac89a3baa96a87cdf5ebaecf16c5d2eab1` | MIT |
| bergside/awesome-design-skills | bergside/awesome-design-skills | main | `f631a09b4fcc0166f2e2c1a8c81906ef680c57e8` | MIT |
| blader/humanizer | blader/humanizer | main | `225a6f39ac85f76ee48dbad772ea4abe4ed6c9d8` | MIT |
| browser-use/browser-use | browser-use/browser-use | main | `c75e8476e26d18b7617643bc2ae082fae8eae431` | MIT |
| cathrynlavery/diagram-design | cathrynlavery/diagram-design | main | `f4547ee95f88e5b28a52517feff6b6c11cc657f9` | MIT |
| dickwu/apple-design-skill | dickwu/apple-design-skill | main | `904b0eedc7cc778152f545506075d5bb5219ce77` | not detected — review required |
| diegosouzapw/OmniRoute | diegosouzapw/OmniRoute | release/v3.8.52 | `4ea24a2f8e1faf8a606c8b8dce45e5b1ab6c9bb0` | MIT |
| emilkowalski/skills | emilkowalski/skills | main | `e8a175de22ae1e49370fc144c1f3bb9aeedf988d` | MIT |
| garrytan/gstack | garrytan/gstack | main | `20eb6202fa8ea83a882e7c0463b722cd8a31af1e` | MIT |
| heygen-com/hyperframes | heygen-com/hyperframes | main | `46f6cb356785bed79e1ce7b79d7e7accc697786a` | Apache-2.0 |
| kepano/obsidian-skills | kepano/obsidian-skills | main | `3ccff5338ea700537839b21900aa5358a0402c98` | MIT |
| latent-spaces/brag | latent-spaces/brag | main | `7079945d391573edebe48fdc0a23b39c4b4e8726` | MIT |
| microsoft/playwright-mcp | microsoft/playwright-mcp | main | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | Apache-2.0 |
| mukul975/Anthropic-Cybersecurity-Skills | mukul975/Anthropic-Cybersecurity-Skills | main | `54a798831d2266a3ca61ce68a7acb80b81160d57` | Apache-2.0 |
| nextlevelbuilder/ui-ux-pro-max-skill | nextlevelbuilder/ui-ux-pro-max-skill | main | `50d8a7de0900119855614541f15a1a616691eb33` | MIT |
| obra/superpowers | obra/superpowers | main | `8ca22dba9a94f28898bbce59f2537ff4d87c747d` | MIT |
| pbakaus/impeccable | pbakaus/impeccable | main | `d631a8827f99414d2b6daba4ef08b7f8701751d7` | Apache-2.0 |
| public-apis/public-apis | public-apis/public-apis | master | `874e5879d20843f7c2a5822cef4c0752127b3775` | MIT |
| rohitg00/agentmemory | rohitg00/agentmemory | main | `df3d4a83b966d8d415cb9180d5a4724b07f729dc` | Apache-2.0 |
| ruvnet/ruflo | ruvnet/ruflo | main | `58e0ae7e14e68aab45a4127d6f42f567bbcfb328` | MIT |
| taylorwilsdon/google_workspace_mcp | taylorwilsdon/google_workspace_mcp | main | `2e9e9e785d30abaf89cf181c548d172b09ed0150` | MIT |
| thedotmack/claude-mem | thedotmack/claude-mem | main | `fa8ab09f06aa05f958c5225cf3756ce52a3ebb96` | Apache-2.0 |
| virgiliojr94/book-to-skill | virgiliojr94/book-to-skill | master | `e180fc46365e8c1aab0120778cc8a40b9515324b` | MIT |
| volcengine/OpenViking | volcengine/OpenViking | main | `e7b2e974b1fb97cd8c6087ff013181ddfec94f77` | AGPL-3.0 |
| walkinglabs/awesome-harness-engineering | walkinglabs/awesome-harness-engineering | main | `cff9b006ef64c624a62cbb1ee36b0c4b2b3a67ad` | NOASSERTION |

Source URL overrides require identity/revision/license review and explicit selection for unresolved names. No transitive package or installer script is trusted simply because the README mentions it.

## Toolchain audit

npm audit of the exact lock reports the braces stack-exhaustion advisory GHSA-vfj7-8cjw-p6xm through OpenSpec/fast-glob/micromatch (four dependent high findings). Latest available braces observed3.0.3; npm's offered OpenSpec0.17.2 downgrade does not meet the selected workflow. Recorded blocker B-OPENSPEC-AUDIT: trusted bounded local patterns only, developer tooling scope, compatible fix requires Sol amendment. This does not imply a runtime Pi vulnerability or completed mitigation.

## Later direct Cloudflare requirement —9 October2026

[Official managed tunnel API](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/) documents cloudflare-managed configuration with exact ingress and final404; [Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/) requires trusted team issuer/AUD, RS256/kid key lookup/rotation and time validation; [email one-time PIN](https://developers.cloudflare.com/cloudflare-one/access-controls/identity-providers/one-time-pin/) uses onetimepin identity provider and allowed-email policy. Restrict app allowed_idps explicitly rather than default all. [Organization API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/) supplies auth_domain. Scoped permission/zone discovery and token-file support are reviewed in planning/cloudflare-primary-evidence.json; runtime cloudflared2026.10.0 ARM64 asset SHA256 e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08/37687584bytes. No actual account setup/inference is established.

[Xpra seamless](https://github.com/Xpra-org/xpra/blob/master/docs/Usage/Seamless.md) exports application windows; [security](https://github.com/Xpra-org/xpra/blob/master/docs/Usage/Security.md) warns remote command/control/integration features need server-side disablement; [HTML5 configuration](https://github.com/Xpra-org/xpra-html5/blob/master/docs/Configuration.md) defaults include broader client options, so use constrained fixed client plus enforced server/gateway policy. Native ARM64 Debian support is tier3; app/window isolation and Pi usability remain unproven. Newly pinned bridge/connector repository revisions are in source-revisions.json.
