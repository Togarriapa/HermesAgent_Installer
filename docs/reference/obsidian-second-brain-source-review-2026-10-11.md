# Obsidian primary second brain — implementation source review

Change jarvis-core-platform; required R0090/HI-T266.2, dashboard R0203/RT-T266.3, Resources RB-T266.4, native learning R0055/R0131 and one capture owner R0135. Latest direct user instruction selects Obsidian as primary second brain and authorizes its implementation. TikTok metadata is not the implementation source. Constella is not the selected second brain.

## Existing repository behavior

- `components/obsidian_skills.py` selects pinned `kepano/obsidian-skills` revision `3ccff5338ea700537839b21900aa5358a0402c98`, writes bounded UTF-8 Markdown and validated JSON Canvas through `ApprovedVault`, and reports CLI presence separately as available-unverified or unavailable.
- `components/portable_skill_adapters.py` binds an existing selected-profile directory, rejects normalized-path traversal/symlinks and writes via temporary file, fsync and replace. This is a useful primitive, not owner authorization, race-safe persistent read/search or conditional-write service. Harden actual managed effects where necessary rather than inventing a new generic filesystem proxy.
- `tests/integrations/test_obsidian_skills.py` exercises a temporary Markdown/Canvas vault and path denials. It does not demonstrate a durable Pi vault, Hermes tools, dashboard graph, app installation or device synchronization.
- Current-scope R0090/component `obsidian-skills` keeps its original ID, aliases, upstream and acceptance OPEN; its required handling now includes the primary persistent second-brain integration. R0055/R0131/R0135/R0203 supply learning, capture and UI policy without a new task forest.

## Official source checks, 2026-10-11

[Official downloads](https://obsidian.md/download) explicitly offer Linux AArch64/ARM64 AppImage and Android Play/APK plus iOS. The ARM64 link currently resolves to official release `v1.14.4/Obsidian-1.14.4-arm64.AppImage`; its binary was not downloaded/verified or installed in this review. ARM64 availability is established, target compatibility/launch remains unqualified.

[Official vault management](https://obsidian.md/help/Files%2Band%2Bfolders/Manage%2Bvaults) documents opening an existing folder as a vault. [Storage documentation](https://help.obsidian.md/Files+and+folders/How+Obsidian+stores+data), separately checked by ROOT, describes ordinary Markdown files and external-edit refresh with `.obsidian` configuration. Thus a native-compatible file vault is a concrete headless first slice; it must not be reported as the GUI app installed.

[Official CLI](https://obsidian.md/cli) requires app installation, CLI activation/registration and a running Obsidian app for its commands. Do not make this graphical prerequisite block headless vault read/search/write. A later native-app adapter must preserve the browser/Electron sandbox; no remote host desktop or arbitrary CLI/eval proxy.

[Official device-sync guidance](https://obsidian.md/help/Getting%2Bstarted/Sync%2Byour%2Bnotes%2Bacross%2Bdevices) distinguishes device-local vaults and synchronization. The direct instruction requires actual Obsidian compatibility and useful Android/tablet access, not paid Sync enrollment. Browser access is not native app sync. Preserve existing sync choices; no paid service, new cloud repository or device pairing is implied. A protected bounded vault export/import can be a manual first handoff, with conflict handling and app “Open folder as vault” steps; ongoing synchronization remains a separately verified account/device slice.

## Compact implementation ownership

Luna Obsidian leaf owner: persistent selected-owner vault store, validated read/search/link-index, per-execution private drafts, exact Jarvis-reviewed conditional promotion, bounded native tool functions and finite dashboard projection/fragment. ROOT supplies existing native plugin/owner admission and fixed managed root registration; do not concurrently rewrite authority files. UI integrator composes the fragment into Resources/Skills or a clear Second brain destination within Resources, plus one actual Overview summary. Existing component adapter and portable skills remain reused. First real proof is native Jarvis write→read/search/backlink→restart readback, with expert draft-only denial and owner-visible dashboard data; GUI/mobile/sync get separate observed results.
