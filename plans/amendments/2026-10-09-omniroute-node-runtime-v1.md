# Pinned isolated OmniRoute Node runtime v1

Sol additive refinement of existing OmniRoute original provider policy R0130/PR-F03 and selected source/component contract. Add PR02/PR-T02/EV-PR02 with prerequisites PR-F01/HI-T01/HI-T09. Frozen baseline/tag and all18AC unchanged.

## Pinned OmniRoute Node compatibility (PR02)

The selected source4ea24a2f8e1faf8a606c8b8dce45e5b1ab6c9bb0/package.json v3.8.52 declares >=22.22.2 <23 || >=24.0.0 <27 (official pinned manifest read2026-10-09). Existing protected PM source catalog declares Node26.7.0 LinuxARM64 archive SHAafc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d, which meets that source range. Node20.19 is not eligible. This is a source/range decision, not artifact-byte/native support evidence.

Use a separately staged component-owned protected instance of that exact selected Node artifact; host/globalNode and HermesPM runtime stay preserved. Verify root catalog bytes/hash/license/nativeABI, complete pinned dependency lock and reviewed fixed build recipe before enrollment. Protect executable/PATH/module roots/output generation under host custody; no caller npm flags/URL/path, unreviewed resolver/postinstall/lazy dependencies or writable import ancestors. Root fixed bounded build/start profile applies actual reviewed dependencies/ARM64 native health; incomplete source/toolchain/module/ABI remains exact unavailable state. Source catalog acquisition and runtime egress remain distinct controlled operations.

planning/omniroute-runtime-contract.json records exact source/range/pin and evidence separation. Original OmniRoute source/privacy/tool/recipient/zero-budget and loop/fallback constraints still apply; engine match cannot authorize direct provider egress or paid fallback. PR-T02 supplements existing PR-F03/PR-R0130; actual native build and provider operation remain open.

Primary source: https://raw.githubusercontent.com/diegosouzapw/OmniRoute/4ea24a2f8e1faf8a606c8b8dce45e5b1ab6c9bb0/package.json
