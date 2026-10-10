# v240 Measured official Desktop headers and fixed managed build interface

Refines v218/v226/v227/v229/v234/v237 for baseline R0028/R0035/R0037/R0203/R0204/R0211 and AC13..15. Frozen v226 remains unchanged. Exact contract: `planning/official-desktop-measured-headers-managed-plan-v240.json`.

The actual retained official Electron40.10.2 header archive and SHASUMS are independently remeasured, with one exact normal-TLS redirect, a unique matching checksum row and a closed 124-file member observation. These are source observations; current held receipt, license verification and production acquisition remain implementation obligations.

The fixed PM314 source driver uses selected Node/native tools and the pinned upstream build/stage/prepared packaging helpers, explicit offline Electron headers, separate binary/npm/sysroot receipts and actual AppDir output. Upstream exported stamp helpers accept genuine held source revision via HERMES_BUILD_COMMIT and emit commit-build without fake CI/Git or fallback zero revision. Member-only and recipe-bound digests remain acyclic.

Owner observed actual ARM64 typecheck/native ABI/sandbox fixture effects. Full AppDir and peak memory remain pending. The reviewed interface deliberately leaves memory/CPU/IO/task/output caps unavailable; any null bound denies plan issuance/execution. The source heap option is no measured MemoryMax. No code/source cohort pins, runtime/Pi acceptance or foreign/global host changes.

RT-T240.1/.2 and VD-T240.3 remain open. Luna Desktop owns the concrete driver/providers and output observer; executor owns exact native plan admission after measured bounds. v239 owns preactive enrollment/network and runtime receipt issuers separately.
