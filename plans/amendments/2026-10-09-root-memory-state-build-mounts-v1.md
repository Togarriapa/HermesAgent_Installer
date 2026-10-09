# Root memory state and deterministic build mounts

Sol additive refinement of original SK01/SK-T01, HI09/HI-T09, HI12/HI-T12 and HW03/HW-T03. Baseline unchanged. Existing implementation and all native acceptance tasks remain open.

The memory authority ledger cannot share service-writable data roots, and protected build artifact pins alone do not define usable in-unit paths. The two live contracts now define root-only journal state and finite protected build mount tokens. No caller paths, arbitrary argv, generic HTTP, replay of consumed grants or predicted compiled output hashes are introduced.

Evidence EV-SK01 requires real isolated backend effects, wrong-owner/path/alias/state corruption/restart/concurrency/lease negatives and fresh per-step grants. EV-HI09/EV-HW03 require actual root launch/mount/UID isolation, selected source/toolchain pins, terminal-success constrained ARM64 outputs and denied escape/unknown-token/artifact/generation cases. Fixtures do not close target acceptance.
