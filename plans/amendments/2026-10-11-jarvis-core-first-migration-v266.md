# Core-first Jarvis migration v266

The direct user decision on 11 October replaces official Desktop as the active installed product with standard Hermes as engine and a custom Jarvis interface. This explicitly supersedes native-only presentation and v265 conditional Desktop retention; it does not delete the frozen baseline or claim its old Desktop acceptance passed. Historical proposals, packages, source and unfinished work remain recoverable.

Order: core installer/runtime → capabilities one by one → responsive Jarvis UI → full Resources/enrichment → core/UI end-to-end review. A useful core increment may ship before all original obligations are complete; unavailable functions remain visible with exact resume status. Phase 2 is iterative: the first real capability unlocks UI work; full capability parity is not a prerequisite for initial visible MVP.

## Concrete handoff

See planning/jarvis-core-first-migration-v266.json and openspec/changes/jarvis-core-platform/. Five phase tasks remain unchecked. Phase 1 alone is the immediate implementation handoff. Preserve existing /home/admin/.hermes and Codex auth by verified adoption/reference, not copying secrets or invoking upstream reset/stash on an adopted tree. Establish independent owned core service and real functional proof before stopping owned Desktop/Xpra; record backups and reversible service/config journal. Preserve unrelated services and Cloudflare resources. No GUI preflight gate for core-only install.

Bot groups need server-owned full durable room/orchestration state and relay; the Desktop's bounded ui_meta mirror is insufficient. Port actual stream/approval, browser, inventory, menu and artifact contracts individually, not by wildcard proxying native trusted RPC. Family conversation ownership is not tool/filesystem/memory isolation. Deny unproven private capabilities and management access. HA remains deferred.

All original acceptance stays OPEN except that Desktop-specific product targets are explicitly superseded rather than falsely completed. No runtime/source pin is added. All tests and validation run only on Pi via root browser; local source/spec editing and Git are allowed. No additional spending or model download.
