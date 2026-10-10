# Bootstrap handoff root TTY reconfirmation v208

Refines BD-F02/HI-T149.1 and the v203 safe diagnostic source contract. Actual source resolves a60s root TTY proof before minutes-long source/runtime acquisition and consumes it at handoff. Actual5ed reports the handoff RuntimeError boundary; no more specific internal cause is established.

After selected source/runtime staging, require a new explicit root foreground TTY re-entry of the SAME exact candidate SHA, with original finite lifecycle action displayed and unchanged. RootBootstrapCandidateSelectionRegistry.reconfirm_for_handoff consumes/replaces the original selection with a fresh independent <=60s proof after exact same-controller/TTY/livePIDFD checks. Original expired proof is retained lineage only, never current authority; do not extend/renew its expiry. Existing source/runtime/choice/controller joins, same-process sealedFD3 reexec and post-reexec expiry checks remain intact. Exact API/order/failure closure are in planning/bootstrap-handoff-tty-reconfirmation-v208.json.

BD-T208.1 implementation and VD-T208.2 tests/source-pin review/target evidence remain OPEN. Mismatch/cancel/drift/expiry/replay fail closed; no service/account authority added. All original scope and AC01..18 OPEN; frozen baseline unchanged.
