# Xpra disabled-control MVP repair v260

Extends BD-T259.1 and original AC13..15. Actual signed Xpra6.5.4 fails with --control=no because args_control imports a deliberately unavailable control module. Source ownership is xpra-server, not xpra-common. Exact contract: `planning/xpra-disabled-control-mvp-repair-v260.json`.

Only the three-line feature guard is allowed. Local xpra-server6.5.4-r0-1+jarvis1 is explicitly a local rebuild of verified signed input, with payload/control comparison and exact installed stub hash. All disabled-control flags, sandbox/TLS and app-only gateway controls remain. No direct vendor hotpatch/PYTHONPATH or wider policy changes. BD-T260.1/VD-T260.2 and all acceptance remain OPEN; exact member/diff and bounded disabled/enabled method regression independently reviewed; local repack/live launch pending. Frozen baseline unchanged.
