# v250 Factual Xpra archive link count correction

Append-only correction to v245 for baseline R0028/R0035/R0037/R0203/R0204/R0211 and AC13..15. Exact contract: `planning/xpra-link-count-correction-v250.json`. v245 and all earlier artifacts remain immutable.

Sol independently reopened every one of the399 actual cached DEB archives, rechecked original byte SHA/size against the v238 signed-policy cohort, and counted original data-tar type headers. There are **3093 symlinks and zero hardlinks**, all typeflag2. Every projected package/version/path/raw-target/mode row matches the immutable v245 observation SHA419c6355d2a00d91325f2286cb70973f412b5fd504103fc1d64fb856531860f6. The original observation is correct; only v245 prose and summary fields were wrong. The earlier3052 extracted-tree diagnostic was not a canonical archive inventory and did not establish41 hardlinks. No replacement observation or policy graph hash is needed.

The actual materializer must use this exact symlink cohort and reject unreviewed kinds/origins. Existing64-hop private-root graph rules, signed/license/current CAS/PM/NSS/choice custody, exact glibc transform, bounded sysroot and actual managed native/session qualification remain unchanged. Source facts are not production/current runtime receipts.

RT-T250.1 and VD-T250.2 remain open. No code/source pins or Pi/runtime acceptance; all AC OPEN.
