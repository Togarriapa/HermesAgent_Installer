# Frozen task handle write phase v57

Existing RB-T08 actual EOF receipt clarification: the same frozen ManagedTaskHandle crosses pre-stdin and post-EOF phases. Its manager-backed receipt lookup is null before write and resolves actual retained custody receipt afterward; terminal stores the nonnull receipt after issuance. No handle replacement, worker mutable authority or changed acceptance scope. Baseline unchanged.
