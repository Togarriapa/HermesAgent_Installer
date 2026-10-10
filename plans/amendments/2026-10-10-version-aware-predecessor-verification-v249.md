# Version-aware immutable predecessor verification v249

BD-F03/LC-F03/AC01..02 and v235/v242 require a fully verified old installed predecessor before source-update. The new verifier applies newest module pins to old cc81 and rejects its exact Gitcc81 root_setup5bd49b6e/62517 row before candidate TTY selection. Current actor pins must remain newest.

The exact contract `planning/version-aware-predecessor-verification-v249.json` selects one independently reviewed whole cc81 historical cohort from the fixed pointer candidate, with exact Git tree/blob provenance and static constants in the adjacent cohort JSON. Old code is never imported or executed. A dedicated sealed predecessor-only receipt retains the same complete file/tree/owner/hash/layout/baseline/current pointer custody; original instance CAS snapshots stay dynamic, not per-Pi allowlist hashes. No caller trustbundle, mixed-cohort fallback, oldcode patch or ordinary actor weakening.

Observe/admit/reexec snapshot/rollback use the dedicated predecessor verifier. The new selected candidate still requires fresh TTY/fixed-origin ancestry/source actor/build/CAS/new installed actor. BD-T249.1, LC-T249.2, VD-T249.3 remain open; actual Pi failure diagnosis is not acceptance.
