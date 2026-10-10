# Predecessor-bound candidate update v235

Sol refinement of original R0029/R0055/R0148/R0151/R0153/R0172/R0190: support existing installations, atomic compatible updates, recovery and preservation. Frozen baseline/tag unchanged. Actual source audit found root setup bootstraps only absent pointers; a verified existing predecessor bypasses candidate selection and UPDATE remains pending. Existing publisher supports present pointer CAS, but builder snapshots its predecessor only after staging and handoff does not carry an update subject.

`planning/predecessor-bound-candidate-update-v235.json` specifies exact current predecessor before source acquisition, fixed-origin SHA/tag/tree/full-input verification, same-controller sealed runtime handoff, reviewed candidate build, existing atomic publisher, durable owned old-pointer rollback and genuine installed candidate reexecution. No pointer deletion/fake fresh install, downgrade, caller bytes, fabricated receipts or runtime completion. Distribution publication is separate from compatible active generation/data/health update; missing runtime adapter remains precise pending.

BD-T235.1 → LC-T235.2 → VD-T235.3 OPEN; no tested source pins or deployment claims. All AC01..18 OPEN.
