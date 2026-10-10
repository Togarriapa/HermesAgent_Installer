# Resource existing child-attempt context v82

Existing RB-T08 requires fresh bounded authorization for each retry. Reuses actual ResourceChildAdmission/ledger IDs and makes root context issuance one-use per actual attempt, not permanently one-use per node. Full source/result closure and selected quota/currentness remain mandatory; ambiguous effects never auto-retry. No new worker retry authority or product scope. Baseline unchanged/all AC pending.

Evidence: real root ledger initial/retry transition, fresh grants, wrong attempt/quota/lineage/generation/consent and ambiguous outcome negatives. Original actual native backend tests remain required.
