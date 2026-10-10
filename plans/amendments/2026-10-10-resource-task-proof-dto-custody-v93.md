# Resource task proof DTO and custody v93

Refines v88 original RB-T08/HI-T09/HI-T12 finite task route: exact distinct signed RootResourceTaskContext/EffectAuthorization/StartGrant and sealed consumed proof are enumerated. Existing authority signer/nonce machinery is reused with resource-specific domains/eligibility. Controller proof and selected child subject remain distinct. Custody accepts the sealed resource proof directly rather than fake worker peer fields. Root actual child loader/input/write/EOF/terminal/result APIs still required.

Selected effective resource row also binds actual root selected consent receipt. Exact fields/signatures in planning/protected-resource-job-contract.json.resource_child_process_start_route. Evidence covers replay/attempt/task/stdin/generation/controller/consent mutation and authentic start-to-terminal proof. Baseline unchanged and all acceptance pending.
