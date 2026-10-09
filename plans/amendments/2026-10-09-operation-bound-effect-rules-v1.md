# Operation-bound protected effect rules v1

Sol additive implementation refinement of original R0054/R0058/R0130 and existing HI03/HI07/HI09. Add HI12/HI-T12/EV-HI12, prerequisites HI-T03/07/09. Frozen baseline/tag and all18AC unchanged; no general operation wildcard or new destination authority.

## Exact operation rule index (HI12)

Protected rule lookup is (capability,operation,target), never only capability/target. Every context/effect admission intersects exact allowed operation and signed canonical payload/generation/recipient/retry/nonce/deadline. Same target may have distinct exact singleton-operation rules; duplicates/ambiguity/implicit wildcard or legacy pair fallback fail closed. Legacy rule migration may explicitly enroll its already-stated singleton operation and new policy revision; never infer extra verbs. Old grants invalidate on revision change.

HI07 exact operations connector.open/read/write/close all use hermes-service-connect plus same canonical enrolled target_id. Frames bind owned connectorID/generation/session/sequence/route plus requested read bound or exact write bytes/hash, remaining bytebudget and deadline; fresh one-use grant for every operation, no reusable open grant. Root original admission lease/resource limits remain hard ceiling, not renewed by later frame grants. Root watchdog expiry/revocation and authenticated owner cancellation close both directions independently of obtaining fresh authority; expired grant cannot keep a stream alive. Cross-owner/sibling close denied. Actual finite stream behavior and operation-switch/replay/duplicate/legacy/digest/deadline negatives are needed beyond rule-key fixtures.
