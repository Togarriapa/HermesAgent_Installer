# Manual Jarvis stage gateway seam v259b

Extends immutable v259 under the same RT-T259.3/LC-T259.4/VD-T259.5 tasks and original AC13..15. Existing managed gateway requires active installer authority; manual stage uses a distinct typed finite adapter, preserving all managed checks. Exact contract: `planning/jarvis-manual-stage-gateway-seam-v259b.json`.

Reuse actual JWT/JWKS and server controls. Test a same-app protected one-use nonce edge roundtrip for current admission/revocation without copying an unavailable management credential. Primary documents support edge token revocation, but actual propagation/failure tests gate public acceptance. Optional genuine isolated policy-verifier IPC remains supported. No get-identity-only or JWT-only revocation assertion. Root-owned actual unit/UID/listener/configuration supports fixed app-only connector; no fabricated active rows.

Implementation/source pins and all target acceptance remain OPEN. Frozen baseline unchanged.
