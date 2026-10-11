# Bounded native observation sharing v264

Extends RT-F02/R0196..R0205/AC13..15 and v259/v263 under unchanged original scope. Actual burst request ages exceed five seconds while full scans take less than0.4s; the serialized perasset fullscan and discarded root timestamps are the concrete seam.

The exact `planning/jarvis-native-observation-burst-sharing-v264.json` authorizes root-owned native single-flight sharing only during the original nonextendable five-second observation. Every nonce request retains fresh cheap custody/currentness joins, and every app request retains fresh Unix ingress/JWT checks. Fullscan is mandatory initially and after expiry/change/failure. Typed root timestamps propagate to per-byte denial; no restamp or authorization cache.

RT-T264.1 implements inspector and consumer; VD-T264.2 verifies effects/negative burst behavior and actual Pi visibility/revocation/restart. No runtime source pins or acceptance; all AC OPEN.
