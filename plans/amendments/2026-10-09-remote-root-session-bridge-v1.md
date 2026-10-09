# Root-observed remote session bridge v1

Sol additive HI13/HI-T13/EV-HI13 refinement of original AC13..15/R0200/R0201/R0206/R0207 and HI07/09/RP02..05. Gateway verified local claims cannot mint authority context for separate root connector. Root re-verifies actual Access JWT and fresh selected policy using protected config/isolated read vault, joins actual authenticated subject to enrolled principal and binds allbytes/lease/revocation to current target generation. planning/remote-root-session-bridge-contract.json defines exact admit/renew/close API/state/config fields. No self-signed gateway claim substitute, generic URL/identity/lease or management credential reuse. Bounded renewal checks not instantaneous revocation claims.

HI-T13 prerequisites HI-T07/HI-T09/HI-T12/RP-T02/RP-T03/RP-T04; HI-T06 and RT-F03 additionally depend HI-T13. Native/account positive and denial/active-WebSocket revocation evidence remain open, all original scope/frozen baseline/tag preserved.
