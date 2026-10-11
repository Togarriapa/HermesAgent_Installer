# Binding-preserving manual MVP ingress v263

Extends R0196..R0205, RT-F02, AC13..15 and RT259.3/LC259.4/VD259.5 without removing original scope. The actual binding-enabled Access response302 invalidates the server self-probe mechanism, not JWT/security requirements.

Use only the closed contract in `planning/jarvis-binding-cookie-unix-heartbeat-v263.json`: owned cloudflared Unix peer, independent root ingress inspection, JWT before app effects and browser credentialed nonce heartbeat with hard five-second expiry. Keep browser binding cookie private and all original lease/deadline limits. Gateway listen readiness does not imply admission.

Luna implements RT-T263.1; VD-T263.2 tests effects/failures and actual binding-enabled browser/revocation/restart. No runtime implementation, source pin or target acceptance is claimed. All AC remain OPEN.
