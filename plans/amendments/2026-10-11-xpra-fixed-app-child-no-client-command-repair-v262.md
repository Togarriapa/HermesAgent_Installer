# Fixed native app child without client commands v262

Extends immutable v260/v261 inside BD-T259.1/AC13..15. Actual commands=no prevents configured start-child. Exact source audit shows commands=yes alone exposes unguarded client hello run and command-signal; it is denied until the minimal registration/direct-handler patch and inspector/readback succeed. Exact contract: `planning/xpra-fixed-app-child-no-client-command-repair-v262.json`.

Only fixed server-owned native child may start; client requests remain denied under start-new-commands=no and all shell/control/logging/security restrictions. Local +jarvis3 retains three prior guards, changes only reviewed fourth member/control integrity/version. No broader process authority or runtime acceptance. Exact member/AST/13 regressions independently reviewed; final package/readback/native launch pending; all AC OPEN.
