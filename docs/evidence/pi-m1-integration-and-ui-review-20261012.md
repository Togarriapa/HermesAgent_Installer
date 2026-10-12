# M1 integration qualification and UI review

Change: `jarvis-core-platform`; R0090/R0200/R0201/R0203,
BD-T266.1/RT-T266.3/RB-T266.4/VD-T266.5. Reviewer: Root with Sol specification
and Luna implementation, 2026-10-12, Europe/Lisbon.

This record distinguishes source validation, controlled Pi fixtures, visual
review and production acceptance. All eight acceptance groups remain open.
The production source remains `0cbf9b819a6be41b3ff34d623374355cb64c3834`;
no new candidate was deployed during these checks. A fresh Root system-Python
check found aiohttp available and all four owned Core/Inspector/gateway/tunnel
units active. Process health does not prove usable chat.

## Executed checks and remaining qualification

| Candidate / archive | Actual Pi result |
| --- | --- |
| `6c7be1fd5ea285020528177c3dacbc475970df2a`, v36 | 10 failed, 115 passed, 7 skipped; strict specs/plan passed. |
| `c6b8675fda00a972ac42b767cec90e2b0be00798`, v37 | Source compilation stopped at a displaced child-authorization method body; tests did not run. |
| `d40390c2b2c90c86114c9754477aa64f6d7025bc`, v38 | Source compilation and strict specs/plan passed; test collection stopped at a malformed fixture `try` block. |
| `def9b1777b66b7fe42f1a3e9b3f668c1e6167a5b`, v39 | Source/tools/tests compilation and strict specs/plan passed; Root suite 24 failed, 234 passed, 5 errors. Root execution exercised cases previously skipped under admin. |
| `2dbdacc05538f9a48fbb693982db498558e2973d`, v40 | Source/tools/tests compilation and strict specs/plan passed. Specification validation only; runtime tests were not repeated. |
| `840343f7a4b762d61b5fad44af90fe1aa50babb3`, v41 | Compilation and strict specs/plan passed. Root effect subset 9 failed, 100 passed; generated guards actually ran as admin in isolated mount namespaces. |
| `07c8539628a10c7855101e2977f937c03b47f9a3`, v42 | Source/tools/tests compilation and strict specs/plan passed. Specification validation only. |
| `bf3fdfd98ae3ed3aebae2de9adaaff880b82dad7`, v44 | Combined code/effect qualification running; do not treat its result as passed. Archive SHA-256 `e4ce6b9f6c8ad0afc2e5f9c0c80ed69e896449e47f9376bca5f406eacdfc56d6`. |

Logs and status JSON are under
`/var/tmp/hermes-jarvis-core-checks-20261011/` on the identified Pi. OpenSpec
reported `spec-driven`, `ready`, eight total/zero complete/eight remaining;
no archive or canonical runtime acceptance was performed.

Concrete production corrections include plan/review response verification,
the closed review RPC, preservation of composed owner skill edits during
helper replacement, and restoration of displaced activity recording. Fixture
corrections retain production checks: native UID/GID1000, valid opaque handles,
complete registry state, actual socket context management and required CLI
backup identity. The initial-primary lane now has actual append/readback and
separate offline rollback contracts. The startup observer is Root-CLI-owned on
a fixed separate lifecycle-only socket rather than an inaccessible global in
another process. These source corrections still require actual Pi update,
provider completion, protected public chat and recovery evidence.

## Full-shell visual review and disposition

Root inspected the actual Pi Chromium contact sheet for candidate
`5fad47196b3e7851e727f36f469beb25858e4219`: Overview, Chats, Projects,
Second Brain, Models, Profiles, Extensions, Calendar and Agent settings at
phone390x844, tablet768x1024 and desktop1440x900. It displays captured JPEGs
from the same controlled run without editing their pixels. Contact SHA-256:
`4fedd2f05cd00b49a74ad68e291afd5ed1edc951b7832d9b43a058b085ccaaad`.
Report SHA-256:
`28fec1aaea94bf738989b528c35a8dda0a3d1e1ae486fd8e45ba480802055661`.
Both are in `affected-flows-parallelcohort35-v19/` on the Pi.

| Review item | Observed result / follow-up |
| --- | --- |
| Placement, purpose and hierarchy | Overview uses the dedicated Jarvis circular presence view; five primary destinations are visible. Secondary resource/control destinations still need the roadmap's usability consolidation. |
| Desktop/tablet/phone reflow | All nine captured views were inspected. No general horizontal overflow was visible in the contact sheet. Small text and lower-fold content need focused full-resolution review. |
| Phone Chat primary journey | Blocking issue: the history pane filled the first Chat viewport, hiding the conversation/composer. Source `78a3a98b18b2e5b093ea042909fb46e01db1f084` makes first entry thread-first and gives history a labeled toggle. Post-fix rendered interaction remains under qualification. |
| Navigation interaction | v20 failed because its fixture expected the obsolete Manage menu. v21 reached the correct destinations but sampled ARIA before the native details MutationObserver update. v22 waits for both native open state and ARIA, retaining selection/close checks; its Pi run is pending. |
| Keyboard/touch, reduced motion and changing service states | Prior controlled probes cover bounded cases; complete focused visual and physical device verification remains pending. Still captures alone do not prove animation or audio. |
| Destructive actions and knowledge retention | Live save/delete/restore and Obsidian preservation were not exercised by this visual review. |
| Capability and authority claims | Synthetic fixture status, graphs and counts prove rendering only. Real native provider/resource/Expert/Team/Obsidian/account effects remain separate acceptance. |

Disposition: **partial; deployment gate remains pending**. The first phone
Chat fix needs actual returned-composer/drawer captures and interaction results.
New Mission review behavior also needs its focused rendered journey. No
provider, microphone, external messaging, account enrollment or production
mutation occurs in the UI fixture runs. Android/voice/communications research,
all14-image intake and every prior direct request remain in the one current
roadmap; neither this review nor the MVP repair closes that backlog.
