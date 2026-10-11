# UI/UX review checkpoint: command and model context

This fresh revision is triggered by the Overview rejected-send repair and conversation-model context/reset changes. It covers source candidate `25a994e80109354f9bbae125a31eb28670c84a11`, change `jarvis-core-platform`, R0203, RT-T266.3 and VD-T266.5. It is **partial, with deployment review still open**. The prior e88 record remains historical and does not qualify this changed candidate.

## Candidate, target and review scope

- Reviewer: Root, with Luna implementation and source review; 2026-10-12, Europe/Lisbon.
- Exact source archive: `core-source-native-owner-queue-fix-v3.tar.gz`.
- Archive SHA-256: `6dfcf1afbd3a6011ebe900d33b10ba6501bcf07826b4a9c0426796c4ffca0fcf`.
- Pi source: `/var/tmp/hermes-jarvis-core-checks-20261011/native-ownerqueue3-source/`.
- Changed paths: `src/hermes_installer/remote/jarvis_chat_assets.py`, `src/hermes_installer/remote/jarvis_models_assets.py` and their contract/effect tests.
- Scope: Overview → Chat send/error/retry; Chat → Models conversation context; general Models navigation; reused-root Models loading/error/unavailable states. These cross-view input/state changes also require the full-shell review carried forward from e88, including Projects, Obsidian, Profiles and Extensions.
- All execution uses the identified Pi browser terminal. Local source/Git review does not count as runtime or rendered UX evidence.

## Current findings and evidence

Source review identified and repaired three user-visible problems: rejected sends could clear the Overview draft; the Chat model link lost its current conversation; reopening Models could show stale choices/settings. The current source propagates queue failure, clears the Overview draft only after an accepted queue result, passes finite Models context only for the chat link, checks membership in the owner-returned list, and resets controls/settings before loading. These are source findings, pending actual affected-flow interaction review.

The focused Pi effects test must exercise rejected versus queued sends while preserving a separate Chat draft and message model/effort. The Models effect test must exercise owner-listed current context, absent/malformed/no context, no automatic POST, and clearing a reused root before its first asynchronous response. These finite harness effects do not prove production-native effects or physical phone input.

The Pi verified the archive hash. All **three focused effects/bridge regressions passed in 0.29 seconds** (`candidate-ownerqueue3-focused.log`). The selected cohort reported **419 passed, one failed, 11 skipped**, 23 warnings in 54.96 seconds. Its only failure split the prior two-argument `showView` signature; the new context argument requires the navigation contract update. Specification/current-scope validation and composed, feature-loader and all three feature-chunk JavaScript syntax checks passed. The failures and skipped roles remain separate from runtime acceptance.

Test-only successor `dd3e9d196f711524e06f63c1885383e655c7f0c6` updates that finite-route/navigation-context contract. `git diff --exit-code 25a994e80109354f9bbae125a31eb28670c84a11 dd3e9d196f711524e06f63c1885383e655c7f0c6 -- src` verified identical runtime source. Its archive is `core-source-native-owner-queue-fix-v4.tar.gz`, SHA-256 `afc5d56f4f2e82a9b90aaba5cd66583310fc9024b2e9cc648ace82865d8eccb2`, with Pi extraction `native-ownerqueue4-source`. Readback on 2026-10-11 at 23:31 UTC confirmed **four focused checks passed in 0.26 seconds** and the selected 48-module/planning cohort reported **420 passed, 11 skipped**, 23 warnings in 53.91 seconds. Composed, feature-loader and all three feature-chunk JavaScript syntax checks passed. Logs are `candidate-ownerqueue4-{focused,tests,run,specs,plan}.log`. The skipped checks include root-role fixtures; they are not privileged/native-effect proof. This test-only correction adds no new visible behavior and does not replace the open rendered/interaction review.

Strict responsive probe v12 (`21439a50bc01ccbe7504b07258c530faaf21c482d85d04e35abb7f1440d19333`) reported `result=pass`, `failed_checks=[]`, and no failures for phone, tablet or desktop. It captured Overview/Chat at phone 390×844, tablet 768×1024 and desktop 1440×900 using synthetic account data, sandboxed Pi Chromium, no model/microphone/mutation effects, and denial of unexpected routes. Evidence directory: `/var/tmp/hermes-jarvis-core-checks-20261011/responsive-ownerqueue3-v12/`; the report is `responsive-fixture-report.json` and six captures are `<device>-<width>x<height>-<overview|chat>-fixture.png`. This is controlled-render evidence, not a completed visual/interaction review.

The exact dd3 successor was also rendered by that strict probe in `responsive-ownerqueue4-v12/`, with the same three actual viewport sizes and six captures. Its report again returned `result=pass`, `failed_checks=[]`, and no failed viewport checks. Root read that report outcome through the Pi terminal. Captured pixels and rendered settings/error interactions have not yet received the full visual review; the automated probe cannot clear that item.

| Review item | Status | Remaining actual review |
| --- | --- | --- |
| Naming, placement, navigation and duplicate destinations | Not reviewed on this candidate | Traverse Overview/Chat/Models and the full shell; inspect reachable entry/exit and scope labels. |
| Phone/tablet/desktop layout and touch targets | Not reviewed on this candidate | Review current captured pixels and affected settings states; physical mobile input is separate. |
| Keyboard/focus and native phone text entry | Not reviewed | Exercise actual rendered controls and error/retry focus; the finite Node harness is insufficient. |
| Motion, hidden/offline and reduced motion | Not reviewed on this candidate | Attach the strict probe result and inspect current rendered state transitions. |
| Loading/error/unavailable/reset states | Source issues repaired; interaction review pending | Confirm preserved drafts, owner context and fresh disabled controls in the rendered flow. |
| Permission, destructive recovery and Obsidian retention | Full-shell review pending | Inspect unchanged but still unqualified Projects/Obsidian/Profiles/Extensions flows; no retention acceptance is inferred. |
| Capability/API claims and native effects | Pending | Keep fixture, observed native readback and production acceptance distinct. |

## Disposition

Review remains open. Source and fixture checks alone do not clear deployment. Actual rendered affected-flow review, the inherited full-shell review, selected-owner native effects and exact-target qualification remain required. Current production remains the earlier `dabdc491610742387a4d8afecd1a295bb41c5bcd`; this candidate has not been deployed. All 219 requirements and eight broad acceptance groups remain open.
