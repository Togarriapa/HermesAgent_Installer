# Pi source qualification and partial UI/UX review

Change: `jarvis-core-platform`; R0090/R0200/R0201/R0203;
HI-T266.2/RT-T266.3/VD-T266.5. Review date: 2026-10-12, Europe/Lisbon.
Reviewer: Root, with Luna implementation and probe review.

This is source/fixture qualification, not production or native runtime acceptance.
The production source remains `dabdc491610742387a4d8afecd1a295bb41c5bcd`.
No Cloudflare, account, production unit, Core, vault, or provider setting changed.
All original requirement and target acceptance groups remain open.

## Candidates and executed checks

- Candidate `8acc837e095022c420b8f075706e6ef841016a48`, archive
  `core-source-native-adoption-query-v3.tar.gz`, SHA-256
  `0acf32953c5f1008d4aa5b64b0a9b085ebd28ce9bc5df2062f023c0f9a30969b`:
  22 focused tests passed in 0.28 seconds; broader cohort 421 passed,
  11 skipped, 23 warnings in 55.34 seconds. Composed/feature JavaScript syntax,
  current OpenSpec validation and planning coverage passed. Exact-source v14
  phone/tablet/desktop fixture render report passed.
- Candidate `2239551914bd391376885833befa746402b7f9b4` adds only the note
  metadata wrapping fix. Archive `core-source-native-adoption-query-v4.tar.gz`,
  SHA-256 `553a0ccad7cd4f82da05945dc6747113f5829e03763bd6ea5cf1d7c9c085ce20`:
  38 focused adoption/client/Second Brain tests passed in 0.65 seconds;
  current OpenSpec status/instructions and specs/plan validation passed.
  The prior broader cohort was not repeated for this two-line CSS change.
- All execution used the Pi browser remote shell as non-root `admin`, the
  isolated Python 3.14.7 test environment, pinned Node 24.6.0 ARM64 and native
  sandboxed `/usr/bin/chromium`. There was no local test, fixture, preview,
  server, npm, OpenSpec or Python execution.

The effect regression calls the production feature API: only validated
Second Brain GET list/search queries reach the request function; invalid,
duplicate, malformed or unrelated query routes never dispatch. Adoption fixtures
exercise ingress ordering and failure recovery, including retention of the
successful protected rollback snapshot. They do not establish privileged Pi
adoption, observer peer protocol, native tool registration or vault effects.

## Rendered affected-flow evidence

Pi directory: `/var/tmp/hermes-jarvis-core-checks-20261011/`.
Probe: `probe_jarvis_affected_flows_v15.py`, SHA-256
`4cc2bcf1ac0835aa1637d5cf2e78c8bf17870db776c78058dc960cde39b26f01`.
Report: `affected-flows-adoptionquery4-v15/responsive-fixture-report.json`,
SHA-256 `7705d14e3435e9fd8aac7ae76243491c46d4c76ba94ee7051182eeb02e4bd074`.
Result: pass; no failed checks. The report binds served asset bytes and captures
to the exact isolated v4 source, not the production service.

The `/chat` shell was exercised at phone 390x844, tablet 768x1024 and desktop
1440x900, opening Overview, Chat, Projects, Second Brain, Models, Profiles and
Extensions. Synthetic reads, note/project selection, local graph filtering,
keyboard traversal and cancellation of the project trash confirmation were
used. No chat/model request, microphone, save, delete, restore or extension
mutation was performed. Empty/unavailable settings are fixture states.

Second Brain selected-note JPEG captures (direct Chromium capture, quality 55):

| Viewport | Filename under the report directory | SHA-256 |
| --- | --- | --- |
| Phone | `phone-390x844-second-brain-fixture.jpg` | `6a69a75e5f1f102f3ba2bf133ae9838dd77f6f649d2e19865461bd481506b864` |
| Tablet | `tablet-768x1024-second-brain-fixture.jpg` | `ccd57047b138b369aeef3bdcc6fb114f2130cfac4b4f078ea2498efaf5e2cd17` |
| Desktop | `desktop-1440x900-second-brain-fixture.jpg` | `fd9662860cbe2fb1fa5c3198554a845edb408cd685e6d1310912d250bad8bc13` |

The focused render check requires the complete deterministic 64-character
fingerprint and measures text fragments, reader bounds, scroll/clipping
ancestors and viewport boundaries. All three viewports opened the note and
passed this assertion without horizontal clipping. This is rendered geometry
evidence; it is not a substitute for the complete human usability review.

## Partial review findings and disposition

Root inspected complete Pi JPEG pixels for the phone Overview (prior unchanged
style) and the repaired-query phone Second Brain before the wrapping fix.
The note/search/navigation controls were readable; the long fingerprint was
clipped. That finding caused the v4 wrapping fix and the stronger v15 probe.
An incomplete image transfer was discarded and was not used as evidence.

| Review item | Status | Remaining evidence |
| --- | --- | --- |
| Phone note discovery/read and labels | observed in prior fixture capture | Complete post-fix pixel review remains |
| Full fingerprint wrapping | observed rendered geometry | v15 passes on all three viewports; post-fix pixel review remains |
| Full shell placement and duplicate navigation | not reviewed completely | Review each relevant rendered flow on all surfaces |
| Tablet/desktop visual hierarchy | not reviewed | Inspect actual captured pixels and interactions |
| Keyboard, touch and reduced motion | partial fixture checks | Physical/device and full focus/reduced-motion usability review |
| Loading/error/recovery and consequential actions | partial fixture checks | Live/native effects, recovery and permissions remain |
| Chat/project deletion retaining learned Obsidian knowledge | not reviewed live | Exact native preservation witness required |
| Runtime/resource/provider capability claims | not established | Observer protocol, native registration and actual effects required |

Disposition: **partial; deployment gate remains pending**. The render result
does not clear the complete UI/UX or native adoption gate. Preserve the current
working service until those witnesses are complete. The trusted-device addition
is a specification task only; no session duration or device-trust setting was
applied by this work.
