# Jarvis profile and full Resources bundle native probe

Evidence for `RB-T205.1`, `RB-T205.2`, and `VD-T205.3` in the Jarvis sole-user-profile v205 contract. This is a non-root fixture observation, not an acceptance record; all AC01–AC18 remain open.

## Exact pinned candidate: primary Jarvis profile

Against installer candidate `d319be50534bbbe602b8a2a98e4cc41e8ab895c5`, Hermes source `7085fbf7753266fc4943c55ac04926186bc90005`, and official Hermes Python `3.14.7`, this command passed:

```text
PYTHONPATH=src HERMES_NATIVE_TEST_SOURCE=/private/tmp/hermes-upstream-profile-audit-20261010 HERMES_NATIVE_TEST_PYTHON=/private/tmp/hermes-native-py314/bin/python python3 -m pytest -q -rA tests/contracts/test_native_install_handoff.py::test_primary_jarvis_is_the_only_pinned_default_home_profile
```

Result: `1 passed in 2.61s`. The fixture materialized the pinned `profiles/hermes` source closure into a temporary native home and exercised Hermes `list_profiles()` and `load_soul_md()` through the installer probe. The probe required the native home to expose exactly one profile, `default`; it asserted the returned native key is `default`, the native profile display name is `Jarvis`, and the primary profile identity loaded. The source profile ID remains `hermes`.

This confirms pinned API/default-home behavior and the display label consumed by native profile metadata. It does not show a rendered Hermes Desktop window or a physical Pi installation.

## Complete profile and skill bundle

On the same candidate, pinned source, and Python runtime, the test `tests/contracts/test_native_install_handoff.py::test_complete_vendored_profiles_and_skills_load_through_pinned_hermes_apis` passed in `282.77s` when run as a single-owner audit. It checked all 208 vendored profile IDs through pinned Hermes profile/identity APIs and all 396 skill IDs through `skills_list()` and individual `skill_view()` calls, including nonempty content and digest collection.

Earlier overlapping full-bundle attempts reached the native probe timeout: one local integrated run reported `9 passed, 1 failed` in `312.45s` with the bundle subprocess exceeding its 300-second bound; the parent reported another timeout in `314.33s`. The later single-owner run passed without changing the timeout or skipping API calls. Overlap is observed and is a plausible explanation for the timing difference, but no profiler established it as the cause.

## Limits

No Hermes Desktop window was rendered or manually inspected. No Pi, privileged installation, protected enrollment, delegate launch, model inference, provider/account operation, or production acceptance was observed. This evidence does not close `RB-T205.1`, `RB-T205.2`, `VD-T205.3`, or AC16.

Machine-readable observation: [EV-RB02-JARVIS-D319BE5](../../evidence/development/EV-RB02-native-jarvis-profile-d319be5.json).
