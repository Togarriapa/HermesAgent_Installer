# Native Resources profile and skill handoff

`NativeRegistry.materialize()` stages profile identity and skill documents in the verified generation. The lifecycle owner remains responsible for ownership-safe writes, overlay preservation, recovery, and activation. For a generation resolved to one profile and its dependency closure, call `selected_profile_materialization(generation, profile_id)` and pass the returned mapping to `GenerationLifecycle.materialize()`. This maps source skills into Hermes' actual named-profile `profiles/<id>/skills/` directory and leaves other profile roots and installer records in the generation. Retain the lifecycle result's installed/updated/preserved paths as the conflict receipt. Then call `discover_and_load_selected()` with the exact pinned Hermes source checkout, official PM-managed Python 3.14 executable, Hermes root, selected profile ID, and the skills selected for that workflow.

The handoff runs a separate, bounded Python process with a sanitized environment. It requires Python 3.14 and verifies Hermes revision `7085fbf7753266fc4943c55ac04926186bc90005`, calls the pinned `hermes_cli.profiles.list_profiles()` API, loads the profile `SOUL.md` through Hermes' `agent.prompt_builder.load_soul_md()`, discovers skills through `tools.skills_tool.skills_list()`, and loads each selected skill through `tools.skills_tool.skill_view()`. It makes no model call and does not change account state. Generated skill documents must not declare package-manager dependencies; the handoff rejects dependency installation notes.

The native fixture layout is:

```text
<HERMES_HOME>/profiles/<profile-id>/
  profile.yaml or another Hermes profile identity file
  SOUL.md
  skills/<skill-id>/SKILL.md
```

That profile-local `skills/` location follows Hermes' profile boundary: each profile owns its skills and configuration. The generation crosswalk contains generation-relative paths; the profile-scoped mapping helper binds them to Hermes' selected profile home rather than treating a receipt as proof that files were installed. `NativeInstallReceipt` records discovery, actual identity/skill content loading, and SHA-256 digests separately from account authentication, capability function, enablement, and target verification.

The opt-in contract test runs against a locally prepared pinned checkout and isolated Python 3.14 runtime:

```sh
HERMES_NATIVE_TEST_SOURCE=/path/to/hermes-agent \
HERMES_NATIVE_TEST_PYTHON=/path/to/official-pm/python \
python -m pytest tests/contracts/test_native_install_handoff.py
```

The same test materializes the complete vendored snapshot and, through real Hermes APIs, lists and loads all 208 profile identities and all 396 skill cards. It also checks every profile's Hermes-visible display alias against its canonical resource ID. Each selected named-profile installation still uses its own profile-local dependency closure through `selected_profile_materialization()` and `discover_and_load_selected()`.

The pinned profile and skill declarations contain no explicit `source`, `repository`, `references`, `assets`, `hooks`, `scripts`, `external`, or `enrichment` fields. The native cards retain each declaration's complete effective spec and its procedure/instruction fields; there are no declared external helper trees to fabricate or attach for these 604 items. Other resource kinds and component adapters have separate full-content/effect obligations.

On this development host, the actual API probe ran under Python 3.14.7 in a disposable venv against the exact pinned Hermes checkout. It discovered `native-fixture`, loaded its SOUL identity, discovered `selected-fixture`, and loaded its SKILL.md; no model was called. The full-bundle audit uses the same interpreter against all 208/396 fixture artifacts. This is source/API fixture evidence; the venv is not Hermes PM-managed, and there is no Linux ARM64 target, account, functional external effect, or production acceptance in this result.
