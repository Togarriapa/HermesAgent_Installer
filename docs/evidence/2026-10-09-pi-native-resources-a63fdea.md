# Raspberry Pi native Resources and wheel evidence

Observed on 2026-10-09 16:59 UTC against installer commit `a63fdea0b2fe673e136385b4d552b34d449aaac3` on Pi `PI-HERMES`, UID 1000, in isolated test tree:

`/home/admin/HermesInstaller/data/devtest-luna-resource-wire-51d3883/native-resources-8b806b49`

No global Hermes profile, service, account, or Cloudflare state was changed.

## Offline wheel and source validation

Commands:

- `python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir <isolated>/wheel-test-a63 .`
- `python3 -m pip install --no-deps --no-index --target <isolated>/wheel-install-a63 <wheel>`
- Import `load_bundled_source()` and `NativeRegistry.from_verified_source()` from the installed wheel, then call `discover(["profiles/ai-developer"])` and `materialize()`.

Results:

- Wheel built: `hermes_agent_installer-0.1.0-py3-none-any.whl`, 433,379 bytes, SHA-256 `917dc9906711df829a3b28d725389d89a693b9ab0599d272e6ea3a3d223c442e`.
- Offline installed-wheel loader verified all 739 pinned source files, including archive size and digest.
- Full catalog discovery returned 692 declarations: 208 profiles, 396 skills, 18 plugins, 3 MCPs, 55 bundles, 5 channels, 4 crons, and 3 webhooks.
- Selected `ai-developer` resolution contained 11 resources; materialization returned 29 generation artifacts and 10 native targets. Its selected Hermes skill root contained exactly the four resolved `SKILL.md` files.

## Native Hermes discovery probe

The selected generation was materialized into the isolated test tree with the crosswalk's target paths, then inspected with the pinned Hermes source `7085fbf7753266fc4943c55ac04926186bc90005` using its managed Python 3.14.7 environment. The official `hermes_cli.profiles` APIs reported `profile_exists("ai-developer") == True` and included it in `list_profile_names()`; `get_profile_dir("ai-developer")` resolved to the generated `HERMES_HOME/profiles/ai-developer`. The official `agent.skill_utils.get_all_skills_dirs()` returned the isolated `HERMES_HOME/skills` root, and `iter_skill_index_files(..., "SKILL.md")` found exactly:

- `ai-application-engineering`
- `automated-testing`
- `machine-learning-workflow`
- `secure-application-development`

This establishes package loading, named profile discovery, and selected skill file discovery for this profile on the pinned Pi runtime. It does not establish profile invocation, model routing, plugin/MCP dispatch, account readiness, or production enablement; those remain pending their guarded adapters and target checks.

## Contract tests and CI

On the same Pi checkout and exact commit:

`PYTHONPATH=src python3 -m unittest discover -s tests/contracts -p 'test_registry_*.py'`

Result: 22 tests, 22.720 seconds, exit 0.

GitHub Actions for `a63fdea0b2fe673e136385b4d552b34d449aaac3` completed successfully:

- Planning integrity and OpenSpec: run 37962716100.
- Remote security fixtures: run 37962716108.

This is implementation evidence for resources-bundle-native-enrichment RB-T02 and resource-registry-import RG-F03. It does not mark any OpenSpec runtime acceptance task complete.
