# PI-HERMES native provider dispatch evidence

Date: 2026-10-09 (UTC)
Installer candidate: `b515d3350bdf51bdec850528911407674b6d21a3`
Hermes source pin: `7085fbf7753266fc4943c55ac04926186bc90005`
Target: enrolled Raspberry Pi 5, Debian 13.6 (Trixie), ARM64; 16 GiB RAM. The Pi was supplied and authorized for deployment/testing by the user. This probe did not mutate unrelated services, reuse the default Hermes profile, or enable a persistent service.

## Runtime contract suite

Command, from `/tmp/hermes-installer-dev` at the exact candidate above:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests/contracts -v
```

Result: exit 0; 95 tests passed in 10.791 seconds. The terminal showed the exact repository HEAD as `b515d3350bdf51bdec850528911407674b6d21a3` immediately before the run. This is native ARM64 contract-fixture evidence, not acceptance of every target component.

## Native Hermes route probe

Command, from the same checkout:

```sh
PYTHONPATH=src python3 tests/native/test_hermes_provider_dispatch.py \
  --hermes-source=/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532 \
  --installer-data-root=/home/admin/HermesInstaller/data
```

Observed exact candidate: `b515d3350bdf51bdec850528911407674b6d21a3`.
Observed run: 2026-10-09 13:32:57Z–13:33:04Z, exit 0; `Ran 1 test`, `OK`.

The harness verified the selected Hermes Git HEAD, installer-owned source/data roots, and committed PM venv at `data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv`. The worker ran Python 3.14.7 from PM toolchain `python-3.14.7+20260901-linux-arm64`; it imported the PM-managed core dependencies including `ruamel.yaml` and OpenAI SDK 2.24.0. It created a disposable installer-owned profile and native provider plugin, resolved the provider/model from that profile's real Hermes configuration, and sent the actual primary SDK call plus the `title_generation` auxiliary call through the local loopback gateway. A recording transport supplied synthetic responses. The recorded fixture made exactly two requests on `openrouter-nemotron-free`, for the pinned Nemotron model, with the expected primary and auxiliary prompts. The disposable profile and gateway were cleaned up by the harness.

The synthetic transport is not OpenRouter, and no provider credential or account was used. This result establishes the tested native configuration and primary/auxiliary request path only. It does **not** establish a complete AIAgent tool turn, private-data provenance, native network isolation, zero-cost account-level plugin policy, live provider eligibility, graphical Desktop sandbox, service activation, Cloudflare setup, or public readiness.

## Failed attempt and correction

An earlier native attempt at `56e458487bbad7d8c7a3452760154bb232b17a69` failed because the harness constructed `AIAgent` with empty provider/model fields even though the profile config contained the managed selection. The implementation then used pinned `resolve_runtime_provider(requested=None)` and passed its config-derived provider/model to the harness. Only the later exact-candidate rerun above passed; the failed attempt is not acceptance evidence.

The account eligibility guard added at `b515d3350bdf51bdec850528911407674b6d21a3` remains default-deny. Synthetic eligibility objects in contract fixtures are test-only. No API currently verified for this account exposes enough effective plugin-default policy to lift the live guard.


## Current native tool-cycle and provider cohort (2026-10-09)

Target identity was read-only verified as PI-HERMES, Raspberry Pi 5, aarch64, Debian GNU/Linux 13.6 (Trixie). No unrelated service, default Hermes profile, live provider account, external provider endpoint, Cloudflare resource, or public route was changed or used by this probe.

Exact candidate: `0d510b7d4b34b601e7f84ba937ec71b9268fefe6`. Hermes source: `7085fbf7753266fc4943c55ac04926186bc90005`. The selected committed PM environment was `/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv`; worker Python was 3.14.7 from the pinned PM toolchain `python-3.14.7+20260901-linux-arm64`.

Native test command from `/tmp/hermes-installer-dev`:

```sh
HERMES_AGENT_SOURCE_ROOT=/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532 HERMES_INSTALLER_DATA_ROOT=/home/admin/HermesInstaller/data PYTHONPATH=src python3 -m unittest tests.native.test_hermes_provider_dispatch -v
```

Observed exact candidate and run: 2026-10-09 14:13:35Z–14:13:43Z, exit 0; one native test passed. The test output recorded `NATIVE_PROVIDER_PROBE_RESULT`: native `AIAgent.run_conversation` invoked the pinned deferred-tool stages `tool_search`, `tool_describe`, and `tool_call`, then completed a final response. The real fixture plugin handler wrote a one-byte append marker exactly once. The complete probe made six gateway requests, all on `synthetic-private-fixture`: four requests for the AIAgent tool turn, then the native primary SDK call and `title_generation` auxiliary call. A synthetic private canary remained in the tool result and was not sent to any public route. The upstream is an in-process recording transport only.

Contract command at the same exact candidate:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests/contracts -v
```

Observed exact candidate and run: 2026-10-09 14:14:35Z–14:14:46Z, exit 0; 97 tests passed in 10.787 seconds.

These results establish the tested native configuration, PM environment, ordinary AIAgent executor/tool-handler cycle, and primary/auxiliary loopback route against a synthetic PRIVATE fixture. They do not establish actual network egress confinement, trusted PUBLIC/private provenance isolation, live provider/account eligibility, zero-charge account-level plugin policy, Desktop/renderer sandbox or GUI readiness, managed service activation, Cloudflare setup, Xpra window containment, or public readiness. Production OpenRouter eligibility remains default-deny because no authoritative effective account plugin-policy proof has been supplied.

### Failed candidate attempts retained

- Candidate `93fe5151353682d07b72f5532774ad93daae013c` reached the five-turn AIAgent budget before the final response because the fake transport repeated `tool_search`; the fixture was updated to follow the actual pinned search/describe/call schemas.
- Candidate `1c0b5104c07467bc0803c56d51a6fd3b320418cb` failed because a generated fixture-plugin source string contained an unterminated literal. The marker fixture was corrected to append a single byte, then the exact `0d510b7` rerun above passed. The earlier failures are not acceptance evidence. Exact timestamps were not captured for these intermediate failed runs.
