# Reviewed source members and boundary joins v180

## Scope and review boundary

One batched Sol refinement of BD-F03, RG-F02/03, HI02/HI-T02/HI-T08/09/11/12, HI-T154/161/172/177/178/179 and SK-T132.2/SK-T147/SK-T152/SK-T161.2/SK-T168.1/SK-T176.1. Frozen160-file baseline/tag remain unchanged. All AC01..AC18 remain OPEN. No fixture custody cycle expansion: HI-T178.2/HI-T179.2 remain OPEN as recorded in v179. No Pi/account mutation, runtime acceptance, canonical runtime sync/archive or ref publication is authorized by this source review.

Exact read-only reference3a349c72b3375fded7cc73629403e2c514039455/tree0d659151a41788cc9fa5c64e2c67a313c1edcc05 was cloned to an owned Sol checkout; source hashes below recomputed from committed files. Rescue-only measurements are superseded for these exact merged members. Source/implementation tests do not prove installed membership, actor import, loaded worker/PIDFD or target behavior. v179 preserves the full42 registrations/61 backend actions/2 workflows/18 obligations; four selected local source operations and38 pending registrations do not close full runtime compliance.

## Exact source and installed member mapping

```json
[
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/bootstrap_runtime_factory.py",
    "module_name": "hermes_installer.authority.bootstrap_runtime_factory",
    "source_artifact_id": "installer-reviewed-source-bootstrap-runtime-factory-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.bootstrap_runtime_factory",
    "installed_member": "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py",
    "sha256": "1156ea17992ddfd0b04819dc5afbc9426611cc2a745ebfb61800df86b08a0c14",
    "size_bytes": 579669,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/local_resource_effects.py",
    "module_name": "hermes_installer.authority.local_resource_effects",
    "source_artifact_id": "installer-reviewed-source-local-resource-effects-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.local_resource_effects",
    "installed_member": "lib/python/hermes_installer/authority/local_resource_effects.py",
    "sha256": "d79fa4c8693e4f6588cd351d51089e45173a437311d15a6dfae16e7e90178fb6",
    "size_bytes": 47854,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_assembler.py",
    "module_name": "hermes_installer.authority.native_assembler",
    "source_artifact_id": "installer-reviewed-source-native-assembler-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_assembler",
    "installed_member": "lib/python/hermes_installer/authority/native_assembler.py",
    "sha256": "311e07fb52ae001e44d4be17cf4ed8a09277118e0aca34b6ff45c22b9b6e2055",
    "size_bytes": 21265,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_output_receipts.py",
    "module_name": "hermes_installer.authority.native_output_receipts",
    "source_artifact_id": "installer-reviewed-source-native-output-receipts-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_output_receipts",
    "installed_member": "lib/python/hermes_installer/authority/native_output_receipts.py",
    "sha256": "37f18a0d9c2e7082955f82bb27221dae3ae4781c6278b5e0c1a254233fbf7b5f",
    "size_bytes": 109864,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_policy_preparation.py",
    "module_name": "hermes_installer.authority.native_policy_preparation",
    "source_artifact_id": "installer-reviewed-source-native-policy-preparation-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_policy_preparation",
    "installed_member": "lib/python/hermes_installer/authority/native_policy_preparation.py",
    "sha256": "93695570e20218ea1e40a0707ef7d6f51e1646e74e5c5338ba1fd83fef737752",
    "size_bytes": 60196,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_registration_projection.py",
    "module_name": "hermes_installer.authority.native_registration_projection",
    "source_artifact_id": "installer-reviewed-source-native-registration-projection-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_registration_projection",
    "installed_member": "lib/python/hermes_installer/authority/native_registration_projection.py",
    "sha256": "7afa35250c9cd82f34030d37a74b6c310f25fde88d2169cf30913eafcbcf266b",
    "size_bytes": 82047,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_source_definitions.py",
    "module_name": "hermes_installer.authority.native_source_definitions",
    "source_artifact_id": "installer-native-source-definitions-module-v137",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_source_definitions",
    "installed_member": "lib/python/hermes_installer/authority/native_source_definitions.py",
    "sha256": "745aa6492235b54205ffeec01f9672d1663602780413757dafc27c2de4e22e2c",
    "size_bytes": 23672,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/native_definition_composition.py",
    "module_name": "hermes_installer.authority.native_definition_composition",
    "source_artifact_id": "installer-reviewed-source-native-definition-composition-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.native_definition_composition",
    "installed_member": "lib/python/hermes_installer/authority/native_definition_composition.py",
    "sha256": "a60e3b2dadb8e1733767035209f988c2fcbb9feb0ff15e5fd0539da9877d16aa",
    "size_bytes": 8355,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/application_runtime_archive.py",
    "module_name": "hermes_installer.authority.application_runtime_archive",
    "source_artifact_id": "installer-reviewed-source-application-runtime-archive-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.application_runtime_archive",
    "installed_member": "lib/python/hermes_installer/authority/application_runtime_archive.py",
    "sha256": "3117c4c706bfcffe6626c57c79934b143c36d8cd75758dd1198c2020286c2197",
    "size_bytes": 31457,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/application_runtime_relocation.py",
    "module_name": "hermes_installer.authority.application_runtime_relocation",
    "source_artifact_id": "installer-reviewed-source-application-runtime-relocation-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.application_runtime_relocation",
    "installed_member": "lib/python/hermes_installer/authority/application_runtime_relocation.py",
    "sha256": "9b426e61480613c9e10aeaa4227aaff6d06a5558000b45cb94fb0d0160e47afc",
    "size_bytes": 12120,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  },
  {
    "source_commit": "3a349c72b3375fded7cc73629403e2c514039455",
    "source_path": "src/hermes_installer/authority/remote_observations.py",
    "module_name": "hermes_installer.authority.remote_observations",
    "source_artifact_id": "installer-reviewed-source-remote-observations-v180",
    "installed_artifact_id": "installer-module:hermes_installer.authority.remote_observations",
    "installed_member": "lib/python/hermes_installer/authority/remote_observations.py",
    "sha256": "b6e602fc03996fcd00da4ba43d394e377feea1706d2b7d08691c587754a9ec31",
    "size_bytes": 93746,
    "roles": [
      "module"
    ],
    "installed_mode": 292,
    "state": "reviewed exact committed source only; held import and loaded runtime evidence separate"
  }
]
```

Raw source acquisition identity and installed module identity are distinct. For the raw source descriptors, exact URL is `https://raw.githubusercontent.com/Togarriapa/HermesAgent_Installer/<source_commit>/<source_path>` with version=source_commit, filename=source basename, SHA/size/max_bytes equal the row, nonarchive format, no redirect/extra URL permission. Preserve existing stable raw v137 source-definition ID; installed source-definition ID is exactly `installer-module:hermes_installer.authority.native_source_definitions`, never a raw catalog alias or duplicate row for the same installed path.

`native_definition_composition` is a new root-imported module with only a direct relative import of local_resource_effects plus stdlib dataclasses/hashlib/types/typing. Packaging owner adds this exact source->lib/python member, module role0444 and its canonical installed ID to reviewed descriptor/plan allowlist. Root source actor must actually import it, together with the exact finite support closure, before actor/module observation; staging an unimported file does not satisfy RootReleaseModuleReceipt. The eight native compiler support imports are native_assembler, native_registration_projection, components.native_plugins, components.public_registries, native_definition_composition, native_policy_preparation, native_source_definitions and local_resource_effects. The first four existing identities/pins remain unchanged except native_assembler/projection rows in this review. Preserve their actual dependency source closure; no wildcard additional import or module-role sweep. PM/source/materialization receipts and worker source roles remain separate.

Luna pin application must reconcile builder `REVIEWED_SOURCE_MODULES`, verifier exact member/role/hash/size tables, installed plan allowed IDs, actual source/artifact catalog row, factory held source-definition resolver and any exact source observer metadata. In particular the current factory resolver still contains source-definition190c471b.../10311 and current release tableca57637f.../16819; both must use the reviewed745aa649.../23672 bytes. The two unchanged v154 workers native_invocations40,107/78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226 and native_boundary14,356/ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb remain held src source-module0444 members, NOT root-imported modules. Factory worker resolver must require their exact source-module role rather than its stale module filter. LoadedProcessRoleObservation/current native PIDFD proof is still later and independent.

The table records reviewed pre-application bytes. Changing factory/source modules to apply receipt APIs or boundary behavior produces new source bytes: retain measured follow-up SHA/size/source commit as pending source review rather than claiming this table matches changed files. Do not embed a self-referential expected factory hash in factory code. Actual selected SourceCAS/actor closure and external finite descriptor are the verifier's owners for final committed source bytes.

## Standalone application build driver

Initial sourcee5b72b147bc066925ffaf985e20d60c87f0fd52d had a concrete valid-input failure: PYTHON_APPS contains four elements, while _load_input unpacked three. It is NOT approved as a runnable driver. Root-authorized routine correctionc757aec16e2dd14a218adf26989b5f982cb1329f unpacks the fourth source script mapping without changing recipe behavior. Sol fetched its exact committed object, verified the sole three-line source diff and complete valid-input regression for all three Python apps; owner reports27 passed/1 root-Linux skip. Those synthetic decoder fixtures explicitly relax root-owned config custody, proving decoder/validator behavior only. Corrected exact driver source descriptor:

```json
{
  "source_commit": "c757aec16e2dd14a218adf26989b5f982cb1329f",
  "source_path": "src/hermes_installer/authority/application_environment_builder.py",
  "module_name": "hermes_installer.authority.application_environment_builder",
  "source_artifact_id": "installer-application-environment-builder-v1",
  "installed_artifact_id": "installer-application-environment-builder-v1",
  "installed_member": "lib/python/hermes_installer/authority/application_environment_builder.py",
  "sha256": "8c5aebe61ba3d7e5c9bcf27dfadba8771ed3a4987240ea52fe2189251f1b6e8c",
  "size_bytes": 45807,
  "roles": [
    "application-build-driver"
  ],
  "installed_mode": 292,
  "state": "corrected committed source reviewed; source-only descriptor approval, no execution receipt/runtime acceptance"
}
```

The corrected driver commit must be merged before applying its descriptor. Its source SHA/size are independently measured from the committed Git object, not copied from a report.

The standalone driver imports only stdlib (including email.parser/email.policy for wheel metadata), accepts no argv beyond its script, and reads only fixed source/toolchain/packages/backend/python-runtime/uv/work/output mounts. It invokes only held PM Python/uv with isolated/offline/no-index/hash-constrained recipes, verifies unchanged lock/source, and emits bounded archive/result data. It is not a root-imported authority adapter and no source project script may replace it.

Add exact finite release role `application-build-driver` only for artifact `installer-application-environment-builder-v1`, installed member `lib/python/hermes_installer/authority/application_environment_builder.py`, reviewed source bytes/mode0444. This is the single explicit lib/python non-module exception: require exact ID/path/role/hash/size; reject role on any other member, role combination, ambient path, or an imported actor claim for this execution-only driver. Exclude it from module-origin/root import closure and from generic worker role lists. RootInstalledReleaseMemberReceipt proves held membership/read_current, not source import or process execution. Source acquisition raw ID is `installer-application-environment-builder-v1` and source URL exact reviewed commit/path; source->installed placement is explicit, not a same-ID root import alias.

Factory/receipt owner adds facade/private `resolve_installed_application_builder_module()` using current verified release+plan+setup/principal/namespace/controller and exact held read_current membership. Revalidate SHA/size/mode/role/release inode before and after use; return the existing exact RootInstalledReleaseMemberReceipt type. Admission consumes that purpose-bound retained receipt and existing fixed argv `[held PM interpreter, -I, held toolchain/hermes_installer/authority/application_environment_builder.py]`. Actual Python base executable AND complete PM stdlib/native dependency closure are separately held; never copy fixture interpreter bytes into a PM receipt. Root currentness must join source/lock/v152 backend/wheel licenses/toolchains/output FD/one-use grant before unit launch; actual terminal+measured archive+relocation+ABI probe after it. Current v168/v176 pure archive/relocation helpers use exact measured module rows above; uv12.3 generated-format fixture is only measured fixture evidence, not PM/source/install acceptance.

Graphify/Browser Use/ScrapeGraphAI Python profiles remain finite distinct choices. ScrapeGraphAI lacks source console scripts: the reviewed existing entrypoint/probe recipe must remain exact, not an invented script or a claim that module entrypoint is already runnable. Hyperframes Node/Bun is unavailable to this Python driver; require its independently observed Node/Bun/source/packages/build recipe/ABI receipts. All real ARM64 source builds, locks/license applicability/provider/account operations remain pending until measured.

## Selected-window observation source

remote_observations module row above originates at source60cdf50d8698970eb567fe69ee806168f3d2ba82, unchanged at merged3a349c72. v177 observer uses a sealed one-use target, selected private display/Xauthority/actual XRes PID/UID/cgroup/PIDFD/executable/namespace evidence, bounded focus/grab lease and exact F24 press+release observed X events. Native module imports only stdlib including ctypes; runtime additionally requires libX11, libXRes and libXtst/XTest with actual installed native ABI/package/dependency observation. Source pin does not prove Linux/aarch64 libraries, X server extension/keymap, genuine official Desktop window or Access/WebSocket acceptance. Missing or unreviewed native dependency stays unavailable; `find_library`/successful CDLL or injector bool alone is not target evidence.

FFI review confirms explicit pointer-width `ctypes.c_void_p` Display arguments, XID/Time/KeySym c_ulong, KeyCode c_uint/c_ubyte, declared XTestQueryExtension/XTestFakeKeyEvent/Xlib focus/grab/event prototypes and XEvent24-long storage. Maintain exact LP64/native-ABI validation; test fixture must set its own XOpenDisplay/XRes prototypes, never truncate pointers or change production code to accommodate a fixture. Any production observer edit from FFI diagnosis gets a new measured source review. Real F24 success needs independent same-window press/release/focus restored receipt; partial/error/focus switch or missing observer event remains failed/unavailable, with truthful cleanup evidence. Current separate fixture FFI correction, if test-only, changes no source pin.

## Separate owner-overlay publication and invocation

v172 exact32-field owner_overlay_operation_records and four fixed source methods remain separate from61 backend PluginActionSchema actions/2 workflows. Extend RootNativeAssemblyDefinitions by exactly one field `owner_overlay_operation_records: tuple[Mapping[str,Any],...]`, making21 public producer fields plus private seal; resolve from genuine retained RootOwnerProfileOverlayEffects operation bundle. Include its exact canonical rows and source/view/schema/target/effect receipt bindings in definitions_sha256 and native resolver bytes; preserve registration/source/candidate coverage separately. No backend action row, synthetic adapter effect or omitted selected-required join fills this gap.

Compiler/output verifier/publisher native action-resolver schema gains required digest-covered owner_overlay_operation_records array (empty only when no local operations selected); validate all v172 fields, selected subset, unique exact registration/operation/view/source role/schema/effect/current generation joins and canonical row order. Include it in native resolver digest, compiled closure/index cross-check and active signed service-generation projection. Root current worker resolver returns an independent typed owner-overlay selection lane; generic adapter_rows remains backend-only. native_plugin_loader manifest validation/import selection must derive exact local module/registration/source schema allowlist from this lane and join it to the same held module origin closure, not fabricate backend adapters/actions. The source registry must not issue loaded/PIDFD proof.

NativeInvocationRegistry/source observer observes exact fixed local registration with current loaded worker/process role, actual input/payload/schema bytes and root-selected view/CAS revision. AuthorityService registers the finite owned overlay broker proxy; it resolves current exact operation row/view/schema/effect grant/source closure, consumes one-use operation-bound grant before CAS store access and validates actual result schema/source receipt afterward. No caller path/view/operation/action label becomes authority. Genuine end-to-end loading/invocation for all four methods and altered view/revision/schema/source/grant/operation failure tests remain OPEN; source compiler four candidates alone do not demonstrate loading/effects.

## Network kernel and per-worker startup gate (HI02/HI-T02)

Root reports actual hosted wrong-port bind success with CAPS_EMPTY. This is unsupported enforcement, not a successful negative test. Do not merge37d627: its `/usr/bin/python3 -c` has no reviewed runtime/source/launch owner and a systemd-run timeout does not establish owned-unit cleanup. No denied-bind skip or weaker expectation may convert unsupported kernel into safety evidence.

Smallest finite producer: network/custody/release owner implements standalone stdlib `hermes_installer.authority.private_loopback_worker_gate` with fixed source-owned helper member `helpers/private-loopback-worker-gate.py`, dedicated `network-startup-helper` role0444 and actual committed SHA/size pending owner implementation/review. No generic helper/script/argv/-c acceptance. `RootActiveNetworkHelperRuntimeRegistry.from_current_installed_release(verified_release,current_actor,active_enrollment,root_journal)` retains exact helper FD/member receipt, installed interpreter/runtime/bin/python role interpreter and full verified runtime-member stdlib/native closure, bound to active selected generation/network/namespace/source choice and original active revocation. This uses isolated installer helper runtime; it never reuses expired setup-session PM selectors, aliases the six runnable roles or substitutes this runtime for Hermes PM. Receipt resolution reopens held bytes and current active source/enrollment. Root-network custodian creates a one-use, purpose-specific fixed launch selection and grant from these real receipts, permitting only isolated interpreter + immutable helper, fixed readonly contract FD/mount, fixed owned unit/name/UID/GID/namespace/network/member role; caller supplies neither executable nor code string.

Separate preflight helper unit tests only host/kernel capability and is never per-worker authority. After helper preflight succeeds, each selected worker unit starts in its OWN selected cgroup/network namespace with app code withheld. The same source-pinned gate executes BEFORE any selected app/import/plugin/provider code; root independently observes actual worker MainPID/PIDFD/start/UID/GID/unit/cgroup/namespace, empty required capability set, selected socket bind deny/allow policy and actual enforcement attachment/readback for THAT cgroup. Gate tests finite exact allowed role+port and root-selected wrong port, forbidden AF_INET6/address/listener/client transition cases; expected denied bind must be observed EACCES/EPERM, not conflict/EADDRINUSE or missing binary. Own allowed endpoint control must succeed to avoid generic network failure falsely satisfying denial. No arbitrary address/port echo or outbound service calls; all probes confined owned namespace/loopback. Root takes actual bounded gate result via retained peer/FD channel and revalidates observations before unblocking the original fixed app recipe in the SAME cgroup. Gate receipt expires/revokes with worker/network lease. Per-worker observation cannot be substituted by a diagnostic helper in a different cgroup.

Both helper/worker units require RuntimeMaxSec bounded<=30s for gate phase, KillMode=control-group, owned cgroup membership and deadline/cancel cleanup. Root uses actual manager control, closes duplicate PIDFD after exit, verifies all owned unit/cgroup processes stopped and sockets/namespace/temporary members released; preserve foreign resources. Gate success releases only selected app start barrier; unsupported failure denies startup, emits no network lease/source role/runnable acceptance and verifies cleanup, classified unavailable. Failed cleanup stays failed/pending and denies reuse. Root runtime receipt and gate helper/source pins remain pending until the owner supplies actual implementation bytes. Lifecycle manager must switch to existing app runtime limit only after gate success, never leave a30s limit silently governing unrelated services. No spending, package installation or host-wide service changes in this refinement.

## Tasks, producer order and evidence

- HI-T180.1 release/broker/factory/source owner: apply exact native/source member descriptors, canonical installed IDs, eight genuine imported support modules, changed source-definition resolver and separate held worker source-module receipts. Test installed descriptor wrong role/ID/path/hash/size/actor origin and altered source closure denial; source imports before assembly/output/publication, later loaded proof remains pending.
- SK-T180.2 builder/factory/release/admission/custody: merge reviewed c757aec tuple correction/three-app valid-input regressions, apply one finite execution-only driver role and actual held resolver/recipe. Wrong driver/runtime/lock/backend/grant/output/ABI fails before ready. Real build/qualification and SK-T161.2 stay OPEN.
- HI-T180.3 compiler/output/publisher/worker resolver/native loader/invocation/AuthorityService:21-field definition + separate digest-covered v172 local operation lane through active publication, loader and real four-method invocation. Preserve full inventory/pending coverage and meaningful view/schema/source/grant/currentness failure/effect tests. HI-T178.1/HI-T179.2 stay OPEN until full exact evidence.
- HI-T180.4 remote observer/release/custody: apply exact remote module pin, finite dependency/FFI observation and test-only fixture correction; genuine same-window event/current peer/Access/runtime evidence separately pending.
- HI-T180.5 network/custody/release/runtime/lifecycle: implement measured immutable helper + active isolated interpreter/source receipt owner, fixed one-use launch, host preflight and SAME-worker-cgroup before-app gate, unsupported denial/startup stop/actual cleanup evidence. Keep helper hashes absent until measured, keep37d627 unmerged, never weaken HI02 wrong-port/IPv6/capability negatives.
- VD-T180.6 integration/evidence owner: after exact pin application, review final changed source bytes, verify packaged closure and focused positive/failure tests plus strict13 spec/160 baseline validation. No broad suite expansion for this planning commit. All AC01..18 OPEN; no source-only fixture outcome becomes runtime acceptance.

Producer order is source implementation and measured committed bytes -> this finite source review -> exact descriptor/role/receipt application -> installed source/actor membership -> selected source/output projection -> active publication -> independently observed loaded worker/kernel gate -> bounded actual effects and target evidence. No source import or declaration is a loaded-worker seal.
