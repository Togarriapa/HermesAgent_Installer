"""Stage-zero proof for the installed root setup release and current actor.

The deployment receipt and immutable closure manifest are produced by the
root installer deployment stage. Verification is deliberately independent of
the later root-setup-selection.json and active worker authority.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import re
import secrets
import select
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending, _process_start_time, _verify_import_search_path
from .application_effect_source_catalog import (
    APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID, APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
    APPLICATION_EFFECT_SOURCE_CATALOG_SHA256, APPLICATION_EFFECT_SOURCE_CATALOG_SIZE,
    APPLICATION_EFFECT_SOURCE_MEMBERS,
)
from .installer_release_roles import NETWORK_STARTUP_HELPER, RELEASE_MEMBER_ROLES

DEPLOYMENT_RECEIPT_PATH = Path("/var/lib/hermes-installer/deployments/current.json")
RELEASE_STORE_ROOT = Path("/usr/lib/hermes-installer/releases")
RELEASE_ID = "hermes-installer-root-release-v1"
BASELINE_TAG_OBJECT = "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
BASELINE_COMMIT = "653ac5fbc7a02613c9951859a7d794599603459b"
TEMPLATE = (
    "installer-bootstrap-compiler-template-v1",
    "templates/bootstrap-compiler-template-v1.json",
    "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5",
    4281,
)
PLAN_TEMPLATE = (
    "installer-root-setup-plan-template-v1",
    "templates/root-setup-plan-template-v1.json",
    "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5",
    920,
)
AUTHENTIK_TEMPLATE = (
    "installer-authentik-policy-template-v1",
    "templates/authentik-policy-template-v1.json",
    "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8",
    261,
)
PREPARED_BASE_TEMPLATE = (
    "installer-prepared-authority-base-template-v1",
    "templates/prepared-authority-base-template-v1.json",
    "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953",
    369,
)
RECEIPT_BINDINGS_TEMPLATE = (
    "installer-bootstrap-receipt-bindings-template-v1",
    "templates/bootstrap-receipt-bindings-template-v1.json",
    "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609",
    10195,
)
COMPOSIO_READER_TEMPLATE = (
    "installer-composio-whatsapp-catalog-read-policy-v1",
    "templates/composio-whatsapp-catalog-read-policy-v1.json",
    "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5",
    528,
)
EXISTING_MODEL_STORE_TEMPLATE = (
    "installer-existing-model-store-root-template-v1",
    "templates/existing-model-store-root-template-v1.json",
    "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f",
    712,
)
PRIVATE_LOOPBACK_POLICY_TEMPLATE = (
    "installer-private-loopback-nft-v1",
    "templates/private-loopback-policy-v1.json",
    "77a48f3a31f115693b04245146158e3c2467f297ff14746a52375850d76237cc",
    1_482,
)
REVIEWED_NATIVE_CAPABILITY_MAP_TEMPLATE = (
    "installer-reviewed-native-capability-map-v1",
    "templates/reviewed-native-capability-map-v1.json",
    "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565",
    2026,
)
FIXED_TEMPLATES = (TEMPLATE, PLAN_TEMPLATE, AUTHENTIK_TEMPLATE,
                   PREPARED_BASE_TEMPLATE, RECEIPT_BINDINGS_TEMPLATE,
                   COMPOSIO_READER_TEMPLATE, EXISTING_MODEL_STORE_TEMPLATE,
                   PRIVATE_LOOPBACK_POLICY_TEMPLATE, REVIEWED_NATIVE_CAPABILITY_MAP_TEMPLATE)
REVIEWED_SOURCE_MODULES = (
    ("installer-module:hermes_installer.authority.active_native_worker_runtime", "lib/python/hermes_installer/authority/active_native_worker_runtime.py",
     "5196a3206cb5a09daef5eb51cb4ef70d812f4d02a85073e2fc67bf8d1ba783e4", 38_660, "module"),
    ("installer-module:hermes_installer.authority.active_network_generation", "lib/python/hermes_installer/authority/active_network_generation.py",
     "143ba59f13316f6a66315aed7193a66e4c2e4d6a7b8d03963a3244735fd44f70", 23_570, "module"),
    ("installer-module:hermes_installer.authority.active_policy_compiler", "lib/python/hermes_installer/authority/active_policy_compiler.py",
     "a9a0f983aeab2c47274c8a3f46155ac7f97ebd2264cb15d888d5379ed550f568", 147_437, "module"),
    ("installer-module:hermes_installer.authority.application_runtime_archive", "lib/python/hermes_installer/authority/application_runtime_archive.py",
     "3117c4c706bfcffe6626c57c79934b143c36d8cd75758dd1198c2020286c2197", 31_457, "module"),
    ("installer-module:hermes_installer.authority.application_runtime_relocation", "lib/python/hermes_installer/authority/application_runtime_relocation.py",
     "9b426e61480613c9e10aeaa4227aaff6d06a5558000b45cb94fb0d0160e47afc", 12_120, "module"),
    ("installer-module:hermes_installer.authority.bootstrap_enrollment", "lib/python/hermes_installer/authority/bootstrap_enrollment.py",
     "d491638ae8a27a3d1a6d3392a50e5e2d41935a181f85a6ff0eac66756429296c", 147_164, "module"),
    ("installer-module:hermes_installer.authority.bootstrap_runtime_factory", "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py",
     "949e4bce79bfff32c9a8bb15152540968aca84b575d253725c80e3ecf23f64b7", 691_421, "module"),
    ("installer-module:hermes_installer.authority.client", "lib/python/hermes_installer/authority/client.py",
     "f8be053e3a00b49087c6104ed77a314a071c8b0a47cf9701c4050b7aae13b46f", 73_488, "module"),
    ("installer-module:hermes_installer.authority.committed_pm_executable", "lib/python/hermes_installer/authority/committed_pm_executable.py",
     "11f6b8f7e46a57bf7056c4ab1b1ffb9f1665eecde5281d64843890f23aa84106", 45_388, "module"),
    ("installer-module:hermes_installer.authority.daemon", "lib/python/hermes_installer/authority/daemon.py",
     "6e506c868e164b429d50b2567a119a9dced2de69cc9bc042c7062813839e37c9", 37_930, "module"),
    ("installer-module:hermes_installer.authority.enrollment", "lib/python/hermes_installer/authority/enrollment.py",
     "f98dcc6e89916a2b1dbef4af8544b38f6518da2a3ff35cfba3e18687d3a520a9", 206_828, "module"),
    ("installer-module:hermes_installer.authority.functional_health_receipt_consumer", "lib/python/hermes_installer/authority/functional_health_receipt_consumer.py",
     "c889505f5b1408c77f234975cc81eb84299177b0153f180d768667bac33a6c4d", 43_402, "module"),
    ("installer-module:hermes_installer.authority.initial_policy_compiler", "lib/python/hermes_installer/authority/initial_policy_compiler.py",
     "34aa92870f6e5fabd327f9518f3fcd4e1a6afa90b43c0be4bcc02ae88996a708", 41_486, "module"),
    ("installer-module:hermes_installer.authority.listener_activation", "lib/python/hermes_installer/authority/listener_activation.py",
     "bdf0575eac51b8d247c741ca57535e956cbc879e5506f60fdc5bf4f50cd8d302", 197_688, "module"),
    ("installer-module:hermes_installer.authority.local_resource_effects", "lib/python/hermes_installer/authority/local_resource_effects.py",
     "1d1f72655ed335ae486c76df80f97ffd997b07440a2b9417563c2918d874be9d", 142_474, "module"),
    ("installer-module:hermes_installer.authority.native_assembler", "lib/python/hermes_installer/authority/native_assembler.py",
     "564093a9bd255b10f83de08811b9280c30104750c949432ab87644eae03bcfb1", 28_815, "module"),
    ("installer-module:hermes_installer.authority.native_custody_proof", "lib/python/hermes_installer/authority/native_custody_proof.py",
     "4b48a790a768b92204d84229e38910cd6d2da37ce5844ca72579ba36c5eb986e", 99_355, "module"),
    ("installer-module:hermes_installer.authority.native_definition_composition", "lib/python/hermes_installer/authority/native_definition_composition.py",
     "f99e072dfb60cfbcce4a760d38355301f9e653d231586d2f538dffd88acfff3a", 9_534, "module"),
    ("installer-module:hermes_installer.authority.native_health_daemon", "lib/python/hermes_installer/authority/native_health_daemon.py",
     "d21d018e6fb6676b61b1f0b6968feb54d4c2d1a0f2fa5ddca6878807ae8d928c", 112_468, "module"),
    ("installer-module:hermes_installer.authority.native_health_observer", "lib/python/hermes_installer/authority/native_health_observer.py",
     "af2b48783347b0a684259233b36312c849ee6896f25bb03b49b6b23c5a51480c", 145_475, "module"),
    ("installer-module:hermes_installer.authority.native_health_source", "lib/python/hermes_installer/authority/native_health_source.py",
     "e98f0a7d5ee5807a06fb1b9e51b27120e0b9c5051aa0af9663ceb67c46ea449e", 16_121, "module"),
    ("installer-module:hermes_installer.authority.native_input_observer", "lib/python/hermes_installer/authority/native_input_observer.py",
     "1777ff56664ee298db2eb4b32af0ed3929f0e509c7a8c5b82bf219d6554c349d", 41_560, "module"),
    ("installer-module:hermes_installer.authority.native_output_receipts", "lib/python/hermes_installer/authority/native_output_receipts.py",
     "25f8903c4e9cfd9b6d05bccc98f00d6b0c8becf09c1e624235fa8f10164563ba", 115_704, "module"),
    ("installer-module:hermes_installer.authority.native_policy_preparation", "lib/python/hermes_installer/authority/native_policy_preparation.py",
     "23557ae9d39b017716936408a4e64d8c197749b42f7b507ef9212cfe41934387", 65_082, "module"),
    ("installer-module:hermes_installer.authority.native_registration_projection", "lib/python/hermes_installer/authority/native_registration_projection.py",
     "7afa35250c9cd82f34030d37a74b6c310f25fde88d2169cf30913eafcbcf266b", 82_047, "module"),
    ("installer-module:hermes_installer.authority.native_request_observation", "lib/python/hermes_installer/authority/native_request_observation.py",
     "a30da168eb0a94ef490e88aed23a4f60b50b9a89f65bf71fd0c642a92ec8117d", 33_600, "module"),
    ("installer-module:hermes_installer.authority.native_runtime_observer", "lib/python/hermes_installer/authority/native_runtime_observer.py",
     "9cab5a39a2ba647514ae11bb7442d418a293941841f9eee382233f0669371bdb", 198_388, "module"),
    ("installer-module:hermes_installer.authority.native_source_definitions", "lib/python/hermes_installer/authority/native_source_definitions.py",
     "4d66c49e798eb957fa77601c4dad021182b734b1eb8fe322d52ecca060223341", 32_858, "module"),
    ("installer-module:hermes_installer.authority.native_worker_endpoint_custody", "lib/python/hermes_installer/authority/native_worker_endpoint_custody.py",
     "66e3ddf7ebc82185bb3cf9df5f60185be5d78f3d2098df0dd513731012589ee5", 40_194, "module"),
    ("installer-module:hermes_installer.authority.native_worker_generation_schema", "lib/python/hermes_installer/authority/native_worker_generation_schema.py",
     "f03c0fc953bb54ace37d86d8e8315999eacb96055c1f61bebc6769eb2061fc83", 13_871, "module"),
    ("installer-module:hermes_installer.authority.native_worker_launch", "lib/python/hermes_installer/authority/native_worker_launch.py",
     "abe1eb856ac6a31c9c4bb828969432ae3afab1a128b23b4ad6ea2ccac0f32054", 38_435, "module"),
    ("installer-module:hermes_installer.authority.native_worker_recipes", "lib/python/hermes_installer/authority/native_worker_recipes.py",
     "add2189878535c7b35d3cc04a426241a5ba24f7d2bed0ab5461fe152e404c0bc", 46_109, "module"),
    ("installer-module:hermes_installer.authority.native_worker_runtime_materialization", "lib/python/hermes_installer/authority/native_worker_runtime_materialization.py",
     "529b0d707bd530df206d6a512dc061a12d894a2b92546235e9480ccea4cff923", 71_935, "module"),
    ("installer-module:hermes_installer.authority.native_worker_service_generation", "lib/python/hermes_installer/authority/native_worker_service_generation.py",
     "0487ea123cad9300bdbab464b012a5b4314f48bf400289aec199cdafad585ace", 42_104, "module"),
    ("installer-module:hermes_installer.authority.native_worker_start_recipe", "lib/python/hermes_installer/authority/native_worker_start_recipe.py",
     "87cc2071f39e4cc2fe636cc9005c39f3c21d1c57f412944de474d198d7144afd", 20_416, "module"),
    ("installer-module:hermes_installer.authority.owner_overlay_capture_schemas", "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py",
     "37b28db4c9709147dee50f14ea99ba5bd6e74a796ace897c3e9a51ba660d063d", 5_409, "module"),
    ("installer-module:hermes_installer.authority.owner_overlay_publication", "lib/python/hermes_installer/authority/owner_overlay_publication.py",
     "c35ac8726ba6b75fa48aed1ef94d6e52e445633c1f8b63a8e49c82aefd64b446", 57_259, "module"),
    ("installer-module:hermes_installer.authority.pm_runtime", "lib/python/hermes_installer/authority/pm_runtime.py",
     "1bf7e149095651c6dfcc33d88d9e2ca375879c5d7dea990c0ec2e6a37c2e4a0e", 70_358, "module"),
    ("installer-module:hermes_installer.authority.private_loopback_network", "lib/python/hermes_installer/authority/private_loopback_network.py",
     "a56123f11f9069fc06b41921e4b2af704781ca321ddd6e314239236f3a6d2384", 70_665, "module"),
    ("installer-module:hermes_installer.authority.private_loopback_worker_gate", "lib/python/hermes_installer/authority/private_loopback_worker_gate.py",
     "4732b84abc05087f2248ecd374c7a55c765676ab9a489c4cdfe0509a324ee508", 22_240, "module"),
    ("installer-module:hermes_installer.authority.remote_observations", "lib/python/hermes_installer/authority/remote_observations.py",
     "b6e602fc03996fcd00da4ba43d394e377feea1706d2b7d08691c587754a9ec31", 93_746, "module"),
    ("installer-module:hermes_installer.authority.runtime_bindings", "lib/python/hermes_installer/authority/runtime_bindings.py",
     "d0a0e8d2dd3465e6b5964286193d101173b394c498cbc11eb6ebc723df8660b5", 133_410, "module"),
    ("installer-module:hermes_installer.authority.runtime_composition", "lib/python/hermes_installer/authority/runtime_composition.py",
     "b9b285f6d97b2fb851bae7809adeafb0927b07a6282c7bf74e1a135a665c2f9a", 120_007, "module"),
    ("installer-module:hermes_installer.authority.runtime_root_custody", "lib/python/hermes_installer/authority/runtime_root_custody.py",
     "85fa514c128b962848dbe267fdcbaeb03f90f16ba2a2a6cf3fb288d3d2be09dd", 38_316, "module"),
    ("installer-module:hermes_installer.authority.service", "lib/python/hermes_installer/authority/service.py",
     "e7d8bd1ff1860df60caa892a0641abfb6386d44c117fb735bb8e304404006412", 369_857, "module"),
    ("installer-module:hermes_installer.authority.setup_policy_publication", "lib/python/hermes_installer/authority/setup_policy_publication.py",
     "0f1af94ac39dabb150a0e4d4a3c2e903883e6e3dd4eda3099ff57bfa9f40bddc", 149_213, "module"),
    ("installer-module:hermes_installer.authority.setup_principal", "lib/python/hermes_installer/authority/setup_principal.py",
     "8c10a9be6fcb0da4e41d56c8f29d14d09d603946ff060b13966a5fefa8d1aa96", 167_860, "module"),
    ("installer-module:hermes_installer.authority.source_observers", "lib/python/hermes_installer/authority/source_observers.py",
     "8cf9ca2e4171c1a5a2402fa2874b2115592143aaff2ab127bc4238d2912e9ba9", 261_264, "module"),
    ("installer-module:hermes_installer.components.native_plugins", "lib/python/hermes_installer/components/native_plugins.py",
     "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7", 28_259, "module"),
    ("installer-module:hermes_installer.components.public_registries", "lib/python/hermes_installer/components/public_registries.py",
     "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f", 29_374, "module"),
    ("installer-module:hermes_installer.managed_process_custodian", "lib/python/hermes_installer/managed_process_custodian.py",
     "5a74aa6c256d6e26e21071c8726d409c5e414b34744d28077f794efd35ff0877", 636_592, "module"),
    ("installer-module:hermes_installer.native_boundary_patch", "lib/python/hermes_installer/native_boundary_patch.py",
     "fe1bfca7de02408c27891f0d6830da938ee7f18c84ee6b34bdd766f8e1645159", 22_888, "module"),
    ("installer-module:hermes_installer.native_plugin_bindings", "lib/python/hermes_installer/native_plugin_bindings.py",
     "f5e9fcb74b555dcd5d98bc37eec29c42cbe85f3793cf43f2dc97536b030d1b26", 22_679, "module"),
    ("installer-module:hermes_installer.native_plugin_loader", "lib/python/hermes_installer/native_plugin_loader.py",
     "eebe58ea486ecebeceacc8d8f46f8b26e061b46b4f25a11e41a5059f0233bdbd", 124_775, "module"),
    ("installer-module:hermes_installer.protected_enrollment", "lib/python/hermes_installer/protected_enrollment.py",
     "5b6848226891a08b0a3f4e25f311cb230ad8b4005fe3c485f0e86c56fddcb0a1", 212_817, "module"),
    ("installer-module:hermes_installer.registry.resource_backends", "lib/python/hermes_installer/registry/resource_backends.py",
     "b7e3fb94b20a21c03c7ae521bea1ca808f7de323c5edd0c3d6d9741b29174843", 27_262, "module"),
    ("installer-module:hermes_installer.root_setup", "lib/python/hermes_installer/root_setup.py",
     "0b7d7203b41d3496ebb14d6997fa3e3aaef58aafa98bb8c498004aaf31960616", 71_543, "module"),
    ("installer-native-invocations-module-v137", "src/hermes_installer/native_invocations.py",
     "78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226", 40_107, "source-module"),
    ("installer-native-boundary-module-v137", "src/hermes_installer/native_boundary.py",
     "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb", 14_356, "source-module"),
    ("installer-module:hermes_installer.authority.durable_pm_runtime", "lib/python/hermes_installer/authority/durable_pm_runtime.py",
     "45c7898f7f3cf371d07ff9bc7f37efa75c8160e6baabe314d0e82fc10988a520", 19_104, "module"),
    ("installer-module:hermes_installer.authority.native_profile_task_homes", "lib/python/hermes_installer/authority/native_profile_task_homes.py",
     "afa80f02065228d454811c0d2653e378d1a9e0bd6e0b494ae9a1536796eaec0f", 39_348, "module"),
    ("installer-module:hermes_installer.authority.selected_startup_intents", "lib/python/hermes_installer/authority/selected_startup_intents.py",
     "1da2c9a0dededd930fe98695455dc438a77572612a34b4774b134566ec2d262d", 28_974, "module"),
)


APPLICATION_BUILD_DRIVER = (
    "installer-application-environment-builder-v1",
    "lib/python/hermes_installer/authority/application_environment_builder.py",
    "8c5aebe61ba3d7e5c9bcf27dfadba8771ed3a4987240ea52fe2189251f1b6e8c",
    45_807,
    "application-build-driver",
)
REQUIRED_NATIVE_SUPPORT_MODULE_IDS = (
    "installer-module:hermes_installer.authority.native_assembler",
    "installer-module:hermes_installer.authority.native_registration_projection",
    "installer-module:hermes_installer.components.native_plugins",
    "installer-module:hermes_installer.components.public_registries",
    "installer-module:hermes_installer.authority.native_definition_composition",
    "installer-module:hermes_installer.authority.native_policy_preparation",
    "installer-module:hermes_installer.authority.native_source_definitions",
    "installer-module:hermes_installer.authority.local_resource_effects",
)
REQUIRED_LAUNCHER_MODULES = (
    ("installer-module:hermes_installer", "lib/python/hermes_installer/__init__.py"),
    ("installer-module:hermes_installer.authority", "lib/python/hermes_installer/authority/__init__.py"),
    ("installer-module:hermes_installer.root_setup", "lib/python/hermes_installer/root_setup.py"),
    ("installer-module:hermes_installer.authority.installer_release",
     "lib/python/hermes_installer/authority/installer_release.py"),
    ("installer-module:hermes_installer.authority.bootstrap_runtime_factory",
     "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py"),
)
REVIEWED_SOURCE_ARTIFACTS = (
    ("installer-native-mcp-discovery-capture-profile-v171",
     "plans/amendments/2026-10-10-mcp-discovery-capture-v171/mcp-discovery-capture-v1.json",
     "bf9b3b649bf995d5743a38597415ef003928e1d67dc337ab5c7f3e7ec9643e8a", 4_601, "amendment"),
    ("installer-native-input-capture-profile-v1",
     "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-input-capture-profile-v1.json",
     "bfdf7175ee1df681b60ab4b707ffe9d314d8cc7fdc5a30a56e19d2cb1372c1d0", 837, "amendment"),
    ("installer-native-tool-result-capture-profile-v1",
     "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-tool-result-capture-profile-v1.json",
     "470fcc43b3d268a6594e0d6bdf2c635ba3bf4e6cd0cfe2dfcd57840d7bee105a", 984, "amendment"),
    ("installer-native-provider-result-capture-profile-v1",
     "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-provider-result-capture-profile-v1.json",
     "a2c6ae9243a7854f114ed492afd395d867f02ed58d50a3f1692fe0ea7efbd8eb", 993, "amendment"),
    ("installer-application-toolchain-source-policy-v144",
     "plans/amendments/2026-10-10-hyperframes-toolchain-source-v144/hyperframes-toolchain-source-v1.json",
     "81b9e3655ddb627c46d828690687a1600fd9a7455af4c4fc5a90c32b3991a5d6", 7_060, "amendment"),
    ("installer-application-pep517-backend-sources-v1",
     "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/application-pep517-backend-source-table-v1.json",
     "c7d64c6ca0a186437d32b8093df0be0a3dc660fc721172e7ce1a56fd5a87c623", 15_907, "amendment"),
    ("glm52-artifact-metadata-v1", "planning/glm52-artifact-metadata.json",
     "b42e3fa6fd5c287b95fcda4d370697bd4c0ef226767ddc08fae4e5bebcfecd1a", 56_232, "baseline"),
    ("glm52-upstream-mit-license-cf457fa",
     "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-upstream-MIT-LICENSE.txt",
     "f4a18c6ae40b0a8e7d2b7667f52f6e1994e54a46430d2e172b73cb8c9b5eb0d7", 1_065, "amendment"),
    ("glm52-quantized-readme-6bbb01e",
     "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-quantized-README.md",
     "85fc4cf947276c376f09ad1226926ebc03eefbb99d184cd05f34412d32d8406b", 17_468, "amendment"),
    ("hermes-agent-health-request-v1", "fixtures/native-health/request.txt",
     "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c", 182, "native-health-fixture"),
    ("hermes-agent-health-seed-v1", "fixtures/native-health/seed-value.txt",
     "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a", 67, "native-health-fixture"),
    ("hermes-agent-health-expected-result-v1", "fixtures/native-health/expected-tool-result.json",
     "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a", 240, "native-health-fixture"),
    ("hermes-agent-health-overlay-read-result-v1", "fixtures/native-health/tool-result.schema.json",
     "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5", 526, "native-health-fixture"),
    ("hermes-agent-health-fixture-v1", "fixtures/native-health/recipe.json",
     "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7", 845, "native-health-fixture"),
)
LAUNCHER_PATH = "bin/hermes-installer-root-setup"
INTERPRETER_PATH = "runtime/bin/python"
PLAN_PATH = "plans/root-setup-plan-v1.json"
ARTIFACT_CATALOG_PATH = "catalog/artifacts.json"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 50_000
MAX_FILE_BYTES = 512 * 1024 * 1024
ROLES = RELEASE_MEMBER_ROLES


def _cohort_value(cohort: Mapping[str, Any] | None, name: str) -> Any:
    return globals()[name] if cohort is None else cohort[name]


def _freeze_review_data(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_review_data(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_review_data(item) for item in value)
    return value

# v249: exact, source-reviewed cc81 constants.  This is data only; historical
# code is never imported or executed.  The adjacent planning artifact records
# the same canonical bytes and their reviewed digest.
_CC81_COHORT_JSON = '{\n  "schema": 1,\n  "cohort_id": "installed-predecessor-cc81-review-v249",\n  "candidate_git_sha": "cc81abffe3cbb1df447889bca269d1e6c0be77ea",\n  "source_origin": "https://github.com/Togarriapa/HermesAgent_Installer.git",\n  "source_git_tree": "74dca3566f212e185cbdada7a2d401cf0d63f6e9",\n  "source_blobs": [\n    {\n      "relative_path": "src/hermes_installer/authority/installer_release_roles.py",\n      "sha256": "77414427c957315b5039e4d90f75c997739d7fd3caa18014f874aa7fed7806f0",\n      "size_bytes": 1162\n    },\n    {\n      "relative_path": "src/hermes_installer/authority/application_effect_source_catalog.py",\n      "sha256": "cc77027546df592d439da36cd162f36841176cdb8a37ca12d213da2ff3666c78",\n      "size_bytes": 3150\n    },\n    {\n      "relative_path": "src/hermes_installer/authority/installer_release.py",\n      "sha256": "aceb07d75a0723ae7abc80aba68aa544056ff9eec49885b73ca0af7190a3780e",\n      "size_bytes": 80261\n    },\n    {\n      "relative_path": "src/hermes_installer/root_setup.py",\n      "sha256": "5bd49b6e0105d65d342302df953ed41f6ab0f0edd2bb90d7e7c2b4b4ada30563",\n      "size_bytes": 62517\n    },\n    {\n      "relative_path": "src/hermes_installer/authority/installer_release_build.py",\n      "sha256": "6355198dd122046469b7aba2d9c02ffae43fc17dd3b7263c1e782b560f06b12f",\n      "size_bytes": 258915\n    }\n  ],\n  "constants": {\n    "RELEASE_ID": "hermes-installer-root-release-v1",\n    "BASELINE_TAG_OBJECT": "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8",\n    "BASELINE_COMMIT": "653ac5fbc7a02613c9951859a7d794599603459b",\n    "FIXED_TEMPLATES": [\n      [\n        "installer-bootstrap-compiler-template-v1",\n        "templates/bootstrap-compiler-template-v1.json",\n        "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5",\n        4281\n      ],\n      [\n        "installer-root-setup-plan-template-v1",\n        "templates/root-setup-plan-template-v1.json",\n        "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5",\n        920\n      ],\n      [\n        "installer-authentik-policy-template-v1",\n        "templates/authentik-policy-template-v1.json",\n        "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8",\n        261\n      ],\n      [\n        "installer-prepared-authority-base-template-v1",\n        "templates/prepared-authority-base-template-v1.json",\n        "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953",\n        369\n      ],\n      [\n        "installer-bootstrap-receipt-bindings-template-v1",\n        "templates/bootstrap-receipt-bindings-template-v1.json",\n        "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609",\n        10195\n      ],\n      [\n        "installer-composio-whatsapp-catalog-read-policy-v1",\n        "templates/composio-whatsapp-catalog-read-policy-v1.json",\n        "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5",\n        528\n      ],\n      [\n        "installer-existing-model-store-root-template-v1",\n        "templates/existing-model-store-root-template-v1.json",\n        "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f",\n        712\n      ],\n      [\n        "installer-private-loopback-nft-v1",\n        "templates/private-loopback-policy-v1.json",\n        "77a48f3a31f115693b04245146158e3c2467f297ff14746a52375850d76237cc",\n        1482\n      ],\n      [\n        "installer-reviewed-native-capability-map-v1",\n        "templates/reviewed-native-capability-map-v1.json",\n        "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565",\n        2026\n      ]\n    ],\n    "REVIEWED_SOURCE_MODULES": [\n      [\n        "installer-module:hermes_installer.authority.active_native_worker_runtime",\n        "lib/python/hermes_installer/authority/active_native_worker_runtime.py",\n        "5196a3206cb5a09daef5eb51cb4ef70d812f4d02a85073e2fc67bf8d1ba783e4",\n        38660,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.active_network_generation",\n        "lib/python/hermes_installer/authority/active_network_generation.py",\n        "143ba59f13316f6a66315aed7193a66e4c2e4d6a7b8d03963a3244735fd44f70",\n        23570,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.active_policy_compiler",\n        "lib/python/hermes_installer/authority/active_policy_compiler.py",\n        "61ae3576ac53e5ad5c6f1b0c74967110021fd961677353aae889b9f8bf04940b",\n        136868,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.application_runtime_archive",\n        "lib/python/hermes_installer/authority/application_runtime_archive.py",\n        "3117c4c706bfcffe6626c57c79934b143c36d8cd75758dd1198c2020286c2197",\n        31457,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.application_runtime_relocation",\n        "lib/python/hermes_installer/authority/application_runtime_relocation.py",\n        "9b426e61480613c9e10aeaa4227aaff6d06a5558000b45cb94fb0d0160e47afc",\n        12120,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.bootstrap_enrollment",\n        "lib/python/hermes_installer/authority/bootstrap_enrollment.py",\n        "ae307ff841b29322ebd2ad06818e9f56a931f811fe789c1c3369a634188ed404",\n        144306,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.bootstrap_runtime_factory",\n        "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py",\n        "89fae27c0b8b4eeabc0c43ba0d56baa2780bc62e390a63cc6db8b1f88b028ead",\n        655738,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.client",\n        "lib/python/hermes_installer/authority/client.py",\n        "f8be053e3a00b49087c6104ed77a314a071c8b0a47cf9701c4050b7aae13b46f",\n        73488,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.committed_pm_executable",\n        "lib/python/hermes_installer/authority/committed_pm_executable.py",\n        "9e8a3a28aa10e8f3e68431b5dcc8a0d51f2afa54c3d57c5e4dd7fda2826cfcf0",\n        43170,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.daemon",\n        "lib/python/hermes_installer/authority/daemon.py",\n        "6e506c868e164b429d50b2567a119a9dced2de69cc9bc042c7062813839e37c9",\n        37930,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.enrollment",\n        "lib/python/hermes_installer/authority/enrollment.py",\n        "7ba9abef79744328ed3d5deefdf8b1815e532df295963fd72d8f9f476aa7f16e",\n        204399,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.functional_health_receipt_consumer",\n        "lib/python/hermes_installer/authority/functional_health_receipt_consumer.py",\n        "c889505f5b1408c77f234975cc81eb84299177b0153f180d768667bac33a6c4d",\n        43402,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.initial_policy_compiler",\n        "lib/python/hermes_installer/authority/initial_policy_compiler.py",\n        "34aa92870f6e5fabd327f9518f3fcd4e1a6afa90b43c0be4bcc02ae88996a708",\n        41486,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.listener_activation",\n        "lib/python/hermes_installer/authority/listener_activation.py",\n        "64274d1dc9027b9c0c80fc31f95f292cf97b34d60f87769c1d0b472306a42869",\n        182234,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.local_resource_effects",\n        "lib/python/hermes_installer/authority/local_resource_effects.py",\n        "1d1f72655ed335ae486c76df80f97ffd997b07440a2b9417563c2918d874be9d",\n        142474,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_assembler",\n        "lib/python/hermes_installer/authority/native_assembler.py",\n        "564093a9bd255b10f83de08811b9280c30104750c949432ab87644eae03bcfb1",\n        28815,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_custody_proof",\n        "lib/python/hermes_installer/authority/native_custody_proof.py",\n        "4b48a790a768b92204d84229e38910cd6d2da37ce5844ca72579ba36c5eb986e",\n        99355,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_definition_composition",\n        "lib/python/hermes_installer/authority/native_definition_composition.py",\n        "f99e072dfb60cfbcce4a760d38355301f9e653d231586d2f538dffd88acfff3a",\n        9534,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_health_daemon",\n        "lib/python/hermes_installer/authority/native_health_daemon.py",\n        "d21d018e6fb6676b61b1f0b6968feb54d4c2d1a0f2fa5ddca6878807ae8d928c",\n        112468,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_health_observer",\n        "lib/python/hermes_installer/authority/native_health_observer.py",\n        "af2b48783347b0a684259233b36312c849ee6896f25bb03b49b6b23c5a51480c",\n        145475,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_health_source",\n        "lib/python/hermes_installer/authority/native_health_source.py",\n        "e98f0a7d5ee5807a06fb1b9e51b27120e0b9c5051aa0af9663ceb67c46ea449e",\n        16121,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_input_observer",\n        "lib/python/hermes_installer/authority/native_input_observer.py",\n        "1777ff56664ee298db2eb4b32af0ed3929f0e509c7a8c5b82bf219d6554c349d",\n        41560,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_output_receipts",\n        "lib/python/hermes_installer/authority/native_output_receipts.py",\n        "25f8903c4e9cfd9b6d05bccc98f00d6b0c8becf09c1e624235fa8f10164563ba",\n        115704,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_policy_preparation",\n        "lib/python/hermes_installer/authority/native_policy_preparation.py",\n        "23557ae9d39b017716936408a4e64d8c197749b42f7b507ef9212cfe41934387",\n        65082,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_registration_projection",\n        "lib/python/hermes_installer/authority/native_registration_projection.py",\n        "7afa35250c9cd82f34030d37a74b6c310f25fde88d2169cf30913eafcbcf266b",\n        82047,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_request_observation",\n        "lib/python/hermes_installer/authority/native_request_observation.py",\n        "a30da168eb0a94ef490e88aed23a4f60b50b9a89f65bf71fd0c642a92ec8117d",\n        33600,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_runtime_observer",\n        "lib/python/hermes_installer/authority/native_runtime_observer.py",\n        "9cab5a39a2ba647514ae11bb7442d418a293941841f9eee382233f0669371bdb",\n        198388,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_source_definitions",\n        "lib/python/hermes_installer/authority/native_source_definitions.py",\n        "4d66c49e798eb957fa77601c4dad021182b734b1eb8fe322d52ecca060223341",\n        32858,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_endpoint_custody",\n        "lib/python/hermes_installer/authority/native_worker_endpoint_custody.py",\n        "66e3ddf7ebc82185bb3cf9df5f60185be5d78f3d2098df0dd513731012589ee5",\n        40194,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_generation_schema",\n        "lib/python/hermes_installer/authority/native_worker_generation_schema.py",\n        "f03c0fc953bb54ace37d86d8e8315999eacb96055c1f61bebc6769eb2061fc83",\n        13871,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_launch",\n        "lib/python/hermes_installer/authority/native_worker_launch.py",\n        "abe1eb856ac6a31c9c4bb828969432ae3afab1a128b23b4ad6ea2ccac0f32054",\n        38435,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_recipes",\n        "lib/python/hermes_installer/authority/native_worker_recipes.py",\n        "add2189878535c7b35d3cc04a426241a5ba24f7d2bed0ab5461fe152e404c0bc",\n        46109,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_runtime_materialization",\n        "lib/python/hermes_installer/authority/native_worker_runtime_materialization.py",\n        "529b0d707bd530df206d6a512dc061a12d894a2b92546235e9480ccea4cff923",\n        71935,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_service_generation",\n        "lib/python/hermes_installer/authority/native_worker_service_generation.py",\n        "0487ea123cad9300bdbab464b012a5b4314f48bf400289aec199cdafad585ace",\n        42104,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.native_worker_start_recipe",\n        "lib/python/hermes_installer/authority/native_worker_start_recipe.py",\n        "e58acef2d612c10863654c05c0ade47a6e00f18d57f9e477c49ce35a957b560d",\n        20416,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.owner_overlay_capture_schemas",\n        "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py",\n        "37b28db4c9709147dee50f14ea99ba5bd6e74a796ace897c3e9a51ba660d063d",\n        5409,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.owner_overlay_publication",\n        "lib/python/hermes_installer/authority/owner_overlay_publication.py",\n        "c35ac8726ba6b75fa48aed1ef94d6e52e445633c1f8b63a8e49c82aefd64b446",\n        57259,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.pm_runtime",\n        "lib/python/hermes_installer/authority/pm_runtime.py",\n        "1bf7e149095651c6dfcc33d88d9e2ca375879c5d7dea990c0ec2e6a37c2e4a0e",\n        70358,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.private_loopback_network",\n        "lib/python/hermes_installer/authority/private_loopback_network.py",\n        "a56123f11f9069fc06b41921e4b2af704781ca321ddd6e314239236f3a6d2384",\n        70665,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.private_loopback_worker_gate",\n        "lib/python/hermes_installer/authority/private_loopback_worker_gate.py",\n        "4732b84abc05087f2248ecd374c7a55c765676ab9a489c4cdfe0509a324ee508",\n        22240,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.remote_observations",\n        "lib/python/hermes_installer/authority/remote_observations.py",\n        "b6e602fc03996fcd00da4ba43d394e377feea1706d2b7d08691c587754a9ec31",\n        93746,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.runtime_bindings",\n        "lib/python/hermes_installer/authority/runtime_bindings.py",\n        "d0a0e8d2dd3465e6b5964286193d101173b394c498cbc11eb6ebc723df8660b5",\n        133410,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.runtime_composition",\n        "lib/python/hermes_installer/authority/runtime_composition.py",\n        "f710ede7fe6a728a0e128f7f852ba15d604e423c19f860ee3adccdb2895f8f60",\n        116776,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.runtime_root_custody",\n        "lib/python/hermes_installer/authority/runtime_root_custody.py",\n        "85fa514c128b962848dbe267fdcbaeb03f90f16ba2a2a6cf3fb288d3d2be09dd",\n        38316,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.service",\n        "lib/python/hermes_installer/authority/service.py",\n        "64693b0be4ac7a8c80547db51517723a09054d56015d520dfc717386d35be3e3",\n        367542,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.setup_policy_publication",\n        "lib/python/hermes_installer/authority/setup_policy_publication.py",\n        "bf6556d1402e03c924f913c39976d82403d1733673983f947edfabc7b3d7f34f",\n        110973,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.setup_principal",\n        "lib/python/hermes_installer/authority/setup_principal.py",\n        "8c10a9be6fcb0da4e41d56c8f29d14d09d603946ff060b13966a5fefa8d1aa96",\n        167860,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.authority.source_observers",\n        "lib/python/hermes_installer/authority/source_observers.py",\n        "8cf9ca2e4171c1a5a2402fa2874b2115592143aaff2ab127bc4238d2912e9ba9",\n        261264,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.components.native_plugins",\n        "lib/python/hermes_installer/components/native_plugins.py",\n        "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7",\n        28259,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.components.public_registries",\n        "lib/python/hermes_installer/components/public_registries.py",\n        "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f",\n        29374,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.managed_process_custodian",\n        "lib/python/hermes_installer/managed_process_custodian.py",\n        "1bb1267e5e95307da0bf78775a3450ce48a5762f8cff6e5600db2ba8af907657",\n        631187,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.native_boundary_patch",\n        "lib/python/hermes_installer/native_boundary_patch.py",\n        "fe1bfca7de02408c27891f0d6830da938ee7f18c84ee6b34bdd766f8e1645159",\n        22888,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.native_plugin_bindings",\n        "lib/python/hermes_installer/native_plugin_bindings.py",\n        "f5e9fcb74b555dcd5d98bc37eec29c42cbe85f3793cf43f2dc97536b030d1b26",\n        22679,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.native_plugin_loader",\n        "lib/python/hermes_installer/native_plugin_loader.py",\n        "eebe58ea486ecebeceacc8d8f46f8b26e061b46b4f25a11e41a5059f0233bdbd",\n        124775,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.protected_enrollment",\n        "lib/python/hermes_installer/protected_enrollment.py",\n        "5b6848226891a08b0a3f4e25f311cb230ad8b4005fe3c485f0e86c56fddcb0a1",\n        212817,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.registry.resource_backends",\n        "lib/python/hermes_installer/registry/resource_backends.py",\n        "e59813aa36754a0e08fece9c9c2a83ec9c21a6807935a6c83f7b09cca6792414",\n        27026,\n        "module"\n      ],\n      [\n        "installer-module:hermes_installer.root_setup",\n        "lib/python/hermes_installer/root_setup.py",\n        "5bd49b6e0105d65d342302df953ed41f6ab0f0edd2bb90d7e7c2b4b4ada30563",\n        62517,\n        "module"\n      ],\n      [\n        "installer-native-invocations-module-v137",\n        "src/hermes_installer/native_invocations.py",\n        "78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226",\n        40107,\n        "source-module"\n      ],\n      [\n        "installer-native-boundary-module-v137",\n        "src/hermes_installer/native_boundary.py",\n        "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb",\n        14356,\n        "source-module"\n      ]\n    ],\n    "REVIEWED_SOURCE_ARTIFACTS": [\n      [\n        "installer-native-mcp-discovery-capture-profile-v171",\n        "plans/amendments/2026-10-10-mcp-discovery-capture-v171/mcp-discovery-capture-v1.json",\n        "bf9b3b649bf995d5743a38597415ef003928e1d67dc337ab5c7f3e7ec9643e8a",\n        4601,\n        "amendment"\n      ],\n      [\n        "installer-native-input-capture-profile-v1",\n        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-input-capture-profile-v1.json",\n        "bfdf7175ee1df681b60ab4b707ffe9d314d8cc7fdc5a30a56e19d2cb1372c1d0",\n        837,\n        "amendment"\n      ],\n      [\n        "installer-native-tool-result-capture-profile-v1",\n        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-tool-result-capture-profile-v1.json",\n        "470fcc43b3d268a6594e0d6bdf2c635ba3bf4e6cd0cfe2dfcd57840d7bee105a",\n        984,\n        "amendment"\n      ],\n      [\n        "installer-native-provider-result-capture-profile-v1",\n        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-provider-result-capture-profile-v1.json",\n        "a2c6ae9243a7854f114ed492afd395d867f02ed58d50a3f1692fe0ea7efbd8eb",\n        993,\n        "amendment"\n      ],\n      [\n        "installer-application-toolchain-source-policy-v144",\n        "plans/amendments/2026-10-10-hyperframes-toolchain-source-v144/hyperframes-toolchain-source-v1.json",\n        "81b9e3655ddb627c46d828690687a1600fd9a7455af4c4fc5a90c32b3991a5d6",\n        7060,\n        "amendment"\n      ],\n      [\n        "installer-application-pep517-backend-sources-v1",\n        "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/application-pep517-backend-source-table-v1.json",\n        "c7d64c6ca0a186437d32b8093df0be0a3dc660fc721172e7ce1a56fd5a87c623",\n        15907,\n        "amendment"\n      ],\n      [\n        "glm52-artifact-metadata-v1",\n        "planning/glm52-artifact-metadata.json",\n        "b42e3fa6fd5c287b95fcda4d370697bd4c0ef226767ddc08fae4e5bebcfecd1a",\n        56232,\n        "baseline"\n      ],\n      [\n        "glm52-upstream-mit-license-cf457fa",\n        "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-upstream-MIT-LICENSE.txt",\n        "f4a18c6ae40b0a8e7d2b7667f52f6e1994e54a46430d2e172b73cb8c9b5eb0d7",\n        1065,\n        "amendment"\n      ],\n      [\n        "glm52-quantized-readme-6bbb01e",\n        "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-quantized-README.md",\n        "85fc4cf947276c376f09ad1226926ebc03eefbb99d184cd05f34412d32d8406b",\n        17468,\n        "amendment"\n      ],\n      [\n        "hermes-agent-health-request-v1",\n        "fixtures/native-health/request.txt",\n        "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c",\n        182,\n        "native-health-fixture"\n      ],\n      [\n        "hermes-agent-health-seed-v1",\n        "fixtures/native-health/seed-value.txt",\n        "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a",\n        67,\n        "native-health-fixture"\n      ],\n      [\n        "hermes-agent-health-expected-result-v1",\n        "fixtures/native-health/expected-tool-result.json",\n        "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a",\n        240,\n        "native-health-fixture"\n      ],\n      [\n        "hermes-agent-health-overlay-read-result-v1",\n        "fixtures/native-health/tool-result.schema.json",\n        "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5",\n        526,\n        "native-health-fixture"\n      ],\n      [\n        "hermes-agent-health-fixture-v1",\n        "fixtures/native-health/recipe.json",\n        "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7",\n        845,\n        "native-health-fixture"\n      ]\n    ],\n    "APPLICATION_BUILD_DRIVER": [\n      "installer-application-environment-builder-v1",\n      "lib/python/hermes_installer/authority/application_environment_builder.py",\n      "8c5aebe61ba3d7e5c9bcf27dfadba8771ed3a4987240ea52fe2189251f1b6e8c",\n      45807,\n      "application-build-driver"\n    ],\n    "REQUIRED_NATIVE_SUPPORT_MODULE_IDS": [\n      "installer-module:hermes_installer.authority.native_assembler",\n      "installer-module:hermes_installer.authority.native_registration_projection",\n      "installer-module:hermes_installer.components.native_plugins",\n      "installer-module:hermes_installer.components.public_registries",\n      "installer-module:hermes_installer.authority.native_definition_composition",\n      "installer-module:hermes_installer.authority.native_policy_preparation",\n      "installer-module:hermes_installer.authority.native_source_definitions",\n      "installer-module:hermes_installer.authority.local_resource_effects"\n    ],\n    "REQUIRED_LAUNCHER_MODULES": [\n      [\n        "installer-module:hermes_installer",\n        "lib/python/hermes_installer/__init__.py"\n      ],\n      [\n        "installer-module:hermes_installer.authority",\n        "lib/python/hermes_installer/authority/__init__.py"\n      ],\n      [\n        "installer-module:hermes_installer.root_setup",\n        "lib/python/hermes_installer/root_setup.py"\n      ],\n      [\n        "installer-module:hermes_installer.authority.installer_release",\n        "lib/python/hermes_installer/authority/installer_release.py"\n      ],\n      [\n        "installer-module:hermes_installer.authority.bootstrap_runtime_factory",\n        "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py"\n      ]\n    ],\n    "LAUNCHER_PATH": "bin/hermes-installer-root-setup",\n    "INTERPRETER_PATH": "runtime/bin/python",\n    "PLAN_PATH": "plans/root-setup-plan-v1.json",\n    "ARTIFACT_CATALOG_PATH": "catalog/artifacts.json",\n    "RELEASE_MEMBER_ROLES": [\n      "amendment",\n      "application-build-driver",\n      "application-effect-fixture",\n      "artifact-catalog",\n      "baseline",\n      "bootstrap-policy",\n      "interpreter",\n      "launcher",\n      "module",\n      "native-health-fixture",\n      "network-startup-helper",\n      "plan",\n      "runtime-member",\n      "source-module",\n      "template"\n    ],\n    "NETWORK_STARTUP_HELPER": [\n      "installer-private-loopback-worker-gate-v180",\n      "helpers/private-loopback-worker-gate.py",\n      "helpers/private-loopback-worker-gate.py",\n      "4bf258da343991920fc80c512975277623d06a96740b073f38b740583d8cb720",\n      20350,\n      "network-startup-helper"\n    ],\n    "APPLICATION_EFFECT_SOURCE_CATALOG_PATH": "plans/amendments/2026-10-10-application-effect-sources-v175/application-effect-sources-v1.json",\n    "APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID": "release-file:eda54c5b908c9d5176afef9ee2bf434b",\n    "APPLICATION_EFFECT_SOURCE_CATALOG_SHA256": "de6df1701fa51727127cdbdb30c6e12a6f4e07297ffce686b758fd3ead1076b4",\n    "APPLICATION_EFFECT_SOURCE_CATALOG_SIZE": 11830,\n    "APPLICATION_EFFECT_SOURCE_MEMBERS": [\n      [\n        "installer-application-effect-graphify-entrypoint-v1",\n        "src/hermes_installer/components/probes/graphify_fixture/entrypoint.py",\n        "source-module",\n        "db0e49e0878f0406d9dba29c9f9860bee2bc7260e59c9ac7e20ecf88b5a03378",\n        153\n      ],\n      [\n        "installer-application-effect-graphify-helper-v1",\n        "src/hermes_installer/components/probes/graphify_fixture/helper.py",\n        "source-module",\n        "acc16fab89297ad11006519103d1033d611b1315529b5614098a3d60c80c2f74",\n        155\n      ],\n      [\n        "installer-application-effect-graphify-result-validator-v1",\n        "src/hermes_installer/components/probes/graphify_result.py",\n        "source-module",\n        "f3f0b44d9d9d707daceee4d563be1d028080ec661c11a29e85e1f38cda0901e9",\n        6481\n      ],\n      [\n        "installer-application-effect-graphify-result-schema-v1",\n        "src/hermes_installer/components/probes/graphify_probe_result.schema.json",\n        "application-effect-fixture",\n        "0649acf5c5e96c629b73e884683df7fe2f98e1fead448c1548f52c22cdd18136",\n        1157\n      ],\n      [\n        "installer-application-effect-browser-use-probe-v1",\n        "src/hermes_installer/components/browser_use_qualification_probe.py",\n        "source-module",\n        "2f939a6cd82f73f4e7474ed7f0c412e9a22fb65df01e7765c1a87cf675a52e58",\n        4404\n      ],\n      [\n        "installer-application-effect-browser-use-result-validator-v1",\n        "src/hermes_installer/components/browser_use.py",\n        "source-module",\n        "2e27c93d701de22792fae24ddb097d3d0dd7424dd5a25ce510ee75fecc90740f",\n        6531\n      ],\n      [\n        "installer-application-effect-scrapegraph-probe-v1",\n        "src/hermes_installer/components/probes/scrapegraph_ai_probe.py",\n        "source-module",\n        "30974c44d2bd9e60847bcad6ba3849cf8b2a262f8c08f79b832a9bba723ed6ab",\n        5446\n      ],\n      [\n        "installer-application-effect-scrapegraph-result-validator-v1",\n        "src/hermes_installer/components/scrapegraph_ai.py",\n        "source-module",\n        "e2ac08afa32b9940705403eb9e2af35b08e21cc6f61ed6731438a6c1c1c98dcb",\n        11891\n      ],\n      [\n        "installer-application-effect-hyperframes-probe-v1",\n        "src/hermes_installer/components/probes/hyperframes_probe.py",\n        "source-module",\n        "f4a63a90b4467ae2db4fcdf7d874bc8f6b75e6b1f02910e326e75fcb49d498aa",\n        12692\n      ],\n      [\n        "installer-application-effect-hyperframes-composition-v1",\n        "src/hermes_installer/components/probes/hyperframes_fixture/composition.html",\n        "application-effect-fixture",\n        "fc20eaf85de0fe9bbc63bf4b315892a4fb0934d19819eb8b9450fa5bb7ed6052",\n        707\n      ]\n    ]\n  },\n  "semantics": "Static data extracted without importing or executing old code. Predecessor-only complete cohort, never current installed actor or candidate pins. Whole historical tuple set, no per-row fallback."\n}\n'
_CC81_COHORT_SHA256 = "32aab0f5eaf5d184dfad3aa6482ee7b17b666bd32d54d180d4aad334db741f5f"
_CC81_COHORT_ID = "installed-predecessor-cc81-review-v249"
_CC81_CANDIDATE = "cc81abffe3cbb1df447889bca269d1e6c0be77ea"


def _historical_cohort(candidate: str) -> Mapping[str, Any] | None:
    value = _historical_cohort_record(candidate)
    if value is None:
        return None
    constants = dict(value["constants"])
    constants["ROLES"] = frozenset(constants["RELEASE_MEMBER_ROLES"])
    return _freeze_review_data(constants)


def _historical_cohort_record(candidate: str) -> Mapping[str, Any] | None:
    if candidate != _CC81_CANDIDATE:
        return None
    raw = _CC81_COHORT_JSON.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != _CC81_COHORT_SHA256:
        raise InstallerReleaseError("historical predecessor source review data failed its fixed digest")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("cohort_id") != _CC81_COHORT_ID
            or value.get("candidate_git_sha") != candidate
            or set(value.get("constants", {})) != {
                "RELEASE_ID", "BASELINE_TAG_OBJECT", "BASELINE_COMMIT", "FIXED_TEMPLATES",
                "REVIEWED_SOURCE_MODULES", "REVIEWED_SOURCE_ARTIFACTS", "APPLICATION_BUILD_DRIVER",
                "REQUIRED_NATIVE_SUPPORT_MODULE_IDS", "REQUIRED_LAUNCHER_MODULES", "LAUNCHER_PATH",
                "INTERPRETER_PATH", "PLAN_PATH", "ARTIFACT_CATALOG_PATH", "RELEASE_MEMBER_ROLES",
                "NETWORK_STARTUP_HELPER", "APPLICATION_EFFECT_SOURCE_CATALOG_PATH",
                "APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID", "APPLICATION_EFFECT_SOURCE_CATALOG_SHA256",
                "APPLICATION_EFFECT_SOURCE_CATALOG_SIZE", "APPLICATION_EFFECT_SOURCE_MEMBERS"}):
        raise InstallerReleaseError("historical predecessor source review data is malformed")
    return _freeze_review_data(value)
_SEAL = object()
_PREDECESSOR_SEAL = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_RECEIPT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}")


class InstallerReleaseError(BootstrapEnrollmentError):
    """Installed release or root actor failed stage-zero verification."""


@dataclass(frozen=True, slots=True)
class VerifiedReleaseFile:
    artifact_id: str
    roles: tuple[str, ...]
    relative_path: str
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int

    @property
    def role(self) -> str:
        """Compatibility convenience; multi-role membership remains explicit."""
        if len(self.roles) != 1:
            raise AttributeError("release file has multiple roles")
        return self.roles[0]


class VerifiedInstallerReleaseReceipt:
    """Sealed proof of one held immutable root deployment release."""
    __slots__ = ("release_root", "release_commit", "deployment_receipt_sha256",
                 "root_device", "root_inode", "closure_manifest_relative_path",
                 "closure_manifest_sha256", "baseline_tag_object", "baseline_commit",
                 "baseline_tree_sha256", "amendment_manifest_sha256", "files",
                 "selected_plan_artifact_id", "selected_plan_sha256", "historical_cohort_id",
                 "historical_cohort_sha256", "_root_fd", "_seal", "_uid", "_closed")

    def __init__(self, seal: object, *, release_root: Path, release_commit: str,
                 deployment_receipt_sha256: str, root_device: int, root_inode: int,
                 closure_manifest_relative_path: str, closure_manifest_sha256: str,
                 baseline_tag_object: str, baseline_commit: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, files: tuple[VerifiedReleaseFile, ...],
                 selected_plan_artifact_id: str, selected_plan_sha256: str,
                 root_fd: int, expected_uid: int, historical_cohort_id: str | None = None,
                 historical_cohort_sha256: str | None = None):
        if seal not in {_SEAL, _PREDECESSOR_SEAL}:
            raise TypeError("release receipts can only be minted by InstalledRootReleaseVerifier")
        self.release_root = release_root
        self.release_commit = release_commit
        self.deployment_receipt_sha256 = deployment_receipt_sha256
        self.root_device, self.root_inode = root_device, root_inode
        self.closure_manifest_relative_path = closure_manifest_relative_path
        self.closure_manifest_sha256 = closure_manifest_sha256
        self.baseline_tag_object, self.baseline_commit = baseline_tag_object, baseline_commit
        self.baseline_tree_sha256, self.amendment_manifest_sha256 = baseline_tree_sha256, amendment_manifest_sha256
        self.files = files
        self.selected_plan_artifact_id, self.selected_plan_sha256 = selected_plan_artifact_id, selected_plan_sha256
        self.historical_cohort_id = historical_cohort_id
        self.historical_cohort_sha256 = historical_cohort_sha256
        self._root_fd, self._seal, self._uid, self._closed = root_fd, seal, expected_uid, False

    def verify_current(self) -> None:
        expected_seal = _PREDECESSOR_SEAL if type(self) is VerifiedInstallerPredecessorReleaseReceipt else _SEAL
        if (type(self) not in {VerifiedInstallerReleaseReceipt, VerifiedInstallerPredecessorReleaseReceipt}
                or self._seal is not expected_seal or self._closed or self._root_fd < 0):
            raise InstallerReleaseError("installer release receipt is not live")
        root = os.fstat(self._root_fd)
        if (root.st_uid != self._uid or not stat.S_ISDIR(root.st_mode)
                or root.st_dev != self.root_device or root.st_ino != self.root_inode
                or stat.S_IMODE(root.st_mode) & 0o222):
            raise InstallerReleaseError("held installer release custody changed")
        for entry in self.files:
            info = _hash_release_file(self._root_fd, entry.relative_path, entry.sha256,
                                      expected_uid=self._uid, expected_size=entry.size_bytes)
            if (info.st_dev != entry.device or info.st_ino != entry.inode
                    or stat.S_IMODE(info.st_mode) != entry.mode):
                raise InstallerReleaseError("held installer release closure changed")

    @property
    def module_closure_sha256(self) -> str:
        rows = {row.relative_path: row.sha256 for row in self.files if "module" in row.roles}
        return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")).hexdigest()

    def open_file(self, artifact_id: str) -> int:
        """Return a no-follow FD for a verified artifact ID in this release."""
        if type(self) is not VerifiedInstallerReleaseReceipt:
            raise InstallerReleaseError("predecessor custody cannot open installed release artifacts")
        self.verify_current()
        matches = [item for item in self.files if item.artifact_id == artifact_id]
        if len(matches) != 1:
            raise InstallerReleaseError("requested release artifact is not uniquely enrolled")
        item = matches[0]
        return _open_verified_fd(self._root_fd, item.relative_path, item.sha256,
                                 expected_uid=self._uid, expected_size=item.size_bytes)

    def resolve_reviewed_source_module(self, artifact_id: str) -> VerifiedReleaseFile:
        """Return the exact held row for a finite target-adapter source module."""
        if type(self) is not VerifiedInstallerReleaseReceipt:
            raise InstallerReleaseError("predecessor custody cannot resolve actor source modules")
        self.verify_current()
        expected = {row[0]: row[1:] for row in REVIEWED_SOURCE_MODULES}
        identity = expected.get(artifact_id)
        if identity is None:
            raise InstallerReleaseError("source module is outside the finite reviewed release set")
        matches = [row for row in self.files if row.artifact_id == artifact_id]
        if len(matches) != 1:
            raise InstallerReleaseError("reviewed source module is absent or ambiguous")
        row = matches[0]
        relative_path, digest, size, role = identity
        if (row.roles != (role,) or row.relative_path != relative_path
                or row.sha256 != digest or row.size_bytes != size):
            raise InstallerReleaseError("reviewed source module differs from its pinned release row")
        return row

    def open_reviewed_source_module(self, artifact_id: str) -> int:
        """Open no-follow bytes for one of the two reviewed target modules."""
        row = self.resolve_reviewed_source_module(artifact_id)
        return _open_verified_fd(self._root_fd, row.relative_path, row.sha256,
                                 expected_uid=self._uid, expected_size=row.size_bytes)

    def resolve_reviewed_source_artifact(self, artifact_id: str) -> VerifiedReleaseFile:
        """Resolve one reviewed source blob to its held baseline/amendment member."""
        if type(self) is not VerifiedInstallerReleaseReceipt:
            raise InstallerReleaseError("predecessor custody cannot resolve actor source artifacts")
        self.verify_current()
        expected = {row[0]: row[1:] for row in REVIEWED_SOURCE_ARTIFACTS}
        identity = expected.get(artifact_id)
        if identity is None:
            raise InstallerReleaseError("source artifact is outside the finite reviewed release set")
        relative_path, digest, size, role = identity
        matches = [row for row in self.files if row.relative_path == relative_path]
        if len(matches) != 1:
            raise InstallerReleaseError("reviewed source artifact member is absent or ambiguous")
        row = matches[0]
        if (row.sha256, row.size_bytes, row.roles) != (digest, size, (role,)):
            raise InstallerReleaseError("reviewed source artifact differs from its held release member")
        return row

    def open_reviewed_source_artifact(self, artifact_id: str) -> int:
        """Open verified bytes for a reviewed catalog source without exposing a path."""
        row = self.resolve_reviewed_source_artifact(artifact_id)
        return _open_verified_fd(self._root_fd, row.relative_path, row.sha256,
                                 expected_uid=self._uid, expected_size=row.size_bytes)

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True

    def __enter__(self) -> "VerifiedInstallerReleaseReceipt":
        self.verify_current()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class VerifiedInstallerPredecessorReleaseReceipt(VerifiedInstallerReleaseReceipt):
    """Distinct sealed custody proof; never an installed root actor receipt."""
    __slots__ = ()


class RootActorObservation:
    """PIDFD-bound observation of the exact installed root setup actor."""
    __slots__ = ("pid", "uid", "gid", "start_time", "launcher", "interpreter",
                 "module_origins", "namespace_inodes", "isolated_import_facts",
                 "_pidfd", "_seal", "_closed")

    def __init__(self, seal: object, *, pid: int, uid: int, gid: int, start_time: int,
                 launcher: tuple[str, int, int, str], interpreter: tuple[str, int, int, str],
                 module_origins: tuple[tuple[str, str, int, int, str], ...],
                 namespace_inodes: tuple[tuple[str, int], ...],
                 isolated_import_facts: tuple[str, ...], pidfd: int):
        if seal is not _SEAL:
            raise TypeError("actor observations can only be minted by InstalledRootReleaseVerifier")
        self.pid, self.uid, self.gid, self.start_time = pid, uid, gid, start_time
        self.launcher, self.interpreter = launcher, interpreter
        self.module_origins, self.namespace_inodes = module_origins, namespace_inodes
        self.isolated_import_facts = isolated_import_facts
        self._pidfd, self._seal, self._closed = pidfd, seal, False

    def verify_current(self, release: VerifiedInstallerReleaseReceipt) -> None:
        if self._seal is not _SEAL or self._closed:
            raise InstallerReleaseError("root actor observation is not live")
        if isinstance(release, VerifiedInstallerPredecessorReleaseReceipt):
            raise InstallerReleaseError("predecessor custody cannot authorize the current root setup actor")
        release.verify_current()
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise InstallerReleaseError("observed root actor has exited")
        if (os.getpid() != self.pid or os.getuid() != self.uid or os.geteuid() != 0
                or os.getgid() != self.gid or _process_start_time(self.pid) != self.start_time
                or self.uid != 0 or self.gid != 0):
            raise InstallerReleaseError("current process identity differs from root actor observation")
        if _namespace_inodes(self.pid) != self.namespace_inodes:
            raise InstallerReleaseError("root actor namespace identity changed")
        for path, device, inode, digest in (self.launcher, self.interpreter):
            _verify_actor_path(Path(path), digest, device, inode)
        try:
            kernel_executable = Path(f"/proc/{self.pid}/exe").resolve(strict=True)
        except OSError:
            raise InstallerReleaseError("kernel executable identity is unavailable") from None
        if kernel_executable != Path(self.interpreter[0]):
            raise InstallerReleaseError("kernel executable differs from pinned setup interpreter")
        for name, module in tuple(sys.modules.items()):
            if name == "hermes_installer" or name.startswith("hermes_installer."):
                origin = getattr(getattr(module, "__spec__", None), "origin", None)
                if origin is None or not any(item[0] == name and item[1] == origin for item in self.module_origins):
                    raise InstallerReleaseError("unreviewed Hermes installer module is loaded")
        for module, origin, device, inode, digest in self.module_origins:
            current = sys.modules.get(module)
            actual_origin = getattr(getattr(current, "__spec__", None), "origin", None)
            if current is None or actual_origin != origin:
                raise InstallerReleaseError("root actor imported module origin changed")
            _verify_actor_path(Path(origin), digest, device, inode)
        current_import_facts = _isolated_import_facts()
        if current_import_facts != self.isolated_import_facts:
            raise InstallerReleaseError("root actor import environment changed")

    def close(self) -> None:
        if not self._closed:
            os.close(self._pidfd)
            self._pidfd, self._closed = -1, True

    def __enter__(self) -> "RootActorObservation":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class InstalledRootReleaseVerifier:
    """Fixed-path, root-only preselection release and actor verifier."""

    @classmethod
    def from_current_root_process(cls) -> tuple[VerifiedInstallerReleaseReceipt, RootActorObservation]:
        if not _linux() or os.getuid() != 0 or os.geteuid() != 0:
            raise BootstrapEnrollmentPending("stage-zero verification requires the installed Linux root process")
        receipt = cls._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH, expected_uid=0)
        release = cls._mint_release(receipt, expected_uid=0)
        actor: RootActorObservation | None = None
        try:
            actor = cls._observe_actor(release)
            actor.verify_current(release)
            return release, actor
        except Exception:
            if actor is not None:
                actor.close()
            release.close()
            raise

    @classmethod
    def verify_installed_release(cls) -> VerifiedInstallerReleaseReceipt:
        """Alias matching the stage-zero deployment contract (root actor included separately)."""
        receipt = cls._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH, expected_uid=0)
        return cls._mint_release(receipt, expected_uid=0)

    @classmethod
    def verify_installed_predecessor_release(cls) -> VerifiedInstallerPredecessorReleaseReceipt:
        """Verify the current fixed release as a predecessor under one exact cohort."""
        receipt = cls._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH, expected_uid=0)
        cohort = _historical_cohort(receipt["candidate_git_sha"])
        if cohort is not None:
            cls._verify_historical_source_cohort(receipt["candidate_git_sha"])
        return cls._mint_release(receipt, expected_uid=0, cohort=cohort, predecessor=True)

    @classmethod
    def _verify_retained_predecessor_bytes(cls, raw: bytes, *, candidate: str,
                                           expected_sha256: str,
                                           expected_uid: int = 0) -> VerifiedInstallerPredecessorReleaseReceipt:
        """Verify exact prior pointer bytes retained by an owned update transaction."""
        if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_RECEIPT_BYTES
                or hashlib.sha256(raw).hexdigest() != expected_sha256
                or not isinstance(candidate, str) or not _COMMIT.fullmatch(candidate)):
            raise InstallerReleaseError("retained predecessor pointer bytes failed their transaction binding")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise InstallerReleaseError("retained predecessor pointer bytes are malformed") from None
        fields = {"schema", "receipt_id", "candidate_git_sha", "release_root", "release_device",
                  "release_inode", "closure_manifest_relative_path", "closure_manifest_sha256",
                  "baseline_tree_sha256", "published_monotonic"}
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8") if isinstance(value, dict) else b""
        if (not isinstance(value, dict) or set(value) != fields or value.get("schema") != 1
                or value.get("candidate_git_sha") != candidate or raw != canonical
                or not isinstance(value.get("receipt_id"), str) or not _RECEIPT_ID.fullmatch(value["receipt_id"])
                or value.get("release_root") != str(RELEASE_STORE_ROOT / candidate)
                or type(value.get("release_device")) is not int
                or value["release_device"] < 0
                or type(value.get("release_inode")) is not int
                or value["release_inode"] <= 0
                or not isinstance(value.get("closure_manifest_sha256"), str)
                or not _SHA.fullmatch(value["closure_manifest_sha256"])
                or not isinstance(value.get("baseline_tree_sha256"), str)
                or not _SHA.fullmatch(value["baseline_tree_sha256"])
                or type(value.get("published_monotonic")) not in (int, float)
                or not math.isfinite(value["published_monotonic"])
                or value["published_monotonic"] <= 0):
            raise InstallerReleaseError("retained predecessor pointer identity is invalid")
        _validate_relative(value["closure_manifest_relative_path"])
        cohort = _historical_cohort(candidate)
        if cohort is not None:
            cls._verify_historical_source_cohort(candidate)
        receipt = MappingProxyType({**value, "_receipt_sha256": expected_sha256})
        return cls._mint_release(receipt, expected_uid=expected_uid, cohort=cohort, predecessor=True)

    @staticmethod
    def _verify_historical_source_cohort(candidate: str) -> None:
        record = _historical_cohort_record(candidate)
        if record is None:
            raise InstallerReleaseError("historical predecessor cohort is not reviewed")
        from .installer_release_build import (
            BASELINE_TREE_SHA256, RootInstallerDistributionRegistry, SOURCE_ORIGIN,
        )
        # The root-owned CAS stores a source export, not a Git worktree. This
        # compares fixed acquisition policy to reviewed provenance; the held
        # complete tree below is the runtime source identity check.
        if SOURCE_ORIGIN != record["source_origin"]:
            raise InstallerReleaseError("historical predecessor fixed-origin policy differs from its review")
        registry = RootInstallerDistributionRegistry()
        try:
            _handle, source = registry.resolve_selected(candidate)
            source.verify_current()
            if (source.candidate_git_sha != candidate
                    or source.git_tree_sha1 != record["source_git_tree"]
                    or source.baseline_tree_sha256 != BASELINE_TREE_SHA256):
                raise InstallerReleaseError("historical predecessor source CAS identity differs from its review")
            tree_entries: dict[str, tuple[int, bytes]] = {}
            for row in source.files:
                fd = source.open_file(row.relative_path)
                try:
                    content_hash = hashlib.sha256()
                    git_hash = hashlib.sha1()
                    git_hash.update(b"blob " + str(row.size_bytes).encode("ascii") + b"\0")
                    size = 0
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        content_hash.update(chunk)
                        git_hash.update(chunk)
                        size += len(chunk)
                    after = os.fstat(fd)
                    if (size != row.size_bytes or content_hash.hexdigest() != row.sha256
                            or not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                            or after.st_uid != 0 or after.st_dev != row.device
                            or after.st_ino != row.inode
                            or stat.S_IMODE(after.st_mode) != row.mode
                            or after.st_ctime_ns != row.ctime_ns
                            or after.st_size != row.size_bytes):
                        raise InstallerReleaseError("historical predecessor source bytes differ from their sealed manifest")
                    if row.mode not in (0o444, 0o555):
                        raise InstallerReleaseError("historical predecessor source mode is not canonical")
                    tree_entries[row.relative_path] = (row.mode, git_hash.digest())
                finally:
                    os.close(fd)
            tree = _git_tree_sha1_from_entries(tree_entries)
            if tree != record["source_git_tree"]:
                raise InstallerReleaseError("historical predecessor complete source tree differs from its review")
            for item in record["source_blobs"]:
                fd = source.open_file(item["relative_path"])
                try:
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        size += len(chunk)
                    if digest.hexdigest() != item["sha256"] or size != item["size_bytes"]:
                        raise InstallerReleaseError("historical predecessor source blob differs from its review")
                finally:
                    os.close(fd)
        finally:
            for held in tuple(getattr(registry, "_receipts", {}).values()):
                held.close()

    @classmethod
    def _load_deployment_receipt(cls, path: Path, *, expected_uid: int) -> Mapping[str, Any]:
        if path != DEPLOYMENT_RECEIPT_PATH:
            raise InstallerReleaseError("deployment receipt path override is forbidden")
        raw, _ = _read_fixed_file(path, MAX_RECEIPT_BYTES, expected_uid, required_mode=0o600)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise InstallerReleaseError("installed release deployment receipt is malformed") from None
        fields = {"schema", "receipt_id", "candidate_git_sha", "release_root", "release_device",
                  "release_inode", "closure_manifest_relative_path", "closure_manifest_sha256",
                  "baseline_tree_sha256", "published_monotonic"}
        if not isinstance(value, dict) or set(value) != fields or value["schema"] != 1:
            raise InstallerReleaseError("installed release deployment receipt has an invalid schema")
        candidate = value["candidate_git_sha"]
        if (not isinstance(candidate, str) or not _COMMIT.fullmatch(candidate)
                or not isinstance(value["receipt_id"], str) or not _RECEIPT_ID.fullmatch(value["receipt_id"])):
            raise InstallerReleaseError("installed release identity is not approved")
        fixed_root = RELEASE_STORE_ROOT / candidate
        if value["release_root"] != str(fixed_root):
            raise InstallerReleaseError("installed release root differs from fixed candidate path")
        if (type(value["release_device"]) is not int or value["release_device"] < 0
                or type(value["release_inode"]) is not int or value["release_inode"] <= 0):
            raise InstallerReleaseError("installed release root identity is malformed")
        for key in ("closure_manifest_sha256", "baseline_tree_sha256"):
            if not isinstance(value[key], str) or not _SHA.fullmatch(value[key]):
                raise InstallerReleaseError("installed release digest is malformed")
        _validate_relative(value["closure_manifest_relative_path"])
        if (type(value["published_monotonic"]) not in (int, float)
                or not math.isfinite(value["published_monotonic"]) or value["published_monotonic"] <= 0):
            raise InstallerReleaseError("installed release publication time is malformed")
        return MappingProxyType({**value, "_receipt_sha256": hashlib.sha256(raw).hexdigest()})

    @classmethod
    def _mint_release(cls, receipt: Mapping[str, Any], *, expected_uid: int,
                      cohort: Mapping[str, Any] | None = None,
                      predecessor: bool = False) -> VerifiedInstallerReleaseReceipt:
        root = Path(receipt["release_root"])
        try:
            _verify_parents(root.parent, expected_uid)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise InstallerReleaseError("deployed release root cannot be opened without following links") from None
        try:
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid
                    or stat.S_IMODE(root_info.st_mode) & 0o222
                    or root_info.st_dev != receipt["release_device"]
                    or root_info.st_ino != receipt["release_inode"]):
                raise InstallerReleaseError("deployed release root custody is unsafe")
            manifest_fd = _open_verified_fd(root_fd, receipt["closure_manifest_relative_path"],
                                            receipt["closure_manifest_sha256"], expected_uid=expected_uid,
                                            maximum=MAX_MANIFEST_BYTES)
            try:
                manifest_bytes = _read_fd_bounded(manifest_fd, MAX_MANIFEST_BYTES)
            finally:
                os.close(manifest_fd)
            manifest_info = os.stat(receipt["closure_manifest_relative_path"], dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_uid != expected_uid
                    or stat.S_IMODE(manifest_info.st_mode) != 0o444 or manifest_info.st_nlink != 1):
                raise InstallerReleaseError("release closure manifest must be immutable root-owned mode 0444")
            manifest = _parse_manifest(manifest_bytes, receipt["candidate_git_sha"])
            rows = _verify_file_rows(root_fd, manifest, expected_uid, cohort=cohort)
            _verify_complete_tree(root_fd, {row.relative_path for row in rows},
                                  receipt["closure_manifest_relative_path"], expected_uid)
            if not secrets.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), receipt["closure_manifest_sha256"]):
                raise InstallerReleaseError("release closure manifest bytes changed")
            baseline_tree = _verify_baseline(root_fd, rows, expected_uid)
            if not secrets.compare_digest(baseline_tree, receipt["baseline_tree_sha256"]):
                raise InstallerReleaseError("frozen baseline tree digest differs from deployment receipt")
            amendment_digest = _amendment_digest(rows)
            plan_id, plan_sha = _fixed_roles(rows, receipt["closure_manifest_relative_path"], cohort=cohort)
            receipt_type = VerifiedInstallerPredecessorReleaseReceipt if predecessor else VerifiedInstallerReleaseReceipt
            seal = _PREDECESSOR_SEAL if predecessor else _SEAL
            return receipt_type(
                seal, release_root=root, release_commit=receipt["candidate_git_sha"],
                deployment_receipt_sha256=receipt["_receipt_sha256"], root_device=root_info.st_dev,
                root_inode=root_info.st_ino,
                closure_manifest_relative_path=receipt["closure_manifest_relative_path"],
                closure_manifest_sha256=receipt["closure_manifest_sha256"],
                baseline_tag_object=_cohort_value(cohort, "BASELINE_TAG_OBJECT"),
                baseline_commit=_cohort_value(cohort, "BASELINE_COMMIT"), baseline_tree_sha256=baseline_tree,
                amendment_manifest_sha256=amendment_digest, files=tuple(rows),
                selected_plan_artifact_id=plan_id, selected_plan_sha256=plan_sha,
                root_fd=root_fd, expected_uid=expected_uid,
                historical_cohort_id=_CC81_COHORT_ID if cohort is not None else None,
                historical_cohort_sha256=_CC81_COHORT_SHA256 if cohort is not None else None)
        except Exception:
            os.close(root_fd)
            raise

    @classmethod
    def _observe_actor(cls, release: VerifiedInstallerReleaseReceipt) -> RootActorObservation:
        if type(release) is not VerifiedInstallerReleaseReceipt:
            raise InstallerReleaseError("predecessor custody cannot authorize the current root setup actor")
        if not hasattr(os, "pidfd_open"):
            raise BootstrapEnrollmentPending("Linux PIDFD support is required for stage-zero setup")
        by_role: dict[str, list[VerifiedReleaseFile]] = {}
        for entry in release.files:
            for role in entry.roles:
                by_role.setdefault(role, []).append(entry)
        launcher, interpreter = by_role["launcher"][0], by_role["interpreter"][0]
        expected_launcher = release.release_root / launcher.relative_path
        expected_interpreter = release.release_root / interpreter.relative_path
        if Path(sys.argv[0]).resolve() != expected_launcher:
            raise InstallerReleaseError("current process is not the installed root setup launcher")
        if Path(sys.executable).resolve() != expected_interpreter:
            raise InstallerReleaseError("current interpreter differs from the installed release")
        # Validate the isolated import environment, then load the complete
        # finite pinned module closure before recording actor origins. This
        # keeps setup and daemon actor snapshots consistent without a lazy
        # post-snapshot import path.
        _isolated_import_facts()
        for _artifact_id, relative_path, _digest, _size, role in REVIEWED_SOURCE_MODULES:
            if role != "module":
                continue
            module_name = _module_name(relative_path)
            try:
                module = importlib.import_module(module_name)
            except Exception:
                raise InstallerReleaseError(
                    "finite reviewed release module could not be preloaded") from None
            expected_origin = str(release.release_root / relative_path)
            if getattr(getattr(module, "__spec__", None), "origin", None) != expected_origin:
                raise InstallerReleaseError(
                    "finite reviewed release module origin differs before actor observation")
        module_rows = [item for item in release.files if "module" in item.roles]
        modules: list[tuple[str, str, int, int, str]] = []
        for item in module_rows:
            module_name = _module_name(item.relative_path)
            module = sys.modules.get(module_name)
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            expected_origin = str(release.release_root / item.relative_path)
            if module is not None and origin == expected_origin:
                modules.append((module_name, origin, item.device, item.inode, item.sha256))
        for artifact_id in REQUIRED_NATIVE_SUPPORT_MODULE_IDS:
            matches = [item for item in module_rows if item.artifact_id == artifact_id
                       and item.roles == ("module",)]
            if len(matches) != 1:
                raise InstallerReleaseError("exact native support module is absent from the release closure")
            item = matches[0]
            module_name = _module_name(item.relative_path)
            module = sys.modules.get(module_name)
            expected_origin = str(release.release_root / item.relative_path)
            if (module is None
                    or getattr(getattr(module, "__spec__", None), "origin", None) != expected_origin
                    or not any(row[0] == module_name and row[1] == expected_origin
                               and row[4] == item.sha256 for row in modules)):
                raise InstallerReleaseError("exact native support module was not imported before actor observation")
        if not modules:
            raise InstallerReleaseError("no imported installer module matches the deployed release closure")
        pid = os.getpid()
        pidfd = os.pidfd_open(pid, 0)
        observation = RootActorObservation(
            _SEAL, pid=pid, uid=os.getuid(), gid=os.getgid(), start_time=_process_start_time(pid),
            launcher=(str(expected_launcher), launcher.device, launcher.inode, launcher.sha256),
            interpreter=(str(expected_interpreter), interpreter.device, interpreter.inode, interpreter.sha256),
            module_origins=tuple(modules), namespace_inodes=_namespace_inodes(pid),
            isolated_import_facts=_isolated_import_facts(), pidfd=pidfd)
        return observation


def _parse_manifest(raw: bytes, candidate: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseError("installed release closure manifest is malformed") from None
    if not isinstance(value, dict) or set(value) != {"schema", "candidate_git_sha", "files"}:
        raise InstallerReleaseError("installed release closure manifest schema is invalid")
    if value["schema"] != 1 or value["candidate_git_sha"] != candidate:
        raise InstallerReleaseError("installed release closure manifest candidate differs")
    rows = value["files"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise InstallerReleaseError("installed release closure manifest file count is invalid")
    paths = [row.get("relative_path") if isinstance(row, dict) else None for row in rows]
    if any(not isinstance(p, str) for p in paths) or paths != sorted(paths) or len(set(paths)) != len(paths):
        raise InstallerReleaseError("installed release closure paths are not sorted and unique")
    return MappingProxyType(value)


def _verify_file_rows(root_fd: int, manifest: Mapping[str, Any], expected_uid: int, *, cohort: Mapping[str, Any] | None = None) -> list[VerifiedReleaseFile]:
    result: list[VerifiedReleaseFile] = []
    for row in manifest["files"]:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode", "roles"}:
            raise InstallerReleaseError("installed release closure file row is malformed")
        path, digest, size, mode, roles = (row[k] for k in ("relative_path", "sha256", "size_bytes", "mode", "roles"))
        _validate_relative(path)
        if (not isinstance(digest, str) or not _SHA.fullmatch(digest)
                or type(size) is not int or size < 0 or size > MAX_FILE_BYTES
                or type(mode) is not int or mode < 0 or mode > 0o7777
                or not isinstance(roles, list) or not roles
                or any(not isinstance(role, str) or role not in _cohort_value(cohort, "ROLES") for role in roles)
                or len(set(roles)) != len(roles) or roles != sorted(roles)):
            raise InstallerReleaseError("installed release closure file metadata is malformed")
        info = _hash_release_file(root_fd, path, digest, expected_uid=expected_uid, expected_size=size)
        if stat.S_IMODE(info.st_mode) != mode:
            raise InstallerReleaseError("installed release file mode differs from closure manifest")
        if path.startswith("plans/2026-10-09-v1/") and "baseline" not in roles:
            raise InstallerReleaseError("frozen baseline file lacks baseline role")
        if path.startswith("plans/amendments/") and "amendment" not in roles:
            raise InstallerReleaseError("append-only amendment lacks amendment role")
        if "amendment" in roles and not path.startswith("plans/amendments/"):
            raise InstallerReleaseError("amendment role is outside append-only amendments")
        _validate_fixed_layout_role(path, digest, size, roles, mode=mode, cohort=cohort)
        artifact_id = _artifact_id_for(path, roles, cohort=cohort)
        result.append(VerifiedReleaseFile(artifact_id, tuple(roles), path, digest, size,
                                          info.st_dev, info.st_ino, mode))
    return result


def _fixed_roles(rows: list[VerifiedReleaseFile], manifest_rel: str, *, cohort: Mapping[str, Any] | None = None) -> tuple[str, str]:
    by_role: dict[str, list[VerifiedReleaseFile]] = {}
    for row in rows:
        for role in row.roles:
            by_role.setdefault(role, []).append(row)
    for role in ("launcher", "interpreter", "runtime-member", "module", "source-module", "template", "plan", "artifact-catalog", "baseline", "amendment", "native-health-fixture", "application-effect-fixture", "application-build-driver"):
        if role not in by_role:
            raise InstallerReleaseError(f"installed release is missing required {role} closure")
    helper_id, _helper_source, helper_path, helper_digest, helper_size, helper_role = _cohort_value(cohort, "NETWORK_STARTUP_HELPER")
    helper_rows = by_role.get(helper_role, [])
    if (helper_digest is None) != (helper_size is None):
        raise InstallerReleaseError("network startup helper review pin is incomplete")
    if helper_digest is None:
        if helper_rows:
            raise InstallerReleaseError("network startup helper source pin is pending final review")
    else:
        if helper_role not in by_role:
            raise InstallerReleaseError("installed release is missing its reviewed network startup helper")
        if (len(helper_rows) != 1 or (helper_rows[0].artifact_id, helper_rows[0].relative_path,
                                      helper_rows[0].sha256, helper_rows[0].size_bytes,
                                      helper_rows[0].mode, helper_rows[0].roles) !=
                (helper_id, helper_path, helper_digest, helper_size, 0o444, (helper_role,))):
            raise InstallerReleaseError("installed network startup helper differs from its exact reviewed member")
    if len(by_role["launcher"]) != 1 or len(by_role["interpreter"]) != 1:
        raise InstallerReleaseError("installed release launcher/interpreter role is ambiguous")
    expected_fixed = {
        "launcher": ("installer-root-setup-launcher-v1", _cohort_value(cohort, "LAUNCHER_PATH")),
        "interpreter": ("installer-root-setup-interpreter-v1", _cohort_value(cohort, "INTERPRETER_PATH")),
        "plan": ("installer-root-setup-plan-v1", _cohort_value(cohort, "PLAN_PATH")),
        "artifact-catalog": ("installer-protected-artifact-catalog-v1", _cohort_value(cohort, "ARTIFACT_CATALOG_PATH")),
    }
    for role, (artifact_id, relative_path) in expected_fixed.items():
        role_rows = by_role[role]
        if len(role_rows) != 1 or (role_rows[0].artifact_id, role_rows[0].relative_path) != (artifact_id, relative_path):
            raise InstallerReleaseError(f"installed {role} role differs from the current fixed release layout")
    expected_templates = {artifact_id: (relative_path, digest, size)
                          for artifact_id, relative_path, digest, size in _cohort_value(cohort, "FIXED_TEMPLATES")}
    actual_templates = {row.artifact_id: (row.relative_path, row.sha256, row.size_bytes)
                        for row in by_role["template"]}
    if actual_templates != expected_templates or len(by_role["template"]) != len(_cohort_value(cohort, "FIXED_TEMPLATES")):
        raise InstallerReleaseError("installed templates differ from the current fixed artifact layout")
    expected_health_fixtures = {artifact_id: (relative_path, digest, size)
                                for artifact_id, relative_path, digest, size, role in _cohort_value(cohort, "REVIEWED_SOURCE_ARTIFACTS")
                                if role == "native-health-fixture"}
    actual_health_fixtures = {row.artifact_id: (row.relative_path, row.sha256, row.size_bytes)
                              for row in by_role["native-health-fixture"]}
    if (actual_health_fixtures != expected_health_fixtures
            or len(by_role["native-health-fixture"]) != len(expected_health_fixtures)):
        raise InstallerReleaseError("installed native health fixtures differ from their exact reviewed closure")
    effect_catalog_rows = [row for row in by_role["amendment"]
                           if row.artifact_id == _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID")]
    if (len(effect_catalog_rows) != 1
            or (effect_catalog_rows[0].relative_path, effect_catalog_rows[0].sha256,
                effect_catalog_rows[0].size_bytes) != (_cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_CATALOG_PATH"),
                    _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_CATALOG_SHA256"), _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_CATALOG_SIZE"))):
        raise InstallerReleaseError("application effect source descriptor differs from its fixed amendment pin")
    if any("bootstrap-policy" in row.roles for row in rows):
        raise InstallerReleaseError("generated bootstrap policy cannot be a base release role")
    modules = [row for row in by_role["module"]]
    if not modules or any(row.artifact_id != _artifact_id_for(row.relative_path, ["module"], cohort=cohort)
                          for row in modules):
        raise InstallerReleaseError("installed module IDs differ from the finite source/import mapping")
    module_by_id = {row.artifact_id: row for row in modules}
    source_module_by_id = {row.artifact_id: row for row in by_role["source-module"]}
    _verify_reviewed_module_rows(module_by_id, source_module_by_id, cohort=cohort)
    driver_id, driver_path, driver_digest, driver_size, driver_role = _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")
    driver_rows = by_role[driver_role]
    if (len(driver_rows) != 1 or (driver_rows[0].artifact_id, driver_rows[0].relative_path,
                                  driver_rows[0].sha256, driver_rows[0].size_bytes,
                                  driver_rows[0].roles) !=
            (driver_id, driver_path, driver_digest, driver_size, (driver_role,))):
        raise InstallerReleaseError("application build driver differs from its exact execution-only closure")
    for artifact_id, relative_path, role, digest, size in _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_MEMBERS"):
        rows_for_member = [row for row in rows if row.artifact_id == artifact_id]
        if (len(rows_for_member) != 1 or rows_for_member[0].roles != (role,)
                or (rows_for_member[0].relative_path, rows_for_member[0].sha256,
                    rows_for_member[0].size_bytes) != (relative_path, digest, size)):
            raise InstallerReleaseError("application effect source member differs from its finite pinned role catalog")
    for artifact_id, relative_path in _cohort_value(cohort, "REQUIRED_LAUNCHER_MODULES"):
        row = module_by_id.get(artifact_id)
        if row is None or row.relative_path != relative_path:
            raise InstallerReleaseError("installed launcher module closure is incomplete or misbound")
    runtime_members = by_role["runtime-member"]
    if not runtime_members or any(
            row.relative_path == _cohort_value(cohort, "INTERPRETER_PATH") or not row.relative_path.startswith("runtime/")
            or row.mode not in {0o444, 0o555} for row in runtime_members):
        raise InstallerReleaseError("installed runtime-member closure is missing or has unsafe roles/modes")
    plan = by_role["plan"]
    if len(plan) != 1:
        raise InstallerReleaseError("installed root setup plan is absent or ambiguous")
    if any(row.relative_path == manifest_rel for row in rows):
        raise InstallerReleaseError("closure manifest cannot include itself")
    for row in by_role["launcher"] + by_role["interpreter"]:
        if not row.mode & 0o111:
            raise InstallerReleaseError("installed launcher/interpreter is not executable")
    return plan[0].artifact_id, plan[0].sha256


def _verify_reviewed_module_rows(module_by_id: Mapping[str, VerifiedReleaseFile],
                                 source_module_by_id: Mapping[str, VerifiedReleaseFile], *,
                                 cohort: Mapping[str, Any] | None = None) -> None:
    for artifact_id, relative_path, digest, size, role in _cohort_value(cohort, "REVIEWED_SOURCE_MODULES"):
        row = (source_module_by_id if role == "source-module" else module_by_id).get(artifact_id)
        if (row is None or row.roles != (role,)
                or (row.relative_path, row.sha256, row.size_bytes) != (relative_path, digest, size)):
            raise InstallerReleaseError("finite native target source module differs from its reviewed pin")


def _verify_complete_tree(root_fd: int, listed: set[str], manifest_path: str, expected_uid: int) -> None:
    expected = listed | {manifest_path}
    found: set[str] = set()
    device = os.fstat(root_fd).st_dev

    def walk(directory_fd: int, prefix: str) -> None:
        scan_fd = os.dup(directory_fd)
        try:
            with os.scandir(scan_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if name in {".", ".."} or "/" in name:
                        raise InstallerReleaseError("release directory contains an invalid entry name")
                    rel = f"{prefix}/{name}" if prefix else name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        raise InstallerReleaseError("release tree contains a symlink")
                    if stat.S_ISDIR(info.st_mode):
                        if (info.st_uid != expected_uid or info.st_dev != device
                                or stat.S_IMODE(info.st_mode) & 0o222):
                            raise InstallerReleaseError("release tree directory custody is unsafe")
                        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=directory_fd)
                        try:
                            walk(child_fd, rel)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_uid != expected_uid or info.st_dev != device or info.st_nlink != 1:
                            raise InstallerReleaseError("release tree file custody is unsafe")
                        found.add(rel)
                    else:
                        raise InstallerReleaseError("release tree contains a special file")
        except OSError:
            raise InstallerReleaseError("release tree cannot be enumerated safely") from None
        finally:
            os.close(scan_fd)

    walk(root_fd, "")
    if found != expected:
        raise InstallerReleaseError("release manifest is not the complete installed file closure")


def _verify_baseline(root_fd: int, rows: list[VerifiedReleaseFile], expected_uid: int) -> str:
    prefix = "plans/2026-10-09-v1/"
    baseline = {row.relative_path[len(prefix):]: row.sha256 for row in rows
                if row.relative_path.startswith(prefix)}
    if "hashes.json" not in baseline:
        raise InstallerReleaseError("frozen baseline hashes manifest is missing")
    row = next(item for item in rows if item.relative_path == prefix + "hashes.json")
    if "baseline" not in row.roles:
        raise InstallerReleaseError("frozen baseline manifest lacks baseline role")
    fd = _open_verified_fd(root_fd, row.relative_path, row.sha256, expected_uid=expected_uid,
                           expected_size=row.size_bytes, maximum=8 * 1024 * 1024)
    try:
        hashes = _parse_json_fd(fd, 8 * 1024 * 1024)
    finally:
        os.close(fd)
    if (not isinstance(hashes, dict) or hashes.get("schema_version") != 1
            or hashes.get("algorithm") != "sha256"
            or hashes.get("baseline_tag") != "hermes-installer-plan-2026-10-09-v1"
            or not isinstance(hashes.get("files"), dict)):
        raise InstallerReleaseError("frozen baseline hashes.json does not match the protected tag")
    if not set(hashes["files"]).issubset(baseline):
        raise InstallerReleaseError("frozen baseline snapshot coverage is incomplete")
    for repo_path, digest in hashes["files"].items():
        if not _safe_relative(repo_path) or not isinstance(digest, str) or not _SHA.fullmatch(digest):
            raise InstallerReleaseError("frozen baseline snapshot row is malformed")
        entry = baseline.get(repo_path)
        if entry != digest:
            raise InstallerReleaseError("release baseline bytes disagree with frozen hashes.json")
    tree = hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()
    return tree


def _amendment_digest(rows: list[VerifiedReleaseFile]) -> str:
    selected = {row.relative_path: row.sha256 for row in rows if "amendment" in row.roles}
    if not selected:
        raise InstallerReleaseError("installed release has no reviewed amendment closure")
    return hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False).encode("utf-8")).hexdigest()


def _artifact_id_for(path: str, roles: list[str], *, cohort: Mapping[str, Any] | None = None) -> str:
    if "application-build-driver" in roles and path == _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[1]:
        return _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[0]
    helper_id, _helper_source, helper_path, _helper_digest, _helper_size, helper_role = _cohort_value(cohort, "NETWORK_STARTUP_HELPER")
    if helper_role in roles:
        if roles != [helper_role] or path != helper_path:
            raise InstallerReleaseError("network startup helper ID requires its one exact fixed member")
        return helper_id
    if "launcher" in roles:
        return "installer-root-setup-launcher-v1"
    if "interpreter" in roles:
        return "installer-root-setup-interpreter-v1"
    if "template" in roles:
        for artifact_id, relative_path, _digest, _size in _cohort_value(cohort, "FIXED_TEMPLATES"):
            if path == relative_path:
                return artifact_id
    if "plan" in roles:
        return "installer-root-setup-plan-v1"
    if "artifact-catalog" in roles and path == _cohort_value(cohort, "ARTIFACT_CATALOG_PATH"):
        return "installer-protected-artifact-catalog-v1"
    if "native-health-fixture" in roles:
        for artifact_id, relative_path, _digest, _size, role in _cohort_value(cohort, "REVIEWED_SOURCE_ARTIFACTS"):
            if role == "native-health-fixture" and path == relative_path:
                return artifact_id
    if "module" in roles:
        for artifact_id, relative_path, _digest, _size, role in _cohort_value(cohort, "REVIEWED_SOURCE_MODULES"):
            if role == "module" and path == relative_path:
                return artifact_id
        return "installer-module:" + _module_name(path)
    if "source-module" in roles:
        for artifact_id, relative_path, _digest, _size, role in _cohort_value(cohort, "REVIEWED_SOURCE_MODULES"):
            if role == "source-module" and path == relative_path:
                return artifact_id
        for artifact_id, relative_path, role, _digest, _size in _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_MEMBERS"):
            if role == "source-module" and path == relative_path:
                return artifact_id
    if "application-effect-fixture" in roles:
        for artifact_id, relative_path, role, _digest, _size in _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_MEMBERS"):
            if role == "application-effect-fixture" and path == relative_path:
                return artifact_id
    return "release-file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:32]


def _validate_fixed_layout_role(path: str, digest: str, size: int, roles: list[str],
                                *, mode: int | None = None,
                                cohort: Mapping[str, Any] | None = None) -> None:
    fixed_paths = {
        _cohort_value(cohort, "LAUNCHER_PATH"): ("launcher", "installer-root-setup-launcher-v1"),
        _cohort_value(cohort, "INTERPRETER_PATH"): ("interpreter", "installer-root-setup-interpreter-v1"),
        _cohort_value(cohort, "PLAN_PATH"): ("plan", "installer-root-setup-plan-v1"),
        _cohort_value(cohort, "ARTIFACT_CATALOG_PATH"): ("artifact-catalog", "installer-protected-artifact-catalog-v1"),
    }
    fixed_templates = {relative_path: (artifact_id, expected_digest, expected_size)
                       for artifact_id, relative_path, expected_digest, expected_size in _cohort_value(cohort, "FIXED_TEMPLATES")}
    expected_fixed_role = fixed_paths.get(path)
    helper_id, _helper_source, helper_path, helper_digest, helper_size, helper_role = _cohort_value(cohort, "NETWORK_STARTUP_HELPER")
    if path == helper_path or helper_role in roles:
        if (roles != [helper_role] or path != helper_path
                or helper_digest is None or helper_size is None
                or not isinstance(helper_digest, str)
                or not _SHA.fullmatch(helper_digest)
                or type(helper_size) is not int or helper_size <= 0
                or (digest, size) != (helper_digest, helper_size)
                or (mode is not None and mode != 0o444)):
            raise InstallerReleaseError("network startup helper differs from its reviewed read-only member")
    if expected_fixed_role is not None and roles != [expected_fixed_role[0]]:
        raise InstallerReleaseError("fixed release artifact must carry only its exact role")
    role_paths = {role: relative_path for relative_path, (role, _artifact_id) in fixed_paths.items()}
    for role, expected_path in role_paths.items():
        if role in roles and path != expected_path:
            raise InstallerReleaseError(f"installed {role} role path differs from the fixed release layout")
    if path in fixed_templates and roles != ["template"]:
        raise InstallerReleaseError("fixed release template must carry only its template role")
    if "template" in roles and roles != ["template"]:
        raise InstallerReleaseError("template closure files must carry only the template role")
    if path.startswith("templates/") and path not in fixed_templates:
        raise InstallerReleaseError("release contains an unrecognized installed template path")
    if path.startswith("lib/python/") and roles != ["module"] and not (
            path == _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[1] and roles == ["application-build-driver"]):
        raise InstallerReleaseError("lib/python release files must have the exact module role")
    if path == _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[1] and "module" in roles:
        raise InstallerReleaseError("execution-only application build driver cannot be an actor module")
    if "application-build-driver" in roles:
        if (roles != [_cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[4]] or path != _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[1]
                or (digest, size) != (_cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[2], _cohort_value(cohort, "APPLICATION_BUILD_DRIVER")[3])
                or (mode is not None and mode != 0o444)):
            raise InstallerReleaseError("application build driver differs from its exact execution-only pin")
    if "module" in roles and not (path.startswith("lib/python/")
                                  or path in {item[1] for item in _cohort_value(cohort, "REVIEWED_SOURCE_MODULES") if item[4] == "module"}):
        raise InstallerReleaseError("module role is outside the finite source/import closure")
    if "source-module" in roles:
        expected_source_modules = {
            relative_path: (digest, size)
            for _artifact_id, relative_path, digest, size, role in _cohort_value(cohort, "REVIEWED_SOURCE_MODULES")
            if role == "source-module"
        }
        expected_source_modules.update({
            relative_path: (digest, size)
            for _artifact_id, relative_path, role, digest, size in _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_MEMBERS")
            if role == "source-module"
        })
        if (roles != ["source-module"] or path not in expected_source_modules
                or (digest, size) != expected_source_modules[path]
                or (mode is not None and mode != 0o444)):
            raise InstallerReleaseError("source-module role differs from its exact reviewed source member")
    if "application-effect-fixture" in roles:
        expected_effect_fixtures = {
            relative_path: (digest, size)
            for _artifact_id, relative_path, role, digest, size in _cohort_value(cohort, "APPLICATION_EFFECT_SOURCE_MEMBERS")
            if role == "application-effect-fixture"
        }
        if (roles != ["application-effect-fixture"]
                or path not in expected_effect_fixtures
                or (digest, size) != expected_effect_fixtures[path]
                or (mode is not None and mode != 0o444)):
            raise InstallerReleaseError(
                "application effect fixture differs from its exact reviewed data member")
    if path.startswith("runtime/") and path != _cohort_value(cohort, "INTERPRETER_PATH") and roles != ["runtime-member"]:
        raise InstallerReleaseError("installed runtime closure member lacks its exact runtime-member role")
    if "runtime-member" in roles and (
            roles != ["runtime-member"] or not path.startswith("runtime/") or path == _cohort_value(cohort, "INTERPRETER_PATH")):
        raise InstallerReleaseError("runtime-member role is outside the selected runtime closure")
    if "runtime-member" in roles and mode is not None and mode not in {0o444, 0o555}:
        raise InstallerReleaseError("runtime-member mode is outside the sealed runtime mode set")
    if "native-health-fixture" in roles:
        expected = {path: (artifact_id, digest, size)
                    for artifact_id, path, digest, size, role in _cohort_value(cohort, "REVIEWED_SOURCE_ARTIFACTS")
                    if role == "native-health-fixture"}
        if (roles != ["native-health-fixture"] or path not in expected
                or (digest, size) != (expected[path][1], expected[path][2])):
            raise InstallerReleaseError("native health fixture role differs from its exact reviewed data member")
    if path.startswith("plans/2026-10-09-v1/") and roles != ["baseline"]:
        raise InstallerReleaseError("frozen baseline files must carry only their baseline role")
    if "baseline" in roles and not path.startswith("plans/2026-10-09-v1/"):
        raise InstallerReleaseError("baseline role is outside the frozen baseline tree")
    if path.startswith("plans/amendments/") and roles != ["amendment"]:
        raise InstallerReleaseError("append-only amendment source files must carry only their amendment role")
    if expected_fixed_role is not None and _artifact_id_for(path, roles, cohort=cohort) != expected_fixed_role[1]:
        raise InstallerReleaseError("fixed release artifact ID differs from its exact path role")
    if roles == ["template"]:
        if not any(path == item[1] and digest == item[2] and size == item[3]
                   for item in _cohort_value(cohort, "FIXED_TEMPLATES")):
            raise InstallerReleaseError("installed template bytes differ from their exact protected role pin")
    if "module" in roles:
        _module_name(path)
    if "bootstrap-policy" in roles:
        raise InstallerReleaseError("generated bootstrap policy is not part of the deployed base release")


def _read_fixed_file(path: Path, maximum: int, expected_uid: int, *, required_mode: int | None = None) -> tuple[bytes, os.stat_result]:
    if path != DEPLOYMENT_RECEIPT_PATH:
        raise InstallerReleaseError("deployment receipt path override is forbidden")
    try:
        _verify_parents(path.parent, expected_uid)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseError("installed release deployment receipt is unavailable") from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_nlink != 1
                or before.st_size > maximum or stat.S_IMODE(before.st_mode) != required_mode):
            raise InstallerReleaseError("installed release deployment receipt custody is unsafe")
        raw = _read_fd_bounded(fd, maximum)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise InstallerReleaseError("installed release deployment receipt changed while reading")
        return raw, before
    finally:
        os.close(fd)


def _read_fd_bounded(fd: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, min(65536, maximum - total + 1))
        if not block:
            break
        chunks.append(block); total += len(block)
        if total > maximum:
            raise InstallerReleaseError("installed release metadata exceeds byte limit")
    return b"".join(chunks)


def _verify_parents(path: Path, expected_uid: int) -> None:
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        info = os.lstat(cursor)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022):
            raise InstallerReleaseError("deployment receipt parent directory custody is unsafe")


def _hash_release_file(root_fd: int, relative: str, expected: str, *, expected_uid: int,
                       expected_size: int | None = None) -> os.stat_result:
    fd = _open_verified_fd(root_fd, relative, expected, expected_uid=expected_uid,
                           expected_size=expected_size, maximum=MAX_FILE_BYTES)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _open_verified_fd(root_fd: int, relative: str, expected: str, *, expected_uid: int,
                      expected_size: int | None = None, maximum: int = MAX_FILE_BYTES) -> int:
    _validate_relative(relative)
    if not _SHA.fullmatch(expected):
        raise InstallerReleaseError("deployed release digest is malformed")
    root_info = os.fstat(root_fd)
    parent = os.dup(root_fd)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_dev != root_info.st_dev or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                raise InstallerReleaseError("deployed release parent directory is unsafe")
            os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError:
        raise InstallerReleaseError("deployed release path cannot be opened without following links") from None
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_nlink != 1
                or before.st_dev != root_info.st_dev or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_size > maximum or (expected_size is not None and before.st_size != expected_size)):
            raise InstallerReleaseError("deployed release file custody or size is unsafe")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or not secrets.compare_digest(digest.hexdigest(), expected)):
            raise InstallerReleaseError("deployed release file bytes or inode differ from receipt")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise


def _verify_actor_path(path: Path, digest: str, device: int, inode: int) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseError("observed actor executable/module cannot be opened safely") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022
                or info.st_dev != device or info.st_ino != inode):
            raise InstallerReleaseError("observed actor executable/module identity changed")
        digestor = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digestor.update(chunk)
        if digestor.hexdigest() != digest:
            raise InstallerReleaseError("observed actor executable/module bytes changed")
    finally:
        os.close(fd)


def _module_name(relative: str) -> str:
    source_names = {
        "src/hermes_installer/components/native_plugins.py": "hermes_installer.components.native_plugins",
        "src/hermes_installer/components/public_registries.py": "hermes_installer.components.public_registries",
        "src/hermes_installer/native_invocations.py": "hermes_installer.native_invocations",
        "src/hermes_installer/native_boundary.py": "hermes_installer.native_boundary",
        "lib/python/hermes_installer/authority/native_source_definitions.py":
            "hermes_installer.authority.native_source_definitions",
    }
    if relative in source_names:
        return source_names[relative]
    prefix = "lib/python/"
    if not relative.startswith(prefix) or not relative.endswith(".py"):
        raise InstallerReleaseError("installer module closure path is outside the fixed lib/python tree")
    subpath = relative[len(prefix):-3]
    if subpath == "__init__":
        raise InstallerReleaseError("installer module closure has a root package initializer")
    if subpath.endswith("/__init__"):
        subpath = subpath[:-9]
    result = subpath.replace("/", ".")
    if not result or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part)
                         for part in result.split(".")):
        raise InstallerReleaseError("installer module closure name is malformed")
    return result


def _isolated_import_facts() -> tuple[str, ...]:
    if (os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME")
            or not sys.flags.no_user_site or sys.flags.isolated == 0
            or any(not isinstance(entry, str) or not entry or not Path(entry).is_absolute() for entry in sys.path)):
        raise InstallerReleaseError("root setup Python import environment is not isolated")
    paths = tuple(os.path.realpath(entry) for entry in sys.path)
    for entry in paths:
        _verify_import_search_path(Path(entry))
    if os.path.realpath(os.getcwd()) in paths:
        raise InstallerReleaseError("root setup current directory is an import path")
    return paths


def _namespace_inodes(pid: int) -> tuple[tuple[str, int], ...]:
    values = []
    try:
        for name in ("mnt", "pid", "user", "net", "ipc", "uts"):
            values.append((name, os.stat(f"/proc/{pid}/ns/{name}").st_ino))
    except OSError:
        raise BootstrapEnrollmentPending("root actor namespaces cannot be observed") from None
    return tuple(values)


def _parse_json_fd(fd: int, maximum: int) -> Any:
    try:
        return json.loads(_read_fd_bounded(fd, maximum).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseError("protected JSON artifact is malformed") from None


def _validate_relative(value: Any) -> None:
    if (not isinstance(value, str) or not 0 < len(value) <= 1024 or value.startswith("/")
            or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise InstallerReleaseError("deployed release path is not a portable normalized relative path")


def _git_tree_sha1_from_entries(entries: Mapping[str, tuple[int, bytes]]) -> str:
    """Reconstruct a complete Git tree from rehashed source-CAS blobs and modes."""
    root: dict[str, Any] = {}
    folded: set[str] = set()
    components: dict[str, str] = {}
    for path, (mode, blob_oid) in entries.items():
        _validate_relative(path)
        if mode not in (0o444, 0o555) or not isinstance(blob_oid, bytes) or len(blob_oid) != 20:
            raise InstallerReleaseError("historical source tree entry is malformed")
        if path.casefold() in folded:
            raise InstallerReleaseError("historical source tree has portable path collisions")
        folded.add(path.casefold())
        node = root
        parts = path.split("/")
        prefix: list[str] = []
        for part in parts:
            prefix.append(part)
            key = "/".join(prefix).casefold()
            previous = components.setdefault(key, "/".join(prefix))
            if previous != "/".join(prefix):
                raise InstallerReleaseError("historical source tree has portable directory collisions")
        for part in parts[:-1]:
            existing = node.get(part)
            if existing is None:
                existing = {}
                node[part] = existing
            if not isinstance(existing, dict):
                raise InstallerReleaseError("historical source tree has a file-directory collision")
            node = existing
        leaf = parts[-1]
        if leaf in node:
            raise InstallerReleaseError("historical source tree has duplicate paths")
        node[leaf] = (mode, blob_oid)

    def hash_directory(directory: dict[str, Any]) -> bytes:
        serialized: list[tuple[bytes, bytes]] = []
        for name, item in directory.items():
            encoded = name.encode("utf-8", "strict")
            if isinstance(item, dict):
                mode, oid, sort_name = b"40000", hash_directory(item), encoded + b"/"
            else:
                source_mode, oid = item
                mode, sort_name = (b"100755" if source_mode == 0o555 else b"100644"), encoded
            serialized.append((sort_name, mode + b" " + encoded + b"\0" + oid))
        body = b"".join(raw for _, raw in sorted(serialized, key=lambda entry: entry[0]))
        return hashlib.sha1(b"tree " + str(len(body)).encode("ascii") + b"\0" + body).digest()

    if not root:
        raise InstallerReleaseError("historical source tree is empty")
    return hash_directory(root).hex()


def _safe_relative(value: Any) -> bool:
    try:
        _validate_relative(value)
        return True
    except InstallerReleaseError:
        return False


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _linux() -> bool:
    return sys.platform.startswith("linux") and Path("/proc/self/status").exists()
