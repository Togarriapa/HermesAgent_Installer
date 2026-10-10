"""Root-owned source acquisition and sealed installer-release build inputs.

This module is deliberately separate from ``installer_release``: that module
verifies an already published release.  This one obtains the next candidate's
source before publication and never treats a source digest as an executable
digest.  Filesystem paths are fixed module policy, not caller parameters.
"""
from __future__ import annotations

import hashlib
import fcntl
import importlib.metadata
import io
import json
import os
import platform
import posixpath
import re
import secrets
import stat
import subprocess
import sys
import sysconfig
import tarfile
import time
import threading
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from .application_effect_source_catalog import APPLICATION_EFFECT_SOURCE_MEMBERS
from .application_effect_source_catalog import (
    APPLICATION_EFFECT_SOURCE_CATALOG_PATH, APPLICATION_EFFECT_SOURCE_CATALOG_SHA256,
    APPLICATION_EFFECT_SOURCE_CATALOG_SIZE,
)
from .installer_release_roles import NETWORK_STARTUP_HELPER, RELEASE_MEMBER_ROLES


SOURCE_ORIGIN = "https://github.com/Togarriapa/HermesAgent_Installer.git"
CANDIDATE_CAS_ROOT = Path("/var/lib/hermes-installer/source-cas/installer")
BUILD_CAS_ROOT = Path("/var/lib/hermes-installer/authority-journal/release-build-cas")
BASELINE_DIRECTORY = "plans/2026-10-09-v1"
BASELINE_TAG = "hermes-installer-plan-2026-10-09-v1"
BASELINE_TAG_OBJECT = "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
BASELINE_COMMIT = "653ac5fbc7a02613c9951859a7d794599603459b"
BASELINE_TREE_SHA256 = "039a6ab93f6bd44d80df01e99368c24c4348624305b6f4d17816eed25a167ade"
PLAN_TEMPLATE_PATH = "plans/amendments/2026-10-10-closed-root-plan-template-selection-v81/root-setup-plan-template-v1.json"
PLAN_TEMPLATE_ID = "installer-root-setup-plan-template-v1"
PLAN_TEMPLATE_SHA256 = "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5"
PLAN_TEMPLATE_BYTES = 920
COMPILER_TEMPLATE_PATH = "plans/amendments/2026-10-09-closed-bootstrap-compiler-template-v30/bootstrap-compiler-template-v1.json"
COMPILER_TEMPLATE_ID = "installer-bootstrap-compiler-template-v1"
COMPILER_TEMPLATE_SHA256 = "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5"
COMPILER_TEMPLATE_BYTES = 4281
IDENTITY_TEMPLATE_PATH = "plans/amendments/2026-10-09-authentik-template-actor-api-v49/authentik-policy-template-v1.json"
IDENTITY_TEMPLATE_ID = "installer-authentik-policy-template-v1"
IDENTITY_TEMPLATE_SHA256 = "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8"
IDENTITY_TEMPLATE_BYTES = 261
PREPARED_BASE_TEMPLATE_PATH = "plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63/prepared-authority-base-template-v1.json"
PREPARED_BASE_TEMPLATE_ID = "installer-prepared-authority-base-template-v1"
PREPARED_BASE_TEMPLATE_SHA256 = "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953"
PREPARED_BASE_TEMPLATE_BYTES = 369
RECEIPT_BINDINGS_TEMPLATE_PATH = "plans/amendments/2026-10-10-literal-bootstrap-receipt-bindings-v72/bootstrap-receipt-bindings-template-v1.json"
RECEIPT_BINDINGS_TEMPLATE_ID = "installer-bootstrap-receipt-bindings-template-v1"
RECEIPT_BINDINGS_TEMPLATE_SHA256 = "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609"
RECEIPT_BINDINGS_TEMPLATE_BYTES = 10_195
COMPOSIO_POLICY_TEMPLATE_PATH = "plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63/composio-whatsapp-catalog-read-policy-v1.json"
COMPOSIO_POLICY_TEMPLATE_ID = "installer-composio-whatsapp-catalog-read-policy-v1"
COMPOSIO_POLICY_TEMPLATE_SHA256 = "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5"
COMPOSIO_POLICY_TEMPLATE_BYTES = 528
EXISTING_MODEL_STORE_TEMPLATE_PATH = (
    "plans/amendments/2026-10-10-existing-model-store-selection-source-v139/"
    "existing-model-store-root-template-v1.json")
EXISTING_MODEL_STORE_TEMPLATE_ID = "installer-existing-model-store-root-template-v1"
EXISTING_MODEL_STORE_TEMPLATE_SHA256 = "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f"
EXISTING_MODEL_STORE_TEMPLATE_BYTES = 712
PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH = (
    "plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97/"
    "private-loopback-policy-v1.json")
PRIVATE_LOOPBACK_POLICY_TEMPLATE_ID = "installer-private-loopback-nft-v1"
PRIVATE_LOOPBACK_POLICY_TEMPLATE_SHA256 = "77a48f3a31f115693b04245146158e3c2467f297ff14746a52375850d76237cc"
PRIVATE_LOOPBACK_POLICY_TEMPLATE_BYTES = 1_482
REVIEWED_SOURCE_MODULES = (
    ("hermes_installer.authority.active_native_worker_runtime", "src/hermes_installer/authority/active_native_worker_runtime.py", "lib/python/hermes_installer/authority/active_native_worker_runtime.py",
     "5196a3206cb5a09daef5eb51cb4ef70d812f4d02a85073e2fc67bf8d1ba783e4", 38_660, "module"),
    ("hermes_installer.authority.active_network_generation", "src/hermes_installer/authority/active_network_generation.py", "lib/python/hermes_installer/authority/active_network_generation.py",
     "143ba59f13316f6a66315aed7193a66e4c2e4d6a7b8d03963a3244735fd44f70", 23_570, "module"),
    ("hermes_installer.authority.active_policy_compiler", "src/hermes_installer/authority/active_policy_compiler.py", "lib/python/hermes_installer/authority/active_policy_compiler.py",
     "61ae3576ac53e5ad5c6f1b0c74967110021fd961677353aae889b9f8bf04940b", 136_868, "module"),
    ("hermes_installer.authority.application_runtime_archive", "src/hermes_installer/authority/application_runtime_archive.py", "lib/python/hermes_installer/authority/application_runtime_archive.py",
     "3117c4c706bfcffe6626c57c79934b143c36d8cd75758dd1198c2020286c2197", 31_457, "module"),
    ("hermes_installer.authority.application_runtime_relocation", "src/hermes_installer/authority/application_runtime_relocation.py", "lib/python/hermes_installer/authority/application_runtime_relocation.py",
     "9b426e61480613c9e10aeaa4227aaff6d06a5558000b45cb94fb0d0160e47afc", 12_120, "module"),
    ("hermes_installer.authority.bootstrap_enrollment", "src/hermes_installer/authority/bootstrap_enrollment.py", "lib/python/hermes_installer/authority/bootstrap_enrollment.py",
     "6c258e92423acffe802ce4670788d9d950f2b4848085b5aa4301db749b7439e6", 141_309, "module"),
    ("hermes_installer.authority.bootstrap_runtime_factory", "src/hermes_installer/authority/bootstrap_runtime_factory.py", "lib/python/hermes_installer/authority/bootstrap_runtime_factory.py",
     "89fae27c0b8b4eeabc0c43ba0d56baa2780bc62e390a63cc6db8b1f88b028ead", 655_738, "module"),
    ("hermes_installer.authority.client", "src/hermes_installer/authority/client.py", "lib/python/hermes_installer/authority/client.py",
     "f8be053e3a00b49087c6104ed77a314a071c8b0a47cf9701c4050b7aae13b46f", 73_488, "module"),
    ("hermes_installer.authority.committed_pm_executable", "src/hermes_installer/authority/committed_pm_executable.py", "lib/python/hermes_installer/authority/committed_pm_executable.py",
     "9e8a3a28aa10e8f3e68431b5dcc8a0d51f2afa54c3d57c5e4dd7fda2826cfcf0", 43_170, "module"),
    ("hermes_installer.authority.daemon", "src/hermes_installer/authority/daemon.py", "lib/python/hermes_installer/authority/daemon.py",
     "6e506c868e164b429d50b2567a119a9dced2de69cc9bc042c7062813839e37c9", 37_930, "module"),
    ("hermes_installer.authority.enrollment", "src/hermes_installer/authority/enrollment.py", "lib/python/hermes_installer/authority/enrollment.py",
     "7ba9abef79744328ed3d5deefdf8b1815e532df295963fd72d8f9f476aa7f16e", 204_399, "module"),
    ("hermes_installer.authority.functional_health_receipt_consumer", "src/hermes_installer/authority/functional_health_receipt_consumer.py", "lib/python/hermes_installer/authority/functional_health_receipt_consumer.py",
     "c889505f5b1408c77f234975cc81eb84299177b0153f180d768667bac33a6c4d", 43_402, "module"),
    ("hermes_installer.authority.initial_policy_compiler", "src/hermes_installer/authority/initial_policy_compiler.py", "lib/python/hermes_installer/authority/initial_policy_compiler.py",
     "34aa92870f6e5fabd327f9518f3fcd4e1a6afa90b43c0be4bcc02ae88996a708", 41_486, "module"),
    ("hermes_installer.authority.listener_activation", "src/hermes_installer/authority/listener_activation.py", "lib/python/hermes_installer/authority/listener_activation.py",
     "64274d1dc9027b9c0c80fc31f95f292cf97b34d60f87769c1d0b472306a42869", 182_234, "module"),
    ("hermes_installer.authority.local_resource_effects", "src/hermes_installer/authority/local_resource_effects.py", "lib/python/hermes_installer/authority/local_resource_effects.py",
     "1d1f72655ed335ae486c76df80f97ffd997b07440a2b9417563c2918d874be9d", 142_474, "module"),
    ("hermes_installer.authority.native_assembler", "src/hermes_installer/authority/native_assembler.py", "lib/python/hermes_installer/authority/native_assembler.py",
     "564093a9bd255b10f83de08811b9280c30104750c949432ab87644eae03bcfb1", 28_815, "module"),
    ("hermes_installer.authority.native_custody_proof", "src/hermes_installer/authority/native_custody_proof.py", "lib/python/hermes_installer/authority/native_custody_proof.py",
     "4b48a790a768b92204d84229e38910cd6d2da37ce5844ca72579ba36c5eb986e", 99_355, "module"),
    ("hermes_installer.authority.native_definition_composition", "src/hermes_installer/authority/native_definition_composition.py", "lib/python/hermes_installer/authority/native_definition_composition.py",
     "f99e072dfb60cfbcce4a760d38355301f9e653d231586d2f538dffd88acfff3a", 9_534, "module"),
    ("hermes_installer.authority.native_health_daemon", "src/hermes_installer/authority/native_health_daemon.py", "lib/python/hermes_installer/authority/native_health_daemon.py",
     "d21d018e6fb6676b61b1f0b6968feb54d4c2d1a0f2fa5ddca6878807ae8d928c", 112_468, "module"),
    ("hermes_installer.authority.native_health_observer", "src/hermes_installer/authority/native_health_observer.py", "lib/python/hermes_installer/authority/native_health_observer.py",
     "af2b48783347b0a684259233b36312c849ee6896f25bb03b49b6b23c5a51480c", 145_475, "module"),
    ("hermes_installer.authority.native_health_source", "src/hermes_installer/authority/native_health_source.py", "lib/python/hermes_installer/authority/native_health_source.py",
     "e98f0a7d5ee5807a06fb1b9e51b27120e0b9c5051aa0af9663ceb67c46ea449e", 16_121, "module"),
    ("hermes_installer.authority.native_input_observer", "src/hermes_installer/authority/native_input_observer.py", "lib/python/hermes_installer/authority/native_input_observer.py",
     "1777ff56664ee298db2eb4b32af0ed3929f0e509c7a8c5b82bf219d6554c349d", 41_560, "module"),
    ("hermes_installer.authority.native_output_receipts", "src/hermes_installer/authority/native_output_receipts.py", "lib/python/hermes_installer/authority/native_output_receipts.py",
     "25f8903c4e9cfd9b6d05bccc98f00d6b0c8becf09c1e624235fa8f10164563ba", 115_704, "module"),
    ("hermes_installer.authority.native_policy_preparation", "src/hermes_installer/authority/native_policy_preparation.py", "lib/python/hermes_installer/authority/native_policy_preparation.py",
     "23557ae9d39b017716936408a4e64d8c197749b42f7b507ef9212cfe41934387", 65_082, "module"),
    ("hermes_installer.authority.native_registration_projection", "src/hermes_installer/authority/native_registration_projection.py", "lib/python/hermes_installer/authority/native_registration_projection.py",
     "7afa35250c9cd82f34030d37a74b6c310f25fde88d2169cf30913eafcbcf266b", 82_047, "module"),
    ("hermes_installer.authority.native_request_observation", "src/hermes_installer/authority/native_request_observation.py", "lib/python/hermes_installer/authority/native_request_observation.py",
     "a30da168eb0a94ef490e88aed23a4f60b50b9a89f65bf71fd0c642a92ec8117d", 33_600, "module"),
    ("hermes_installer.authority.native_runtime_observer", "src/hermes_installer/authority/native_runtime_observer.py", "lib/python/hermes_installer/authority/native_runtime_observer.py",
     "9cab5a39a2ba647514ae11bb7442d418a293941841f9eee382233f0669371bdb", 198_388, "module"),
    ("hermes_installer.authority.native_source_definitions", "src/hermes_installer/authority/native_source_definitions.py", "lib/python/hermes_installer/authority/native_source_definitions.py",
     "4d66c49e798eb957fa77601c4dad021182b734b1eb8fe322d52ecca060223341", 32_858, "module"),
    ("hermes_installer.authority.native_worker_endpoint_custody", "src/hermes_installer/authority/native_worker_endpoint_custody.py", "lib/python/hermes_installer/authority/native_worker_endpoint_custody.py",
     "66e3ddf7ebc82185bb3cf9df5f60185be5d78f3d2098df0dd513731012589ee5", 40_194, "module"),
    ("hermes_installer.authority.native_worker_generation_schema", "src/hermes_installer/authority/native_worker_generation_schema.py", "lib/python/hermes_installer/authority/native_worker_generation_schema.py",
     "f03c0fc953bb54ace37d86d8e8315999eacb96055c1f61bebc6769eb2061fc83", 13_871, "module"),
    ("hermes_installer.authority.native_worker_launch", "src/hermes_installer/authority/native_worker_launch.py", "lib/python/hermes_installer/authority/native_worker_launch.py",
     "abe1eb856ac6a31c9c4bb828969432ae3afab1a128b23b4ad6ea2ccac0f32054", 38_435, "module"),
    ("hermes_installer.authority.native_worker_recipes", "src/hermes_installer/authority/native_worker_recipes.py", "lib/python/hermes_installer/authority/native_worker_recipes.py",
     "add2189878535c7b35d3cc04a426241a5ba24f7d2bed0ab5461fe152e404c0bc", 46_109, "module"),
    ("hermes_installer.authority.native_worker_runtime_materialization", "src/hermes_installer/authority/native_worker_runtime_materialization.py", "lib/python/hermes_installer/authority/native_worker_runtime_materialization.py",
     "529b0d707bd530df206d6a512dc061a12d894a2b92546235e9480ccea4cff923", 71_935, "module"),
    ("hermes_installer.authority.native_worker_service_generation", "src/hermes_installer/authority/native_worker_service_generation.py", "lib/python/hermes_installer/authority/native_worker_service_generation.py",
     "0487ea123cad9300bdbab464b012a5b4314f48bf400289aec199cdafad585ace", 42_104, "module"),
    ("hermes_installer.authority.native_worker_start_recipe", "src/hermes_installer/authority/native_worker_start_recipe.py", "lib/python/hermes_installer/authority/native_worker_start_recipe.py",
     "e58acef2d612c10863654c05c0ade47a6e00f18d57f9e477c49ce35a957b560d", 20_416, "module"),
    ("hermes_installer.authority.owner_overlay_capture_schemas", "src/hermes_installer/authority/owner_overlay_capture_schemas.py", "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py",
     "37b28db4c9709147dee50f14ea99ba5bd6e74a796ace897c3e9a51ba660d063d", 5_409, "module"),
    ("hermes_installer.authority.owner_overlay_publication", "src/hermes_installer/authority/owner_overlay_publication.py", "lib/python/hermes_installer/authority/owner_overlay_publication.py",
     "c35ac8726ba6b75fa48aed1ef94d6e52e445633c1f8b63a8e49c82aefd64b446", 57_259, "module"),
    ("hermes_installer.authority.pm_runtime", "src/hermes_installer/authority/pm_runtime.py", "lib/python/hermes_installer/authority/pm_runtime.py",
     "1bf7e149095651c6dfcc33d88d9e2ca375879c5d7dea990c0ec2e6a37c2e4a0e", 70_358, "module"),
    ("hermes_installer.authority.private_loopback_network", "src/hermes_installer/authority/private_loopback_network.py", "lib/python/hermes_installer/authority/private_loopback_network.py",
     "a56123f11f9069fc06b41921e4b2af704781ca321ddd6e314239236f3a6d2384", 70_665, "module"),
    ("hermes_installer.authority.private_loopback_worker_gate", "src/hermes_installer/authority/private_loopback_worker_gate.py", "lib/python/hermes_installer/authority/private_loopback_worker_gate.py",
     "4732b84abc05087f2248ecd374c7a55c765676ab9a489c4cdfe0509a324ee508", 22_240, "module"),
    ("hermes_installer.authority.remote_observations", "src/hermes_installer/authority/remote_observations.py", "lib/python/hermes_installer/authority/remote_observations.py",
     "b6e602fc03996fcd00da4ba43d394e377feea1706d2b7d08691c587754a9ec31", 93_746, "module"),
    ("hermes_installer.authority.runtime_bindings", "src/hermes_installer/authority/runtime_bindings.py", "lib/python/hermes_installer/authority/runtime_bindings.py",
     "d0a0e8d2dd3465e6b5964286193d101173b394c498cbc11eb6ebc723df8660b5", 133_410, "module"),
    ("hermes_installer.authority.runtime_composition", "src/hermes_installer/authority/runtime_composition.py", "lib/python/hermes_installer/authority/runtime_composition.py",
     "f710ede7fe6a728a0e128f7f852ba15d604e423c19f860ee3adccdb2895f8f60", 116_776, "module"),
    ("hermes_installer.authority.runtime_root_custody", "src/hermes_installer/authority/runtime_root_custody.py", "lib/python/hermes_installer/authority/runtime_root_custody.py",
     "85fa514c128b962848dbe267fdcbaeb03f90f16ba2a2a6cf3fb288d3d2be09dd", 38_316, "module"),
    ("hermes_installer.authority.service", "src/hermes_installer/authority/service.py", "lib/python/hermes_installer/authority/service.py",
     "64693b0be4ac7a8c80547db51517723a09054d56015d520dfc717386d35be3e3", 367_542, "module"),
    ("hermes_installer.authority.setup_policy_publication", "src/hermes_installer/authority/setup_policy_publication.py", "lib/python/hermes_installer/authority/setup_policy_publication.py",
     "bf6556d1402e03c924f913c39976d82403d1733673983f947edfabc7b3d7f34f", 110_973, "module"),
    ("hermes_installer.authority.setup_principal", "src/hermes_installer/authority/setup_principal.py", "lib/python/hermes_installer/authority/setup_principal.py",
     "8c10a9be6fcb0da4e41d56c8f29d14d09d603946ff060b13966a5fefa8d1aa96", 167_860, "module"),
    ("hermes_installer.authority.source_observers", "src/hermes_installer/authority/source_observers.py", "lib/python/hermes_installer/authority/source_observers.py",
     "8cf9ca2e4171c1a5a2402fa2874b2115592143aaff2ab127bc4238d2912e9ba9", 261_264, "module"),
    ("hermes_installer.components.native_plugins", "src/hermes_installer/components/native_plugins.py", "lib/python/hermes_installer/components/native_plugins.py",
     "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7", 28_259, "module"),
    ("hermes_installer.components.public_registries", "src/hermes_installer/components/public_registries.py", "lib/python/hermes_installer/components/public_registries.py",
     "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f", 29_374, "module"),
    ("hermes_installer.managed_process_custodian", "src/hermes_installer/managed_process_custodian.py", "lib/python/hermes_installer/managed_process_custodian.py",
     "1bb1267e5e95307da0bf78775a3450ce48a5762f8cff6e5600db2ba8af907657", 631_187, "module"),
    ("hermes_installer.native_boundary_patch", "src/hermes_installer/native_boundary_patch.py", "lib/python/hermes_installer/native_boundary_patch.py",
     "fe1bfca7de02408c27891f0d6830da938ee7f18c84ee6b34bdd766f8e1645159", 22_888, "module"),
    ("hermes_installer.native_plugin_bindings", "src/hermes_installer/native_plugin_bindings.py", "lib/python/hermes_installer/native_plugin_bindings.py",
     "f5e9fcb74b555dcd5d98bc37eec29c42cbe85f3793cf43f2dc97536b030d1b26", 22_679, "module"),
    ("hermes_installer.native_plugin_loader", "src/hermes_installer/native_plugin_loader.py", "lib/python/hermes_installer/native_plugin_loader.py",
     "eebe58ea486ecebeceacc8d8f46f8b26e061b46b4f25a11e41a5059f0233bdbd", 124_775, "module"),
    ("hermes_installer.protected_enrollment", "src/hermes_installer/protected_enrollment.py", "lib/python/hermes_installer/protected_enrollment.py",
     "5b6848226891a08b0a3f4e25f311cb230ad8b4005fe3c485f0e86c56fddcb0a1", 212_817, "module"),
    ("hermes_installer.registry.resource_backends", "src/hermes_installer/registry/resource_backends.py", "lib/python/hermes_installer/registry/resource_backends.py",
     "e59813aa36754a0e08fece9c9c2a83ec9c21a6807935a6c83f7b09cca6792414", 27_026, "module"),
    ("hermes_installer.root_setup", "src/hermes_installer/root_setup.py", "lib/python/hermes_installer/root_setup.py",
     "d4a1a4702d011d08b266a084e013c4d7fb014a00721bef6010fb4fa5a749db0f", 57_026, "module"),
    ("hermes_installer.native_invocations", "src/hermes_installer/native_invocations.py", "src/hermes_installer/native_invocations.py",
     "78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226", 40_107, "source-module"),
    ("hermes_installer.native_boundary", "src/hermes_installer/native_boundary.py", "src/hermes_installer/native_boundary.py",
     "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb", 14_356, "source-module"),
)


APPLICATION_BUILD_DRIVER = (
    "installer-application-environment-builder-v1",
    "src/hermes_installer/authority/application_environment_builder.py",
    "lib/python/hermes_installer/authority/application_environment_builder.py",
    "8c5aebe61ba3d7e5c9bcf27dfadba8771ed3a4987240ea52fe2189251f1b6e8c",
    45_807,
    "application-build-driver",
)
REVIEWED_HEALTH_FIXTURES = (
    ("src/hermes_installer/native_health_fixture/request.txt", "fixtures/native-health/request.txt",
     "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c", 182),
    ("src/hermes_installer/native_health_fixture/seed-value.txt", "fixtures/native-health/seed-value.txt",
     "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a", 67),
    ("src/hermes_installer/native_health_fixture/expected-tool-result.json",
     "fixtures/native-health/expected-tool-result.json",
     "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a", 240),
    ("src/hermes_installer/native_health_fixture/tool-result.schema.json",
     "fixtures/native-health/tool-result.schema.json",
     "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5", 526),
    ("src/hermes_installer/native_health_fixture/recipe.json", "fixtures/native-health/recipe.json",
     "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7", 845),
)
REVIEWED_CAPABILITY_MAP_PATH = "plans/amendments/2026-10-10-reviewed-native-capability-selection-v91/reviewed-native-capability-map-v1.json"
REVIEWED_CAPABILITY_MAP_ID = "installer-reviewed-native-capability-map-v1"
REVIEWED_CAPABILITY_MAP_SHA256 = "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565"
REVIEWED_CAPABILITY_MAP_BYTES = 2026
CATALOG_SOURCE_PATH = "src/hermes_installer/authority/artifact-catalog.json"
RUNTIME_REQUIREMENTS_PATH = "requirements-runtime.txt"
RELEASE_BUILDER_ARTIFACT_ID = "installer-release-builder-v1"
RELEASE_BUILD_STORE_ID = "installer-release-build-cas-v1"
MAX_SOURCE_FILES = 50_000
MAX_SOURCE_FILE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SOURCE_CAS_BYTES = 16 * 1024 * 1024 * 1024
MAX_RELEASE_BUILD_CAS_BYTES = 16 * 1024 * 1024 * 1024
BOOTSTRAP_RUNTIME_ROOT = Path("/var/lib/hermes-installer/bootstrap-runtimes")
BOOTSTRAP_RUNTIME_ARCHIVE_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/20260901/"
    "cpython-3.14.7+20260901-aarch64-unknown-linux-gnu-install_only.tar.gz")
BOOTSTRAP_RUNTIME_ARCHIVE_SHA256 = "30f1cc489be654477d895b441e196bb080738bf0456da82080ad4ab66a22d80f"
BOOTSTRAP_RUNTIME_ARCHIVE_BYTES = 95_628_137
BOOTSTRAP_RUNTIME_MAX_DOWNLOAD = 100_663_296
BOOTSTRAP_RUNTIME_MAX_EXPANDED = 536_870_912
BOOTSTRAP_RUNTIME_ARTIFACT_ID = "installer-bootstrap-cpython314-linux-arm64"
BOOTSTRAP_PYYAML_URL = (
    "https://files.pythonhosted.org/packages/92/b5/47e807c2623074914e29dabd16cbbdd4bf5e9b2db9f8090fa64411fc5382/"
    "pyyaml-6.0.3-cp314-cp314-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl")
BOOTSTRAP_PYYAML_SHA256 = "501a031947e3a9025ed4405a168e6ef5ae3126c59f90ce0cd6f2bfc477be31b7"
BOOTSTRAP_PYYAML_BYTES = 766_454
BOOTSTRAP_DEPENDENCY_ARTIFACT_ID = "installer-bootstrap-pyyaml603-cp314-linux-arm64"
BOOTSTRAP_RUNTIME_TTL_SECONDS = 600.0
RELEASE_MANIFEST_PATH = "release-manifest.json"
RELEASE_ROLES = RELEASE_MEMBER_ROLES
SOURCE_CAS_V65_ROOT = Path("/var/lib/hermes-installer/source-cas/installer")
STAGED_LAUNCHER_SOURCE = "scripts/hermes-installer-root-setup"
STAGED_LAUNCHER_PATH = "bin/hermes-installer-root-setup"
STAGED_INTERPRETER_PATH = "runtime/bin/python"
STAGED_PLAN_PATH = "plans/root-setup-plan-v1.json"
STAGED_PLAN_TEMPLATE_PATH = "templates/root-setup-plan-template-v1.json"
STAGED_COMPILER_TEMPLATE_PATH = "templates/bootstrap-compiler-template-v1.json"
STAGED_IDENTITY_TEMPLATE_PATH = "templates/authentik-policy-template-v1.json"
STAGED_PREPARED_BASE_TEMPLATE_PATH = "templates/prepared-authority-base-template-v1.json"
STAGED_RECEIPT_BINDINGS_TEMPLATE_PATH = "templates/bootstrap-receipt-bindings-template-v1.json"
STAGED_COMPOSIO_POLICY_TEMPLATE_PATH = "templates/composio-whatsapp-catalog-read-policy-v1.json"
STAGED_EXISTING_MODEL_STORE_TEMPLATE_PATH = "templates/existing-model-store-root-template-v1.json"
STAGED_PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH = "templates/private-loopback-policy-v1.json"
STAGED_REVIEWED_CAPABILITY_MAP_PATH = "templates/reviewed-native-capability-map-v1.json"
STAGED_CATALOG_PATH = "catalog/artifacts.json"
ROOT_PLAN_TEMPLATE_ARTIFACT_IDS = (
    COMPILER_TEMPLATE_ID, IDENTITY_TEMPLATE_ID, PREPARED_BASE_TEMPLATE_ID,
    RECEIPT_BINDINGS_TEMPLATE_ID, COMPOSIO_POLICY_TEMPLATE_ID,
    PRIVATE_LOOPBACK_POLICY_TEMPLATE_ID,
)
RECEIPT_TTL_SECONDS = 300.0
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SEAL = object()
_FIXED_SOURCE_ORIGIN_POLICY = object()
_DEPLOYMENT_PREDECESSOR_SEAL = object()
_DEPLOYMENT_PREDECESSOR_LOCK = threading.RLock()
_DEPLOYMENT_PREDECESSOR_RECEIPTS: dict[str, tuple["VerifiedDeploymentPredecessor", Any]] = {}


class InstallerReleaseBuildError(BootstrapEnrollmentError):
    """Candidate source or release-build custody failed verification."""


def _runtime_output_roles(relative_path: str) -> tuple[str, ...]:
    if relative_path == STAGED_INTERPRETER_PATH:
        return ("interpreter",)
    if relative_path.startswith("runtime/"):
        return ("runtime-member",)
    raise InstallerReleaseBuildError("runtime output path is outside the fixed interpreter closure")


@dataclass(frozen=True, slots=True)
class DistributionFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    device: int
    inode: int
    ctime_ns: int = 0


class VerifiedInstallerDistributionReceipt:
    """Sealed, held view of one exact root-owned candidate source tree."""

    __slots__ = ("candidate_git_sha", "git_tree_sha1", "source_tree_sha256",
                 "baseline_tree_sha256", "amendment_manifest_sha256",
                 "source_catalog_sha256", "files", "root_device", "root_inode",
                 "_root_fd", "_seal", "_expected_uid", "_closed", "_handle", "_file_fds")

    def __init__(self, seal: object, *, candidate_git_sha: str, git_tree_sha1: str,
                 source_tree_sha256: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, source_catalog_sha256: str,
                 files: tuple[DistributionFile, ...], root_fd: int, expected_uid: int,
                 handle: str):
        if seal is not _SEAL:
            raise TypeError("distribution receipts can only be minted by the source CAS registry")
        self.candidate_git_sha = candidate_git_sha
        self.git_tree_sha1 = git_tree_sha1
        self.source_tree_sha256 = source_tree_sha256
        self.baseline_tree_sha256 = baseline_tree_sha256
        self.amendment_manifest_sha256 = amendment_manifest_sha256
        self.source_catalog_sha256 = source_catalog_sha256
        self.files = files
        info = os.fstat(root_fd)
        self.root_device, self.root_inode = info.st_dev, info.st_ino
        self._root_fd, self._seal, self._expected_uid = root_fd, seal, expected_uid
        self._closed, self._handle = False, handle
        held: dict[str, int] = {}
        try:
            for row in files:
                fd = _open_relative(root_fd, row.relative_path, os.O_RDONLY)
                current = os.fstat(fd)
                if (current.st_dev != row.device or current.st_ino != row.inode
                        or current.st_ctime_ns != row.ctime_ns):
                    os.close(fd)
                    raise InstallerReleaseBuildError("candidate source changed while sealing its file custody")
                held[row.relative_path] = fd
        except BaseException:
            for fd in held.values():
                os.close(fd)
            raise
        self._file_fds = held

    @property
    def receipt_handle(self) -> str:
        return self._handle

    def verify_current(self) -> None:
        self._verify_root_current()
        for row in self.files:
            self._verify_row(row)
        if _enumerate_regular_files(self._root_fd) != tuple(sorted(row.relative_path for row in self.files)):
            raise InstallerReleaseBuildError("candidate source tree has unlisted files")

    def _verify_root_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._root_fd < 0:
            raise InstallerReleaseBuildError("candidate distribution receipt is not live")
        root = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != self._expected_uid
                or root.st_dev != self.root_device or root.st_ino != self.root_inode
                or stat.S_IMODE(root.st_mode) & 0o022):
            raise InstallerReleaseBuildError("candidate source CAS directory custody changed")

    def _verify_row(self, row: DistributionFile) -> None:
        held_fd = self._file_fds.get(row.relative_path)
        if held_fd is None:
            raise InstallerReleaseBuildError("candidate source file custody is not retained")
        held = os.fstat(held_fd)
        if (held.st_dev != row.device or held.st_ino != row.inode
                or held.st_ctime_ns != row.ctime_ns):
            raise InstallerReleaseBuildError("retained candidate source file identity changed")
        fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != self._expected_uid or info.st_dev != row.device
                    or info.st_ino != row.inode or stat.S_IMODE(info.st_mode) != row.mode
                    or info.st_ctime_ns != row.ctime_ns
                    or digest != row.sha256 or size != row.size_bytes):
                raise InstallerReleaseBuildError("candidate source CAS file bytes or ownership changed")
        finally:
            os.close(fd)

    def open_file(self, relative_path: str) -> int:
        self._verify_root_current()
        row = next((entry for entry in self.files if entry.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("requested source path is outside the verified candidate closure")
        self._verify_row(row)
        fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (digest != row.sha256 or size != row.size_bytes or info.st_dev != row.device
                    or info.st_ino != row.inode or info.st_ctime_ns != row.ctime_ns
                    or info.st_uid != self._expected_uid):
                raise InstallerReleaseBuildError("candidate source changed while opening a verified file")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        if not self._closed:
            for fd in self._file_fds.values():
                os.close(fd)
            self._file_fds.clear()
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True

    def __enter__(self) -> "VerifiedInstallerDistributionReceipt":
        self.verify_current()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class RootInstallerDistributionRegistry:
    """Instance-local opaque source receipt registry; handles never carry paths."""

    def __init__(self, *, root: Path = SOURCE_CAS_V65_ROOT):
        if root != SOURCE_CAS_V65_ROOT:
            raise ValueError("installer source CAS root is fixed by installed policy")
        self._root = root
        self._receipts: dict[str, VerifiedInstallerDistributionReceipt] = {}
        self._used: set[str] = set()

    @classmethod
    def from_owned_source_CAS(cls, source_cas: "RootInstallerDistributionSourceCAS",
                              root_journal: object) -> "RootInstallerDistributionRegistry":
        if not isinstance(source_cas, RootInstallerDistributionSourceCAS) or root_journal is None:
            raise TypeError("distribution registry requires the fixed source CAS and root journal")
        return source_cas.registry

    def acquire_selected(self, candidate_git_sha: str) -> str:
        """Internal CAS operation used by RootInstallerDistributionSourceCAS."""
        _require_linux_root()
        _validate_git_sha(candidate_git_sha)
        self._prepare_root()
        lock_fd = os.open(self._root / ".acquire.lock",
                          os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallerReleaseBuildError("source CAS acquisition lock custody is invalid")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._clean_incomplete_staging()
            existing = self._root / candidate_git_sha
            if existing.exists() or existing.is_symlink():
                handle, _ = self.resolve_selected(candidate_git_sha)
                return handle
            if _tree_byte_usage(self._root) + MAX_SOURCE_TREE_BYTES + 16 * 1024 * 1024 > MAX_SOURCE_CAS_BYTES:
                raise BootstrapEnrollmentPending("root source CAS has no bounded space for another candidate")
            return self._acquire_selected_locked(candidate_git_sha)
        finally:
            os.close(lock_fd)

    def _acquire_selected_locked(self, candidate_git_sha: str) -> str:
        _require_linux_root()
        work = self._root / (".fetch-" + secrets.token_hex(16))
        candidate_dir: Path | None = None
        os.mkdir(work, 0o700)
        try:
            self._git(["init", "--quiet", str(work)])
            self._git(["-C", str(work), "remote", "add", "origin", SOURCE_ORIGIN])
            origin = self._git(["-C", str(work), "remote", "get-url", "origin"]).decode("utf-8").strip()
            if origin != SOURCE_ORIGIN:
                raise InstallerReleaseBuildError("source checkout origin differs from the fixed repository")
            self._git(["-C", str(work), "fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin",
                       f"refs/tags/{BASELINE_TAG}:refs/tags/{BASELINE_TAG}"])
            self._git(["-C", str(work), "fetch", "--depth=1", "--filter=blob:none", "--no-tags",
                       "origin", candidate_git_sha])
            commit = self._git(["-C", str(work), "rev-parse", "FETCH_HEAD^{commit}"]).decode("ascii").strip()
            if commit != candidate_git_sha:
                raise InstallerReleaseBuildError("Git source acquisition did not resolve the selected commit")
            tag_object = self._git(["-C", str(work), "rev-parse", f"{BASELINE_TAG}^{{tag}}"]).decode("ascii").strip()
            baseline_commit = self._git(["-C", str(work), "rev-parse", f"{BASELINE_TAG}^{{commit}}"]).decode("ascii").strip()
            if tag_object != BASELINE_TAG_OBJECT or baseline_commit != BASELINE_COMMIT:
                raise InstallerReleaseBuildError("frozen baseline tag identity differs from the protected plan")
            tagged_baseline_tree = self._git(["-C", str(work), "rev-parse",
                                               f"{BASELINE_COMMIT}:{BASELINE_DIRECTORY}"]).decode("ascii").strip()
            selected_baseline_tree = self._git(["-C", str(work), "rev-parse",
                                                 f"{candidate_git_sha}:{BASELINE_DIRECTORY}"]).decode("ascii").strip()
            if tagged_baseline_tree != selected_baseline_tree:
                raise InstallerReleaseBuildError("selected candidate changed the frozen baseline Git tree")
            self._git(["-C", str(work), "checkout", "--detach", candidate_git_sha])
            actual = self._git(["-C", str(work), "rev-parse", "HEAD"]).decode("ascii").strip()
            tree = self._git(["-C", str(work), "rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
            if actual != candidate_git_sha:
                raise InstallerReleaseBuildError("Git checkout is not the selected candidate")
            files = self._export_commit(work, candidate_git_sha)
            final_candidate_dir = self._root / candidate_git_sha
            if final_candidate_dir.exists() or final_candidate_dir.is_symlink():
                raise InstallerReleaseBuildError("candidate source CAS already contains this revision")
            candidate_dir = self._root / (".stage-" + secrets.token_hex(16))
            os.mkdir(candidate_dir, 0o700)
            final = candidate_dir / "source"
            os.rename(work, final)
            _make_immutable_tree(final)
            _fsync_dir(candidate_dir)
            _fsync_dir(self._root)
            root_fd = os.open(final, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                rows = _inspect_source_tree(root_fd, files)
                source_digest = _manifest_digest({row.relative_path: row.sha256 for row in rows})
                baseline_digest = _verify_frozen_baseline(root_fd, rows)
                if baseline_digest != BASELINE_TREE_SHA256:
                    raise InstallerReleaseBuildError("complete frozen baseline digest differs from the pinned v1 tree")
                amendment_digest = _amendment_digest(rows)
                catalog_row = next((row for row in rows if row.relative_path == CATALOG_SOURCE_PATH), None)
                if catalog_row is None:
                    raise InstallerReleaseBuildError("candidate source artifact catalog is missing")
                _validate_source_catalog(_read_relative(root_fd, CATALOG_SOURCE_PATH, 16 * 1024 * 1024))
                handle = secrets.token_urlsafe(32)
                receipt = VerifiedInstallerDistributionReceipt(
                    _SEAL, candidate_git_sha=actual, git_tree_sha1=tree,
                    source_tree_sha256=source_digest, baseline_tree_sha256=baseline_digest,
                    amendment_manifest_sha256=amendment_digest,
                    source_catalog_sha256=catalog_row.sha256, files=rows,
                    root_fd=root_fd, expected_uid=os.geteuid(), handle=handle)
                receipt.verify_current()
                _write_distribution_receipt(candidate_dir, receipt)
                os.rename(candidate_dir, final_candidate_dir)
                candidate_dir = final_candidate_dir
                _fsync_dir(self._root)
                self._receipts[handle] = receipt
                return handle
            except BaseException:
                os.close(root_fd)
                raise
        except BaseException:
            if work.exists():
                _remove_tree_no_follow(work)
            if candidate_dir is not None and candidate_dir.exists():
                _remove_tree_no_follow(candidate_dir)
            raise

    def _clean_incomplete_staging(self) -> None:
        for entry in self._root.iterdir():
            if not (entry.name.startswith(".fetch-") or entry.name.startswith(".stage-")):
                continue
            info = entry.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise InstallerReleaseBuildError("incomplete source staging entry has unsafe custody")
            _remove_tree_no_follow(entry)

    def resolve(self, handle: str, *, consume: bool = False) -> VerifiedInstallerDistributionReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle) or handle in self._used:
            raise BootstrapEnrollmentPending("candidate source CAS receipt is absent or already consumed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            receipt = self._load_distribution_receipt(handle)
            self._receipts[handle] = receipt
        receipt.verify_current()
        if consume:
            self._used.add(handle)
        return receipt

    def resolve_selected(self, candidate_git_sha: str) -> tuple[str, VerifiedInstallerDistributionReceipt]:
        _validate_git_sha(candidate_git_sha)
        _verify_private_cas_root(SOURCE_CAS_V65_ROOT)
        candidate_dir = SOURCE_CAS_V65_ROOT / candidate_git_sha
        candidate_info = candidate_dir.lstat()
        if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid != 0
                or stat.S_IMODE(candidate_info.st_mode) != 0o700):
            raise InstallerReleaseBuildError("selected source CAS directory is not root-owned and private")
        descriptor = _read_private_json(candidate_dir / "source-receipt.json", 16 * 1024 * 1024)
        handle = descriptor.get("receipt_handle")
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise InstallerReleaseBuildError("selected source CAS has no root-issued receipt handle")
        receipt = self.resolve(handle)
        if receipt.candidate_git_sha != candidate_git_sha:
            raise InstallerReleaseBuildError("selected source CAS receipt candidate does not match requested commit")
        return handle, receipt

    def _load_distribution_receipt(self, handle: str) -> VerifiedInstallerDistributionReceipt:
        _require_linux_root()
        for candidate_dir in self._root.iterdir():
            if not _GIT_SHA.fullmatch(candidate_dir.name) or candidate_dir.is_symlink():
                continue
            try:
                candidate_info = candidate_dir.lstat()
                if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid != 0
                        or stat.S_IMODE(candidate_info.st_mode) != 0o700):
                    raise InstallerReleaseBuildError("source CAS candidate directory custody changed")
                raw = _read_private_json(candidate_dir / "source-receipt.json", 16 * 1024 * 1024)
                if raw.get("receipt_handle") != handle:
                    continue
                if raw.get("candidate_git_sha") != candidate_dir.name or raw.get("schema") != 1:
                    raise InstallerReleaseBuildError("durable source receipt identity is invalid")
                source_root = candidate_dir / "source"
                root_fd = _open_secure_directory(source_root, expected_uid=0)
                root_identity = os.fstat(root_fd)
                if (root_identity.st_dev != raw.get("source_device")
                        or root_identity.st_ino != raw.get("source_inode")):
                    os.close(root_fd)
                    raise InstallerReleaseBuildError("durable source receipt root identity changed")
                manifest_fd = os.open(candidate_dir / "source-manifest.json",
                                      os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    manifest_info = os.fstat(manifest_fd)
                    if (manifest_info.st_uid != 0 or manifest_info.st_nlink != 1
                            or stat.S_IMODE(manifest_info.st_mode) != 0o600
                            or manifest_info.st_size > 16 * 1024 * 1024):
                        raise InstallerReleaseBuildError("durable source manifest custody is invalid")
                    manifest_bytes = _read_exact_fd(manifest_fd, manifest_info.st_size)
                    if hashlib.sha256(manifest_bytes).hexdigest() != raw.get("source_manifest_sha256"):
                        raise InstallerReleaseBuildError("durable source manifest digest changed")
                finally:
                    os.close(manifest_fd)
                files = tuple(DistributionFile(**item) for item in raw["files"])
                receipt = VerifiedInstallerDistributionReceipt(
                    _SEAL, candidate_git_sha=raw["candidate_git_sha"], git_tree_sha1=raw["git_tree_sha1"],
                    source_tree_sha256=raw["source_tree_sha256"], baseline_tree_sha256=raw["baseline_tree_sha256"],
                    amendment_manifest_sha256=raw["amendment_manifest_sha256"],
                    source_catalog_sha256=raw["source_catalog_sha256"], files=files, root_fd=root_fd,
                    expected_uid=0, handle=handle)
                receipt.verify_current()
                return receipt
            except FileNotFoundError:
                continue
        raise BootstrapEnrollmentPending("candidate source CAS receipt is absent or invalid")

    def _prepare_root(self) -> None:
        _ensure_root_directory(Path("/var/lib/hermes-installer"), 0o700)
        _ensure_root_directory(Path("/var/lib/hermes-installer/source-cas"), 0o700)
        _ensure_root_directory(self._root, 0o700)
        _ensure_root_directory(self._root / ".receipts", 0o700)

    @staticmethod
    def _git(arguments: list[str]) -> bytes:
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": "/bin/false",
                       "SSH_ASKPASS": "/bin/false",
                       "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
                       "GIT_OPTIONAL_LOCKS": "0", "GIT_PROTOCOL_FROM_USER": "0"}
        command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                   "-c", "http.followRedirects=false",
                   "-c", "protocol.file.allow=never", *arguments]
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=environment, timeout=600,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BootstrapEnrollmentPending("fixed-origin candidate source acquisition failed") from None
        if result.returncode != 0 or len(result.stdout) > MAX_SOURCE_TREE_BYTES:
            raise BootstrapEnrollmentPending("fixed-origin candidate source acquisition failed")
        return result.stdout

    @classmethod
    def _export_commit(cls, repository: Path, commit: str) -> tuple[tuple[str, str, int], ...]:
        raw = cls._git(["-C", str(repository), "ls-tree", "-rz", "--full-tree", commit])
        entries: list[tuple[str, str, int]] = []
        object_ids: list[str] = []
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                header, path_raw = item.split(b"\t", 1)
                mode_raw, kind, object_id = header.decode("ascii").split(" ")
                path = path_raw.decode("utf-8", "strict")
            except (ValueError, UnicodeError):
                raise InstallerReleaseBuildError("candidate Git tree contains a malformed entry") from None
            _validate_relative_path(path)
            if kind != "blob" or mode_raw not in {"100644", "100755"}:
                raise InstallerReleaseBuildError("candidate Git tree contains a non-regular or linked entry")
            if len(entries) >= MAX_SOURCE_FILES:
                raise InstallerReleaseBuildError("candidate Git tree exceeds the protected file-count bound")
            entries.append((path, object_id, int(mode_raw, 8)))
            object_ids.append(object_id)
        if not entries:
            raise InstallerReleaseBuildError("candidate Git tree is empty")
        if len({path.casefold() for path, _, _ in entries}) != len(entries):
            raise InstallerReleaseBuildError("candidate Git tree has portable path collisions")
        batch = cls._git_batch(repository, object_ids)
        stage = repository / ".source-export"
        exported = repository.parent / (".stage-source-" + secrets.token_hex(16))
        os.mkdir(stage, 0o700)
        total = 0
        out: list[tuple[str, str, int]] = []
        try:
            root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                for (path, object_id, mode), body in zip(entries, batch, strict=True):
                    total += len(body)
                    if len(body) > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_TREE_BYTES:
                        raise InstallerReleaseBuildError("candidate Git source exceeds its byte bound")
                    digest = hashlib.sha256(body).hexdigest()
                    _write_relative(root_fd, path, body, mode=0o700 if mode == 0o100755 else 0o600)
                    out.append((path, digest, len(body)))
                _fsync_tree(root_fd)
            finally:
                os.close(root_fd)
            # Keep only the exact exported source tree; Git metadata is not part of its trust domain.
            os.rename(stage, exported)
            for child in list(repository.iterdir()):
                if child.is_dir() and not child.is_symlink():
                    _remove_tree_no_follow(child)
                else:
                    child.unlink()
            os.rmdir(repository)
            os.rename(exported, repository)
            _fsync_dir(repository.parent)
            return tuple(out)
        except BaseException:
            if stage.exists():
                _remove_tree_no_follow(stage)
            if exported.exists():
                _remove_tree_no_follow(exported)
            raise

    @classmethod
    def _git_batch(cls, repository: Path, object_ids: list[str]) -> Iterator[bytes]:
        command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(repository),
                   "cat-file", "--batch"]
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": "/bin/false",
                       "SSH_ASKPASS": "/bin/false", "GIT_TERMINAL_PROMPT": "0"}
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=environment)
            assert process.stdin is not None and process.stdout is not None
            writer_errors: list[BaseException] = []

            def write_object_ids() -> None:
                try:
                    for object_id in object_ids:
                        process.stdin.write((object_id + "\n").encode("ascii"))
                    process.stdin.close()
                except BaseException as exc:
                    writer_errors.append(exc)

            # cat-file may block on stdout while the parent fills stdin. Feed
            # requests concurrently so neither bounded pipe can starve the
            # other for larger candidate trees.
            writer = threading.Thread(target=write_object_ids,
                                      name="installer-git-object-input", daemon=True)
            writer.start()
            total = 0
            for expected in object_ids:
                header = process.stdout.readline(256)
                fields = header.decode("ascii", "strict").rstrip("\n").split(" ")
                if len(fields) != 3 or fields[0] != expected or fields[1] != "blob":
                    raise InstallerReleaseBuildError("Git source object closure changed during export")
                size = int(fields[2])
                total += size
                if size < 0 or size > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_TREE_BYTES:
                    raise InstallerReleaseBuildError("candidate source exceeds its protected byte bound")
                body = _read_exact(process.stdout, size)
                if process.stdout.read(1) != b"\n":
                    raise InstallerReleaseBuildError("Git source object framing is invalid")
                yield body
            writer.join(timeout=30)
            if writer.is_alive():
                raise InstallerReleaseBuildError("Git source object input did not finish")
            if writer_errors:
                raise InstallerReleaseBuildError("Git source object input failed")
            if process.wait(timeout=30) != 0:
                raise InstallerReleaseBuildError("Git source object export failed")
        except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
            if "writer" in locals():
                writer.join(timeout=1)
            raise BootstrapEnrollmentPending("candidate Git source object export failed") from None
        except BaseException:
            if process.poll() is None:
                process.kill()
            if "writer" in locals():
                writer.join(timeout=1)
            raise
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()


class RootInstallerDistributionSourceCAS:
    """Fixed-origin stage-zero source acquisition; this precedes actor/release checks."""

    def __init__(self, registry: RootInstallerDistributionRegistry):
        if not isinstance(registry, RootInstallerDistributionRegistry):
            raise TypeError("source CAS requires its in-process root distribution registry")
        self.registry = registry

    @classmethod
    def from_root_bootstrap(cls, root_journal: object,
                            verified_fixed_origin_policy: object) -> "RootInstallerDistributionSourceCAS":
        _require_linux_root()
        if root_journal is None or verified_fixed_origin_policy is not _FIXED_SOURCE_ORIGIN_POLICY:
            raise TypeError("stage-zero source acquisition requires the fixed-origin root bootstrap policy")
        return cls(RootInstallerDistributionRegistry())

    def acquire_selected(self, candidate_git_sha: str) -> str:
        return self.registry.acquire_selected(candidate_git_sha)


def fixed_source_origin_policy_for_root_bootstrap() -> object:
    _require_linux_root()
    return _FIXED_SOURCE_ORIGIN_POLICY


@dataclass(frozen=True, slots=True)
class RuntimeFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    device: int
    inode: int
    link_target: str | None = None
    target_relative_path: str | None = None
    target_device: int | None = None
    target_inode: int | None = None


class VerifiedInstallerInterpreterReceipt:
    """Actual selected isolated installer interpreter and byte-closure proof."""

    __slots__ = ("receipt_handle", "distribution_receipt_handle", "candidate_git_sha",
                 "runtime_artifact_receipt_handles", "executable_sha256", "executable_device",
                 "executable_inode", "runtime_prefix_sha256", "stdlib_closure_sha256",
                 "dependency_closure_sha256", "python_version", "implementation", "cache_tag",
                 "soabi", "machine", "owner_uid", "owner_gid", "mode", "issued_monotonic",
                 "expires_monotonic", "files", "runtime_prefix", "_prefix_fd", "_exe_fd",
                 "_seal", "_closed")

    def __init__(self, seal: object, *, receipt_handle: str, distribution_receipt_handle: str,
                 candidate_git_sha: str, runtime_artifact_receipt_handles: tuple[str, ...],
                 executable_sha256: str, executable_device: int, executable_inode: int,
                 runtime_prefix_sha256: str, stdlib_closure_sha256: str,
                 dependency_closure_sha256: str, python_version: str, implementation: str,
                 cache_tag: str, soabi: str, machine: str, owner_uid: int, owner_gid: int,
                 mode: int, issued_monotonic: float, expires_monotonic: float,
                 files: tuple[RuntimeFile, ...], runtime_prefix: Path,
                 prefix_fd: int, exe_fd: int):
        if seal is not _SEAL:
            raise TypeError("interpreter receipts can only be minted by the root interpreter registry")
        self.receipt_handle = receipt_handle
        self.distribution_receipt_handle = distribution_receipt_handle
        self.candidate_git_sha = candidate_git_sha
        self.runtime_artifact_receipt_handles = runtime_artifact_receipt_handles
        self.executable_sha256, self.executable_device = executable_sha256, executable_device
        self.executable_inode = executable_inode
        self.runtime_prefix_sha256 = runtime_prefix_sha256
        self.stdlib_closure_sha256, self.dependency_closure_sha256 = stdlib_closure_sha256, dependency_closure_sha256
        self.python_version, self.implementation, self.cache_tag = python_version, implementation, cache_tag
        self.soabi, self.machine = soabi, machine
        self.owner_uid, self.owner_gid, self.mode = owner_uid, owner_gid, mode
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, expires_monotonic
        self.files, self.runtime_prefix = files, runtime_prefix
        self._prefix_fd, self._exe_fd, self._seal, self._closed = prefix_fd, exe_fd, seal, False

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._prefix_fd < 0 or self._exe_fd < 0:
            raise InstallerReleaseBuildError("installer interpreter receipt is not live")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("installer interpreter observation expired; re-observe the bootstrap runtime")
        prefix = os.fstat(self._prefix_fd)
        if (not stat.S_ISDIR(prefix.st_mode) or prefix.st_uid != self.owner_uid
                or prefix.st_gid != self.owner_gid or stat.S_IMODE(prefix.st_mode) & 0o022):
            raise InstallerReleaseBuildError("isolated installer runtime prefix custody changed")
        executable = os.fstat(self._exe_fd)
        digest, size = _hash_fd(self._exe_fd, MAX_SOURCE_FILE_BYTES)
        if (digest != self.executable_sha256 or executable.st_dev != self.executable_device
                or executable.st_ino != self.executable_inode or not stat.S_ISREG(executable.st_mode)
                or executable.st_uid != self.owner_uid or not executable.st_mode & 0o111 or size == 0):
            raise InstallerReleaseBuildError("actual installer interpreter executable changed")
        _verify_runtime_files(self._prefix_fd, self.files, self.owner_uid, self.owner_gid)

    def open_executable(self) -> int:
        self.verify_current()
        return os.dup(self._exe_fd)

    def open_runtime_file(self, relative_path: str) -> int:
        if self._seal is not _SEAL or self._closed or self._prefix_fd < 0:
            raise InstallerReleaseBuildError("installer interpreter receipt is not live")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("installer interpreter observation expired; re-observe the bootstrap runtime")
        row = next((item for item in self.files if item.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("runtime path is outside the observed interpreter closure")
        target_path = row.target_relative_path or row.relative_path
        fd = _open_relative(self._prefix_fd, target_path, os.O_RDONLY)
        info = os.fstat(fd)
        digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        if (info.st_dev != (row.target_device if row.link_target else row.device)
                or info.st_ino != (row.target_inode if row.link_target else row.inode)
                or info.st_uid != self.owner_uid
                or info.st_gid != self.owner_gid or digest != row.sha256 or size != row.size_bytes):
            os.close(fd)
            raise InstallerReleaseBuildError("runtime closure file changed after observation")
        if row.link_target is not None:
            alias_info = os.stat(row.relative_path, dir_fd=self._prefix_fd, follow_symlinks=False)
            if (not stat.S_ISLNK(alias_info.st_mode) or alias_info.st_dev != row.device
                    or alias_info.st_ino != row.inode
                    or _readlink_relative(self._prefix_fd, row.relative_path) != row.link_target):
                os.close(fd)
                raise InstallerReleaseBuildError("runtime archive alias changed after observation")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def close(self) -> None:
        if not self._closed:
            os.close(self._prefix_fd)
            os.close(self._exe_fd)
            self._prefix_fd, self._exe_fd, self._closed = -1, -1, True


@dataclass(frozen=True, slots=True)
class VerifiedInstallerRuntimeArtifactReceipt:
    """Observed installed dependency files joined to an exact lock identity."""

    receipt_handle: str
    package_name: str
    version: str
    files: tuple[tuple[str, str], ...]
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class _ProvisionedBootstrapRuntime:
    receipt_handle: str
    distribution_receipt_handle: str
    candidate_git_sha: str
    prefix: Path
    executable: Path
    runtime_artifact_sha256: str
    dependency_artifact_sha256: str
    requirements_runtime_sha256: str
    runtime_closure_sha256: str
    executable_sha256: str
    executable_device: int
    executable_inode: int
    issued_monotonic: float
    expires_monotonic: float
    soabi: str = "cpython-314-aarch64-linux-gnu"
    site_relative_path: str = "lib/python3.14/site-packages"


def _runtime_receipt_json(record: _ProvisionedBootstrapRuntime) -> dict[str, Any]:
    info = record.executable.stat(follow_symlinks=False)
    return {
        "schema": 1, "receipt_handle": record.receipt_handle,
        "distribution_receipt_handle": record.distribution_receipt_handle,
        "candidate_git_sha": record.candidate_git_sha,
        "runtime_artifact_id": BOOTSTRAP_RUNTIME_ARTIFACT_ID,
        "runtime_artifact_sha256": record.runtime_artifact_sha256,
        "dependency_artifact_id": BOOTSTRAP_DEPENDENCY_ARTIFACT_ID,
        "dependency_artifact_sha256": record.dependency_artifact_sha256,
        "requirements_runtime_sha256": record.requirements_runtime_sha256,
        "runtime_closure_sha256": record.runtime_closure_sha256,
        "executable_sha256": record.executable_sha256,
        "executable_device": record.executable_device,
        "executable_inode": record.executable_inode,
        "owner_uid": info.st_uid, "owner_gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode), "python_version": [3, 14, 7],
        "implementation": "cpython", "cache_tag": "cpython-314",
        "soabi": record.soabi, "machine": "aarch64",
        "module_closure_sha256": record.runtime_closure_sha256,
        "issued_monotonic": record.issued_monotonic,
        "expires_monotonic": record.expires_monotonic,
        "boot_id": _current_boot_id(),
        "site_relative_path": record.site_relative_path,
    }


def _write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    body = _canonical_json(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _write_all(fd, body)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


def _load_runtime_receipt(handle: str, distribution_handle: str) -> _ProvisionedBootstrapRuntime:
    if not _HANDLE.fullmatch(handle):
        raise BootstrapEnrollmentPending("bootstrap runtime receipt handle is malformed")
    # The closure identity is found only by scanning the fixed root-owned CAS;
    # the handle never supplies a path.
    _ensure_bootstrap_runtime_root()
    root_fd = _open_secure_directory(BOOTSTRAP_RUNTIME_ROOT, expected_uid=0)
    try:
        matches: list[Path] = []
        with os.scandir(root_fd) as entries:
            for entry in entries:
                if not _SHA256.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                    continue
                receipt = BOOTSTRAP_RUNTIME_ROOT / entry.name / "runtime-receipts" / (handle + ".json")
                try:
                    info = receipt.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    matches.append(receipt)
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("bootstrap runtime receipt is absent or ambiguous")
        path = matches[0]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16 * 1024):
                raise InstallerReleaseBuildError("bootstrap runtime receipt custody is invalid")
            raw = _read_exact_fd(fd, info.st_size)
        finally:
            os.close(fd)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise InstallerReleaseBuildError("bootstrap runtime receipt is malformed") from None
        if _canonical_json(value) != raw:
            raise InstallerReleaseBuildError("bootstrap runtime receipt is not canonical")
        if (not isinstance(value, dict) or value.get("schema") != 1
                or value.get("receipt_handle") != handle
                or value.get("distribution_receipt_handle") != distribution_handle
                or value.get("runtime_artifact_id") != BOOTSTRAP_RUNTIME_ARTIFACT_ID
                or value.get("runtime_artifact_sha256") != BOOTSTRAP_RUNTIME_ARCHIVE_SHA256
                or value.get("dependency_artifact_id") != BOOTSTRAP_DEPENDENCY_ARTIFACT_ID
                or value.get("dependency_artifact_sha256") != BOOTSTRAP_PYYAML_SHA256
                or value.get("runtime_closure_sha256") != path.parent.parent.name):
            raise InstallerReleaseBuildError("bootstrap runtime receipt identity does not match fixed policy")
        if value.get("boot_id") != _current_boot_id():
            raise BootstrapEnrollmentPending("bootstrap runtime receipt belongs to a different kernel boot")
        prefix = path.parent.parent / "python"
        executable = _find_runtime_executable(prefix)
        if (value.get("candidate_git_sha") is None or not _GIT_SHA.fullmatch(value["candidate_git_sha"])
                or value.get("requirements_runtime_sha256") is None
                or not _SHA256.fullmatch(value["requirements_runtime_sha256"])):
            raise InstallerReleaseBuildError("bootstrap runtime receipt source identity is malformed")
        return _ProvisionedBootstrapRuntime(
            receipt_handle=handle, distribution_receipt_handle=distribution_handle,
            candidate_git_sha=value["candidate_git_sha"], prefix=prefix, executable=executable,
            runtime_artifact_sha256=value["runtime_artifact_sha256"],
            dependency_artifact_sha256=value["dependency_artifact_sha256"],
            requirements_runtime_sha256=value["requirements_runtime_sha256"],
            runtime_closure_sha256=value["runtime_closure_sha256"],
            executable_sha256=value["executable_sha256"],
            executable_device=value["executable_device"], executable_inode=value["executable_inode"],
            issued_monotonic=float(value["issued_monotonic"]),
            expires_monotonic=float(value["expires_monotonic"]), soabi=value["soabi"],
            site_relative_path=value["site_relative_path"])
    finally:
        os.close(root_fd)


def _download_pinned(url: str, expected_sha: str, expected_size: int, maximum: int) -> bytes:
    runtime_pin = (url == BOOTSTRAP_RUNTIME_ARCHIVE_URL
                   and expected_sha == BOOTSTRAP_RUNTIME_ARCHIVE_SHA256
                   and expected_size == BOOTSTRAP_RUNTIME_ARCHIVE_BYTES
                   and maximum == BOOTSTRAP_RUNTIME_MAX_DOWNLOAD)
    wheel_pin = (url == BOOTSTRAP_PYYAML_URL
                 and expected_sha == BOOTSTRAP_PYYAML_SHA256
                 and expected_size == BOOTSTRAP_PYYAML_BYTES
                 and maximum == 1_048_576)
    if not (runtime_pin or wheel_pin) or not _SHA256.fullmatch(expected_sha):
        raise InstallerReleaseBuildError("bootstrap payload source is outside fixed policy")

    def request_for(target: str) -> urllib.request.Request:
        return urllib.request.Request(
            target, headers={"Accept-Encoding": "identity", "User-Agent": "HermesInstaller/1"})

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    response: Any = None
    target: str | None = None
    try:
        try:
            response = opener.open(request_for(url), timeout=30)
        except urllib.error.HTTPError as redirect:
            if not runtime_pin or redirect.code != 302 or redirect.url != url:
                redirect.close()
                raise InstallerReleaseBuildError("pinned bootstrap payload response is not permitted") from None
            try:
                location = redirect.headers.get("Location")
            finally:
                redirect.close()
            target = _validate_runtime_asset_redirect(location)
            try:
                response = opener.open(request_for(target), timeout=30)
            except urllib.error.HTTPError as second_response:
                second_response.close()
                raise InstallerReleaseBuildError("pinned runtime asset returned another redirect or HTTP error") from None
        if response.status != 200 or (runtime_pin and target is None):
            raise InstallerReleaseBuildError("pinned bootstrap payload response is not successful")
        if response.geturl() != (target if runtime_pin else url):
            raise InstallerReleaseBuildError("pinned bootstrap payload response URL changed unexpectedly")
        if _declared_content_length(response.headers, expected_size) is False:
            raise InstallerReleaseBuildError("pinned bootstrap payload length differs from the fixed size")
        body = response.read(maximum + 1)
        if len(body) > maximum or response.read(1):
            raise InstallerReleaseBuildError("pinned bootstrap payload exceeds its transfer bound")
    except (OSError, urllib.error.URLError, TimeoutError):
        raise BootstrapEnrollmentPending("pinned bootstrap payload could not be acquired over verified TLS") from None
    finally:
        if response is not None:
            response.close()
    if len(body) != expected_size or hashlib.sha256(body).hexdigest() != expected_sha:
        raise InstallerReleaseBuildError("pinned bootstrap payload bytes do not match the reviewed digest")
    return body


def _validate_runtime_asset_redirect(location: str | None) -> str:
    if not isinstance(location, str) or not location:
        raise InstallerReleaseBuildError("pinned runtime redirect location is missing or oversized")
    try:
        if len(location.encode("utf-8", "strict")) > 8192:
            raise InstallerReleaseBuildError("pinned runtime redirect location is missing or oversized")
        location.encode("ascii", "strict")
        parsed = urllib.parse.urlsplit(location)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        raise InstallerReleaseBuildError("pinned runtime redirect location is malformed") from None
    if (parsed.scheme != "https" or parsed.hostname != "release-assets.githubusercontent.com"
            or parsed.netloc not in {"release-assets.githubusercontent.com", "release-assets.githubusercontent.com:443"}
            or port not in (None, 443)
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise InstallerReleaseBuildError("pinned runtime redirect authority is outside fixed policy")
    return location


def _declared_content_length(headers: Any, expected_size: int) -> bool | None:
    """Validate the optional HTTP Content-Length without trusting it as byte count."""
    try:
        values = headers.get_all("Content-Length", [])
    except (AttributeError, TypeError):
        raise InstallerReleaseBuildError("pinned bootstrap response headers are malformed") from None
    if not values:
        return None
    if len(values) != 1 or not isinstance(values[0], str):
        return False
    value = values[0].strip(" \t")
    if not value or not value.isascii() or not value.isdecimal():
        return False
    try:
        return int(value, 10) == expected_size
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _is_glibc_aarch64() -> bool:
    if platform.machine().lower() not in {"aarch64", "arm64"}:
        return False
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        return hasattr(libc, "gnu_get_libc_version")
    except OSError:
        return False


def _ensure_bootstrap_runtime_root() -> None:
    parent_fd = _open_secure_directory(Path("/var/lib/hermes-installer"), expected_uid=0)
    try:
        try:
            os.mkdir(BOOTSTRAP_RUNTIME_ROOT.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        child = os.open(BOOTSTRAP_RUNTIME_ROOT.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent_fd)
        try:
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise InstallerReleaseBuildError("bootstrap runtime CAS root custody is invalid")
            os.fsync(parent_fd)
        finally:
            os.close(child)
    finally:
        os.close(parent_fd)


def _lock_contains_exact_pyyaml(lock: bytes) -> bool:
    try:
        rows = _locked_package_versions(lock)
    except InstallerReleaseBuildError:
        return False
    text = lock.decode("utf-8", "strict")
    return (rows.get("pyyaml") == frozenset({"6.0.3"}) and
            f"--hash=sha256:{BOOTSTRAP_PYYAML_SHA256}" in text)


def _extract_verified_runtime_archive(archive: bytes, destination: Path) -> None:
    if len(archive) != BOOTSTRAP_RUNTIME_ARCHIVE_BYTES or hashlib.sha256(archive).hexdigest() != BOOTSTRAP_RUNTIME_ARCHIVE_SHA256:
        raise InstallerReleaseBuildError("runtime archive is not the reviewed CPython payload")
    members: dict[str, tarfile.TarInfo] = {}
    expanded, total = 0, 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        for member in bundle:
            name = member.name.rstrip("/")
            if not name or name == ".":
                continue
            _validate_relative_path(name)
            if not name.startswith("python/") or name in members:
                raise InstallerReleaseBuildError("runtime archive contains an unexpected or duplicate member")
            if member.isdir():
                pass
            elif member.isfile():
                if member.size < 0 or member.size > MAX_SOURCE_FILE_BYTES:
                    raise InstallerReleaseBuildError("runtime archive member exceeds file bounds")
                total += member.size
                if total > BOOTSTRAP_RUNTIME_MAX_EXPANDED:
                    raise InstallerReleaseBuildError("runtime archive exceeds expanded size bound")
            elif member.issym():
                _resolve_runtime_archive_symlink(name, member.linkname)
            else:
                raise InstallerReleaseBuildError("runtime archive contains a hardlink or special member")
            members[name] = member
        expanded = len(members)
        if not members or expanded > MAX_SOURCE_FILES:
            raise InstallerReleaseBuildError("runtime archive member count is outside policy")
        for name, member in sorted(members.items(), key=lambda item: (item[0].count("/"), item[0])):
            target = destination.parent / name
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise InstallerReleaseBuildError("runtime archive regular member has no bytes")
                body = source.read(member.size + 1)
                if len(body) != member.size:
                    raise InstallerReleaseBuildError("runtime archive member length changed during extraction")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    _write_all(fd, body)
                    os.fchmod(fd, 0o555 if member.mode & 0o111 else 0o444)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        for name, member in sorted(members.items()):
            if member.issym():
                target = destination.parent / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.symlink(member.linkname, target)
        for name, member in members.items():
            if member.issym():
                try:
                    resolved = (destination.parent / name).resolve(strict=True)
                except (OSError, RuntimeError):
                    raise InstallerReleaseBuildError("runtime archive symlink is broken or cyclic") from None
                if not _is_beneath(resolved, destination.resolve(strict=True)):
                    raise InstallerReleaseBuildError("runtime archive alias resolves outside its prefix")


def _resolve_runtime_archive_symlink(member_path: str, link_target: str) -> str:
    """Allow relative ``..`` components only when their normalized target stays in python/."""
    _validate_relative_path(member_path)
    if (not isinstance(link_target, str) or not link_target or link_target.startswith("/")
            or "\\" in link_target or "\x00" in link_target
            or any(ord(char) < 32 or ord(char) == 127 for char in link_target)
            or any(part in {"", "."} for part in link_target.split("/"))):
        raise InstallerReleaseBuildError("runtime archive symlink target is not a portable relative path")
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(member_path), link_target))
    if normalized == "python" or normalized.startswith("python/"):
        return normalized
    raise InstallerReleaseBuildError("runtime archive symlink escapes its fixed prefix")


def _write_all(fd: int, body: bytes) -> None:
    view = memoryview(body)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short protected runtime write")
        view = view[count:]


def _locate_bootstrap_python(root: Path) -> Path:
    candidates = (root / "bin/python3.14", root / "bin/python3", root / "bin/python")
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if _is_beneath(resolved, root.resolve(strict=True)) and resolved.is_file():
            return resolved
    raise InstallerReleaseBuildError("reviewed runtime archive has no contained CPython 3.14 executable")


def _probe_site_directory(executable: Path, root: Path) -> str:
    script = "import sysconfig; print(sysconfig.get_path('purelib'))"
    result = subprocess.run([str(executable), "-I", "-S", "-c", script], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/"}, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise InstallerReleaseBuildError("fixed isolated runtime sysconfig probe failed")
    try:
        path = Path(result.stdout.decode("ascii").strip()).resolve(strict=False)
        relative = path.relative_to(root.resolve(strict=True)).as_posix()
    except (UnicodeError, ValueError, OSError):
        raise InstallerReleaseBuildError("isolated runtime site directory escapes its fixed prefix") from None
    _validate_relative_path(relative)
    return relative


def _materialize_pyyaml_wheel(wheel: bytes, site_dir: Path) -> None:
    if len(wheel) != BOOTSTRAP_PYYAML_BYTES or hashlib.sha256(wheel).hexdigest() != BOOTSTRAP_PYYAML_SHA256:
        raise InstallerReleaseBuildError("dependency wheel is not the reviewed PyYAML payload")
    with zipfile.ZipFile(io.BytesIO(wheel)) as bundle:
        names = bundle.namelist()
        if len(names) > 256 or len(set(names)) != len(names):
            raise InstallerReleaseBuildError("dependency wheel member list is duplicate or overlong")
        rows: dict[str, bytes] = {}
        expanded = 0
        for name in names:
            _validate_relative_path(name.rstrip("/"))
            info = bundle.getinfo(name)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise InstallerReleaseBuildError("dependency wheel contains a link or special member")
            if info.is_dir():
                continue
            expanded += info.file_size
            if info.file_size > 4 * 1024 * 1024 or expanded > 16 * 1024 * 1024:
                raise InstallerReleaseBuildError("dependency wheel exceeds member or expanded bounds")
            # The pinned Linux ARM64 wheel splits its native extension package
            # into the reviewed top-level `_yaml` package as well as `yaml`.
            # Keep this exact package set closed; do not accept arbitrary
            # top-level wheel payloads merely because the wheel itself is pinned.
            if not (name.startswith(("yaml/", "_yaml/", "pyyaml-6.0.3.dist-info/"))):
                raise InstallerReleaseBuildError("dependency wheel contains an unreviewed package path")
            rows[name] = bundle.read(info)
        record_name = "pyyaml-6.0.3.dist-info/RECORD"
        wheel_meta = rows.get("pyyaml-6.0.3.dist-info/WHEEL", b"").decode("utf-8", "strict")
        if "Tag: cp314-cp314-manylinux_2_28_aarch64" not in wheel_meta and "Tag: cp314-cp314-manylinux2014_aarch64" not in wheel_meta:
            raise InstallerReleaseBuildError("dependency wheel does not carry the reviewed CPython ARM64 tag")
        _verify_wheel_record(rows, record_name)
        for name, body in rows.items():
            _write_relative_path(site_dir, name, body, 0o444)


def _verify_wheel_record(rows: Mapping[str, bytes], record_name: str) -> None:
    import base64
    import csv
    import io as _io
    record = rows.get(record_name)
    if record is None:
        raise InstallerReleaseBuildError("dependency wheel lacks RECORD")
    try:
        parsed = list(csv.reader(_io.StringIO(record.decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error):
        raise InstallerReleaseBuildError("dependency wheel RECORD is malformed") from None
    seen: set[str] = set()
    for row in parsed:
        if len(row) != 3 or row[0] in seen or row[0] not in rows:
            raise InstallerReleaseBuildError("dependency wheel RECORD does not exactly enumerate members")
        seen.add(row[0])
        body = rows[row[0]]
        if row[0] == record_name:
            if row[1] or row[2]:
                raise InstallerReleaseBuildError("dependency wheel RECORD self row must be unhashed")
        else:
            try:
                algo, encoded = row[1].split("=", 1)
                digest = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                size = int(row[2])
            except (ValueError, TypeError):
                raise InstallerReleaseBuildError("dependency wheel RECORD hash row is malformed") from None
            if algo != "sha256" or digest != hashlib.sha256(body).digest() or size != len(body):
                raise InstallerReleaseBuildError("dependency wheel RECORD digest or size mismatch")
    if seen != set(rows):
        raise InstallerReleaseBuildError("dependency wheel RECORD omits a package member")


def _write_relative_path(root: Path, relative: str, body: bytes, mode: int) -> None:
    _validate_relative_path(relative)
    path = root / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        _write_all(fd, body)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _probe_materialized_runtime(executable: Path, prefix: Path, site_dir: Path) -> Mapping[str, Any]:
    script = ("import importlib.util,json,platform,sys,sysconfig; "
              "sys.path.insert(0, sys.argv[1]); import yaml; "
              "assert sys.version_info[:3] == (3,14,7); "
              "assert sys.implementation.name == 'cpython'; "
              "assert sys.implementation.cache_tag == 'cpython-314'; "
              "assert platform.machine().lower() in ('aarch64','arm64'); "
              "assert yaml.__version__ == '6.0.3'; "
              "assert importlib.util.find_spec('yaml').origin.startswith(sys.argv[1] + '/'); "
              "assert importlib.util.find_spec('yaml._yaml').origin.startswith(sys.argv[1] + '/'); "
              "print(json.dumps({'version':list(sys.version_info[:3]),'implementation':sys.implementation.name,"
              "'cache_tag':sys.implementation.cache_tag,'soabi':sysconfig.get_config_var('SOABI'),"
              "'machine':platform.machine().lower(),'yaml':yaml.__version__},sort_keys=True))")
    result = subprocess.run([str(executable), "-I", "-S", "-c", script, str(site_dir)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/"}, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise InstallerReleaseBuildError("materialized runtime failed its exact interpreter and wheel probe")
    try:
        observation = json.loads(result.stdout.decode("ascii"))
    except (UnicodeError, ValueError):
        raise InstallerReleaseBuildError("materialized runtime probe output is malformed") from None
    if (observation.get("version") != [3, 14, 7] or observation.get("implementation") != "cpython"
            or observation.get("cache_tag") != "cpython-314" or observation.get("machine") != "aarch64"
            or not isinstance(observation.get("soabi"), str)
            or not observation["soabi"].startswith("cpython-314-")
            or "aarch64" not in observation["soabi"] or observation.get("yaml") != "6.0.3"):
        raise InstallerReleaseBuildError("materialized interpreter version, ABI, or dependency differs from policy")
    yaml_extension = Path(subprocess.run(
        [str(executable), "-I", "-S", "-c",
         "import sys; sys.path.insert(0,sys.argv[1]); import yaml._yaml; print(yaml._yaml.__file__)", str(site_dir)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": "/"}, check=True).stdout.decode("ascii").strip())
    if _elf_machine(yaml_extension) != 183:
        raise InstallerReleaseBuildError("PyYAML extension is not an AArch64 ELF object")
    if _elf_machine(executable) != 183:
        raise InstallerReleaseBuildError("selected interpreter is not an AArch64 ELF object")
    if not _is_beneath(executable.resolve(strict=True), prefix.resolve(strict=True)):
        raise InstallerReleaseBuildError("runtime executable escaped its selected prefix")
    return observation


def _elf_machine(path: Path) -> int:
    with path.open("rb") as source:
        header = source.read(20)
    if len(header) != 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        raise InstallerReleaseBuildError("bootstrap executable or extension is not little-endian ELF64")
    return int.from_bytes(header[18:20], "little")


def _runtime_archive_rows(root: Path) -> list[tuple[str, str, int, int, str | None]]:
    rows: list[tuple[str, str, int, int, str | None]] = []
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_gid != 0
            or stat.S_IMODE(root_info.st_mode) != 0o555):
        raise InstallerReleaseBuildError("runtime directory mode is not read-only sealed")
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in list(dirs):
            path = base / name
            if path.is_symlink():
                dirs.remove(name)
                _append_runtime_member(rows, root, path)
            else:
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                        or stat.S_IMODE(info.st_mode) != 0o555):
                    raise InstallerReleaseBuildError("runtime directory mode is not read-only sealed")
        for name in files:
            _append_runtime_member(rows, root, base / name)
    rows.sort(key=lambda row: row[0])
    return rows


def _append_runtime_member(rows: list[tuple[str, str, int, int, str | None]], root: Path, path: Path) -> None:
    info = path.lstat()
    rel = path.relative_to(root).as_posix()
    _validate_relative_path(rel)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        # The official CPython archive uses contained parent-relative aliases.
        # Validate them against the same closed `python/` prefix rule used by
        # extraction, rather than rejecting them as stand-alone source paths.
        _resolve_runtime_archive_symlink(f"python/{rel}", target)
        rows.append((rel, hashlib.sha256(target.encode()).hexdigest(), len(target.encode()), 0o777, target))
    elif (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and info.st_gid == 0
          and stat.S_IMODE(info.st_mode) in {0o444, 0o555}):
        digest, size = _hash_path(path, MAX_SOURCE_FILE_BYTES)
        rows.append((rel, digest, size, stat.S_IMODE(info.st_mode), None))
    elif stat.S_ISREG(info.st_mode):
        raise InstallerReleaseBuildError("runtime file mode is not read-only sealed")
    else:
        raise InstallerReleaseBuildError("materialized runtime closure contains a hardlink or special member")


def _hash_path(path: Path, maximum: int) -> tuple[str, int]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _hash_fd(fd, maximum)
    finally:
        os.close(fd)


def _seal_runtime_tree(root: Path) -> None:
    for directory, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            path = current / name
            if path.is_symlink():
                continue
            info = path.lstat()
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, _sealed_runtime_mode(info.st_mode), follow_symlinks=False)
        for name in dirs:
            path = current / name
            if not path.is_symlink():
                os.chown(path, 0, 0, follow_symlinks=False)
                os.chmod(path, 0o555, follow_symlinks=False)
        os.chown(current, 0, 0, follow_symlinks=False)
        os.chmod(current, 0o555, follow_symlinks=False)
        _fsync_dir(current)


def _sealed_runtime_mode(mode: int) -> int:
    return 0o555 if mode & 0o111 else 0o444


def _verify_runtime_materialization(root: Path, expected_closure: str) -> None:
    digest = _runtime_closure_digest(root)
    if digest != expected_closure:
        raise InstallerReleaseBuildError("retained bootstrap runtime closure changed")


def _runtime_closure_digest(root: Path) -> str:
    rows = _runtime_archive_rows(root)
    return hashlib.sha256(_canonical_json([
        {"path": row[0], "sha256": row[1], "size_bytes": row[2], "mode": row[3], "link_target": row[4]}
        for row in rows])).hexdigest()


def _find_current_provisioned_runtime(distribution_handle: str, executable: Path) -> _ProvisionedBootstrapRuntime:
    """Find the unique private provision receipt matching the process image."""
    _ensure_bootstrap_runtime_root()
    actual = executable.resolve(strict=True)
    root_fd = _open_secure_directory(BOOTSTRAP_RUNTIME_ROOT, expected_uid=0)
    matches: list[_ProvisionedBootstrapRuntime] = []
    try:
        with os.scandir(root_fd) as entries:
            for entry in entries:
                if not _SHA256.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                    continue
                receipt_dir = BOOTSTRAP_RUNTIME_ROOT / entry.name / "runtime-receipts"
                try:
                    receipt_fd = _open_secure_directory(receipt_dir, expected_uid=0)
                except (FileNotFoundError, InstallerReleaseBuildError):
                    continue
                try:
                    with os.scandir(receipt_fd) as records:
                        for record in records:
                            if not record.name.endswith(".json"):
                                continue
                            handle = record.name[:-5]
                            if not _HANDLE.fullmatch(handle):
                                continue
                            try:
                                runtime = _load_runtime_receipt(handle, distribution_handle)
                            except (BootstrapEnrollmentPending, InstallerReleaseBuildError):
                                continue
                            if runtime.executable.resolve(strict=True) == actual:
                                matches.append(runtime)
                finally:
                    os.close(receipt_fd)
    finally:
        os.close(root_fd)
    if len(matches) != 1:
        raise BootstrapEnrollmentPending("running executable has no unique retained installer runtime receipt")
    return matches[0]


def _find_runtime_executable(root: Path) -> Path:
    return _locate_bootstrap_python(root)


class RootInstallerRuntimeArtifactRegistry:
    def __init__(self):
        self._receipts: dict[str, VerifiedInstallerRuntimeArtifactReceipt] = {}

    def _mint_observed(self, package_name: str, version: str,
                       files: Mapping[str, str], locked_versions: frozenset[str]) -> str:
        normalized = _normalize_package_name(package_name)
        if (not _ID.fullmatch(normalized) or not isinstance(version, str)
                or version not in locked_versions or not files):
            raise InstallerReleaseBuildError("runtime package is not pinned by the selected requirements-runtime.txt")
        rows = tuple(sorted(files.items()))
        try:
            for path, digest in rows:
                _validate_relative_path(path)
                if not _SHA256.fullmatch(str(digest)):
                    raise InstallerReleaseBuildError("runtime package closure contains an invalid digest")
        except InstallerReleaseBuildError:
            raise
        if not rows:
            raise InstallerReleaseBuildError("runtime package closure contains an invalid measured file")
        handle = secrets.token_urlsafe(32)
        closure = _manifest_digest(dict(rows))
        self._receipts[handle] = VerifiedInstallerRuntimeArtifactReceipt(
            handle, normalized, version, rows, closure)
        return handle

    def resolve(self, handle: str) -> VerifiedInstallerRuntimeArtifactReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending("runtime artifact receipt handle is malformed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            raise BootstrapEnrollmentPending("runtime artifact receipt is absent from the root registry")
        return receipt


class RootInstallerInterpreterRegistry:
    """Observe the running bootstrap interpreter against the selected source lock."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 runtime_artifact_registry: RootInstallerRuntimeArtifactRegistry | None = None):
        if not isinstance(distribution_registry, RootInstallerDistributionRegistry):
            raise TypeError("interpreter registry requires the selected distribution registry")
        self.distribution_registry = distribution_registry
        self.runtime_artifact_registry = runtime_artifact_registry or RootInstallerRuntimeArtifactRegistry()
        if not isinstance(self.runtime_artifact_registry, RootInstallerRuntimeArtifactRegistry):
            raise TypeError("interpreter registry requires the root runtime-artifact registry")
        self._receipts: dict[str, VerifiedInstallerInterpreterReceipt] = {}
        self._provisioned: dict[str, _ProvisionedBootstrapRuntime] = {}

    def provision_selected_bootstrap_interpreter(self, distribution_handle: str) -> str:
        """Acquire the one reviewed ARM64 runtime and materialize its locked wheel.

        This is bounded source staging only. It refuses to run on a development
        host and does not execute the runtime; the root launcher must perform
        the journal-bound re-exec before observing an authority actor.
        """
        _require_linux_root()
        source = self.distribution_registry.resolve(distribution_handle)
        source.verify_current()
        if platform.machine().lower() not in {"aarch64", "arm64"}:
            raise BootstrapEnrollmentPending("first-source installer runtime is reviewed only for Linux aarch64")
        if not _is_glibc_aarch64():
            raise BootstrapEnrollmentPending("first-source installer runtime requires the reviewed glibc aarch64 ABI")
        lock_bytes = source.open_file(RUNTIME_REQUIREMENTS_PATH)
        try:
            lock_digest, _ = _hash_fd(lock_bytes, 4 * 1024 * 1024)
            os.lseek(lock_bytes, 0, os.SEEK_SET)
            lock_content = _read_exact_fd(lock_bytes, os.fstat(lock_bytes).st_size)
        finally:
            os.close(lock_bytes)
        if not _lock_contains_exact_pyyaml(lock_content):
            raise InstallerReleaseBuildError("selected runtime requirements do not bind the reviewed PyYAML wheel")
        now = time.monotonic()
        receipt_handle = secrets.token_urlsafe(32)
        runtime_bytes = _download_pinned(
            BOOTSTRAP_RUNTIME_ARCHIVE_URL, BOOTSTRAP_RUNTIME_ARCHIVE_SHA256,
            BOOTSTRAP_RUNTIME_ARCHIVE_BYTES, BOOTSTRAP_RUNTIME_MAX_DOWNLOAD)
        wheel_bytes = _download_pinned(
            BOOTSTRAP_PYYAML_URL, BOOTSTRAP_PYYAML_SHA256,
            BOOTSTRAP_PYYAML_BYTES, 1_048_576)
        _ensure_bootstrap_runtime_root()
        root_fd = _open_secure_directory(BOOTSTRAP_RUNTIME_ROOT, expected_uid=0)
        try:
            stage_name = ".stage-" + secrets.token_hex(16)
            os.mkdir(stage_name, 0o700, dir_fd=root_fd)
            stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=root_fd)
            stage = BOOTSTRAP_RUNTIME_ROOT / stage_name
            try:
                python_dir = stage / "python"
                python_dir.mkdir(mode=0o700)
                _extract_verified_runtime_archive(runtime_bytes, python_dir)
                executable = _locate_bootstrap_python(python_dir)
                site_rel = _probe_site_directory(executable, python_dir)
                site_dir = python_dir / site_rel
                site_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
                _materialize_pyyaml_wheel(wheel_bytes, site_dir)
                runtime_probe = _probe_materialized_runtime(executable, python_dir, site_dir)
                # The closure ID names the immutable tree we will retain, so
                # seal modes before calculating its digest and before rename.
                _seal_runtime_tree(python_dir)
                runtime_rows = _runtime_archive_rows(python_dir)
                runtime_closure = hashlib.sha256(_canonical_json([
                    {"path": row[0], "sha256": row[1], "size_bytes": row[2],
                     "mode": row[3], "link_target": row[4]}
                    for row in runtime_rows])).hexdigest()
                final = BOOTSTRAP_RUNTIME_ROOT / runtime_closure
                if final.exists():
                    _verify_runtime_materialization(final / "python", runtime_closure)
                    _remove_tree_no_follow(stage)
                else:
                    os.rename(stage_name, runtime_closure, src_dir_fd=root_fd, dst_dir_fd=root_fd)
                    os.fsync(root_fd)
                prefix = final if final.exists() else BOOTSTRAP_RUNTIME_ROOT / runtime_closure
                executable_final = _find_runtime_executable(prefix / "python")
                exe_fd = os.open(executable_final, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    exe_info = os.fstat(exe_fd)
                    exe_sha, _ = _hash_fd(exe_fd, MAX_SOURCE_FILE_BYTES)
                finally:
                    os.close(exe_fd)
                record = _ProvisionedBootstrapRuntime(
                    receipt_handle=receipt_handle, distribution_receipt_handle=distribution_handle,
                    candidate_git_sha=source.candidate_git_sha, prefix=prefix / "python",
                    executable=executable_final, runtime_artifact_sha256=BOOTSTRAP_RUNTIME_ARCHIVE_SHA256,
                    dependency_artifact_sha256=BOOTSTRAP_PYYAML_SHA256,
                    requirements_runtime_sha256=lock_digest, runtime_closure_sha256=runtime_closure,
                    executable_sha256=exe_sha, executable_device=exe_info.st_dev,
                    executable_inode=exe_info.st_ino, issued_monotonic=now,
                    expires_monotonic=now + BOOTSTRAP_RUNTIME_TTL_SECONDS,
                    soabi=runtime_probe["soabi"], site_relative_path=site_rel)
                records_dir = prefix / "runtime-receipts"
                records_dir.mkdir(mode=0o700, exist_ok=True)
                _write_private_json(records_dir / (receipt_handle + ".json"), _runtime_receipt_json(record))
                self._provisioned[receipt_handle] = record
                return receipt_handle
            except BaseException:
                if stage.exists():
                    _remove_tree_no_follow(stage)
                raise
            finally:
                os.close(stage_fd)
        finally:
            os.close(root_fd)

    def resolve_interpreter(self, handle: str, distribution_handle: str) -> "_ProvisionedBootstrapRuntime":
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending("bootstrap runtime receipt handle is malformed")
        runtime = self._provisioned.get(handle)
        if runtime is None:
            runtime = _load_runtime_receipt(handle, distribution_handle)
            self._provisioned[handle] = runtime
        if runtime.distribution_receipt_handle != distribution_handle:
            raise BootstrapEnrollmentPending("bootstrap runtime receipt is not retained for this source")
        if time.monotonic() >= runtime.expires_monotonic:
            raise BootstrapEnrollmentPending("bootstrap runtime receipt expired")
        source = self.distribution_registry.resolve(distribution_handle)
        source.verify_current()
        if source.candidate_git_sha != runtime.candidate_git_sha:
            raise InstallerReleaseBuildError("bootstrap runtime receipt belongs to another candidate")
        lock_fd = source.open_file(RUNTIME_REQUIREMENTS_PATH)
        try:
            lock_sha, _ = _hash_fd(lock_fd, 4 * 1024 * 1024)
        finally:
            os.close(lock_fd)
        if lock_sha != runtime.requirements_runtime_sha256:
            raise InstallerReleaseBuildError("bootstrap runtime requirements lock changed")
        _verify_runtime_materialization(runtime.prefix, runtime.runtime_closure_sha256)
        fd = os.open(runtime.executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            digest, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (digest != runtime.executable_sha256 or info.st_dev != runtime.executable_device
                    or info.st_ino != runtime.executable_inode or info.st_uid != 0 or info.st_gid != 0):
                raise InstallerReleaseBuildError("bootstrap interpreter executable identity changed")
        finally:
            os.close(fd)
        return runtime

    @classmethod
    def from_owned_source_CAS(cls, distribution_registry: RootInstallerDistributionRegistry,
                              root_journal: object,
                              actual_runtime_artifact_registry: RootInstallerRuntimeArtifactRegistry
                              ) -> "RootInstallerInterpreterRegistry":
        if root_journal is None:
            raise TypeError("interpreter observer requires the retained root journal")
        return cls(distribution_registry, actual_runtime_artifact_registry)

    def observe_current_bootstrap_interpreter(self, distribution_handle: str) -> str:
        _require_linux_root()
        source = self.distribution_registry.resolve(distribution_handle)
        source.verify_current()
        if not sys.flags.isolated or sys.flags.no_user_site != 1 or not sys.prefix:
            raise BootstrapEnrollmentPending("bootstrap process is not running in isolated mode")
        executable_path = Path(f"/proc/{os.getpid()}/exe")
        try:
            executable_real = executable_path.resolve(strict=True)
            configured_executable = Path(sys.executable).resolve(strict=True)
        except OSError:
            raise BootstrapEnrollmentPending("actual bootstrap interpreter executable is unavailable") from None
        if executable_real != configured_executable:
            raise InstallerReleaseBuildError("Python runtime executable differs from the kernel process executable")
        provisioned = _find_current_provisioned_runtime(distribution_handle, executable_real)
        if provisioned.candidate_git_sha != source.candidate_git_sha:
            raise InstallerReleaseBuildError("running interpreter receipt belongs to another source candidate")
        prefix_path = provisioned.prefix.resolve(strict=True)
        if Path(sys.prefix).resolve(strict=True) != prefix_path:
            raise BootstrapEnrollmentPending("running interpreter prefix differs from the provisioned installer runtime")
        prefix_fd = _open_secure_directory(prefix_path, expected_uid=0)
        try:
            prefix_info = os.fstat(prefix_fd)
            runtime_files = _scan_runtime_prefix(prefix_fd, expected_uid=0, expected_gid=0)
            runtime_digest = _runtime_closure_digest(prefix_path)
            if runtime_digest != provisioned.runtime_closure_sha256:
                raise InstallerReleaseBuildError("running interpreter closure differs from the provisioned runtime receipt")
            executable_rel = _relative_below(prefix_path, executable_real)
            executable_row = next((row for row in runtime_files if row.relative_path == executable_rel), None)
            if executable_row is None:
                raise BootstrapEnrollmentPending("running interpreter is outside its dedicated runtime prefix")
            executable_fd = _open_relative(prefix_fd, executable_rel, os.O_RDONLY)
            try:
                executable_info = os.fstat(executable_fd)
                executable_sha, executable_size = _hash_fd(executable_fd, MAX_SOURCE_FILE_BYTES)
            except BaseException:
                os.close(executable_fd)
                raise
            if (executable_sha != executable_row.sha256 or executable_size == 0
                    or not executable_info.st_mode & 0o111):
                os.close(executable_fd)
                raise InstallerReleaseBuildError("runtime executable bytes differ from the measured prefix")
            project = _read_relative(source._root_fd, "pyproject.toml", 1024 * 1024)
            lock = _read_relative(source._root_fd, RUNTIME_REQUIREMENTS_PATH, 4 * 1024 * 1024)
            _require_python_requirement(project)
            stdlib_root = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
            stdlib_prefix = Path(sys.prefix).resolve(strict=True)
            if stdlib_prefix != prefix_path or not _is_beneath(stdlib_root, stdlib_prefix):
                os.close(executable_fd)
                raise BootstrapEnrollmentPending("stdlib is outside the selected isolated installer runtime prefix")
            stdlib_rel = stdlib_root.relative_to(stdlib_prefix).as_posix()
            stdlib_rows = tuple(row for row in runtime_files
                                if row.relative_path == stdlib_rel or row.relative_path.startswith(stdlib_rel + "/"))
            if not stdlib_rows:
                os.close(executable_fd)
                raise BootstrapEnrollmentPending("isolated runtime has no measured standard-library closure")
            locked_packages = _locked_package_versions(lock)
            package_rows, artifact_handles = _runtime_dependency_receipts(
                prefix_path, locked_packages, self.runtime_artifact_registry)
            dependency_digest = _manifest_digest({name: digest for name, digest in package_rows})
            stdlib_digest = _manifest_digest({row.relative_path: row.sha256 for row in stdlib_rows})
            now = time.monotonic()
            handle = secrets.token_urlsafe(32)
            receipt = VerifiedInstallerInterpreterReceipt(
                _SEAL, receipt_handle=handle, distribution_receipt_handle=distribution_handle,
                candidate_git_sha=source.candidate_git_sha,
                runtime_artifact_receipt_handles=artifact_handles,
                executable_sha256=executable_sha, executable_device=executable_info.st_dev,
                executable_inode=executable_info.st_ino, runtime_prefix_sha256=runtime_digest,
                stdlib_closure_sha256=stdlib_digest, dependency_closure_sha256=dependency_digest,
                python_version=platform.python_version(), implementation=sys.implementation.name,
                cache_tag=sys.implementation.cache_tag or "", soabi=str(sysconfig.get_config_var("SOABI") or ""),
                machine=platform.machine(), owner_uid=prefix_info.st_uid, owner_gid=prefix_info.st_gid,
                mode=stat.S_IMODE(prefix_info.st_mode), issued_monotonic=now,
                expires_monotonic=now + RECEIPT_TTL_SECONDS, files=runtime_files,
                runtime_prefix=prefix_path, prefix_fd=prefix_fd, exe_fd=executable_fd)
            receipt.verify_current()
            if (receipt.executable_sha256 != provisioned.executable_sha256
                    or receipt.executable_device != provisioned.executable_device
                    or receipt.executable_inode != provisioned.executable_inode
                    or receipt.runtime_prefix != provisioned.prefix):
                receipt.close()
                raise InstallerReleaseBuildError("observed process differs from the retained interpreter provision receipt")
            self._receipts[handle] = receipt
            return handle
        except BaseException:
            os.close(prefix_fd)
            raise

    def resolve(self, handle: str, distribution_handle: str) -> VerifiedInstallerInterpreterReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending("installer interpreter receipt handle is malformed")
        receipt = self._receipts.get(handle)
        if (receipt is None or receipt.distribution_receipt_handle != distribution_handle
                or receipt.candidate_git_sha != self.distribution_registry.resolve(distribution_handle).candidate_git_sha):
            raise BootstrapEnrollmentPending("installer interpreter proof does not match this selected source")
        receipt.verify_current()
        return receipt

    def resolve_runtime_artifact(self, handle: str, interpreter_handle: str) -> VerifiedInstallerRuntimeArtifactReceipt:
        interpreter = self._receipts.get(interpreter_handle)
        if (interpreter is None
                or handle not in interpreter.runtime_artifact_receipt_handles):
            raise BootstrapEnrollmentPending("runtime artifact receipt is absent or not bound to this interpreter")
        interpreter.verify_current()
        artifact = self.runtime_artifact_registry.resolve(handle)
        actual_rows = dict(_runtime_artifact_current_files(interpreter, artifact))
        if actual_rows != dict(artifact.files):
            raise InstallerReleaseBuildError("runtime artifact package bytes changed after observation")
        return artifact


class VerifiedRootSourceBootstrapActor:
    """PIDFD-bound proof that the current root process loaded the selected bootstrap source."""

    __slots__ = ("receipt_handle", "distribution_receipt_handle", "interpreter_receipt_handle",
                 "candidate_git_sha", "entry_module", "entry_symbol", "module_closure_sha256",
                 "executable_sha256", "pid", "pid_start_ticks", "pidfd_identity", "uid", "gid",
                 "issued_monotonic", "expires_monotonic", "module_rows", "_pidfd", "_seal")

    def __init__(self, seal: object, *, receipt_handle: str, distribution_receipt_handle: str,
                 interpreter_receipt_handle: str, candidate_git_sha: str,
                 module_rows: tuple[tuple[str, str, str, int, int], ...], executable_sha256: str,
                 pid: int, pid_start_ticks: int, pidfd: int, issued_monotonic: float,
                 expires_monotonic: float):
        if seal is not _SEAL:
            raise TypeError("bootstrap actor receipts can only be minted by RootSourceBootstrapActorVerifier")
        self.receipt_handle = receipt_handle
        self.distribution_receipt_handle, self.interpreter_receipt_handle = distribution_receipt_handle, interpreter_receipt_handle
        self.candidate_git_sha, self.entry_module = candidate_git_sha, "hermes_installer.authority.installer_release_build"
        self.entry_symbol, self.module_rows = "bootstrap_selected_release", module_rows
        self.module_closure_sha256 = _manifest_digest({name: digest for name, _, digest, _, _ in module_rows})
        self.executable_sha256 = executable_sha256
        self.pid, self.pid_start_ticks = pid, pid_start_ticks
        self._pidfd = pidfd
        self.pidfd_identity = f"{os.fstat(pidfd).st_dev}:{os.fstat(pidfd).st_ino}"
        self.uid, self.gid = os.getuid(), os.getgid()
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, expires_monotonic
        self._pidfd, self._seal = pidfd, seal

    def verify_current(self, distribution: VerifiedInstallerDistributionReceipt,
                       interpreter: VerifiedInstallerInterpreterReceipt) -> None:
        if self._seal is not _SEAL or time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("root source bootstrap actor proof is absent or expired")
        distribution.verify_current()
        interpreter.verify_current()
        if (os.getpid() != self.pid or os.getuid() != 0 or os.geteuid() != 0
                or _process_start_ticks(self.pid) != self.pid_start_ticks
                or self.uid != 0 or self.gid != 0):
            raise InstallerReleaseBuildError("current root source actor identity changed")
        try:
            if os.readlink(f"/proc/self/exe") != os.readlink(f"/proc/{self.pid}/exe"):
                raise InstallerReleaseBuildError("root source actor executable changed")
        except OSError:
            raise BootstrapEnrollmentPending("root source actor executable identity is unavailable") from None
        poll = __import__("select").poll()
        poll.register(self._pidfd, __import__("select").POLLIN | __import__("select").POLLHUP)
        if poll.poll(0):
            raise InstallerReleaseBuildError("root source actor process exited")
        for module_name, expected_path, digest, device, inode in self.module_rows:
            module = sys.modules.get(module_name)
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            if origin != expected_path:
                raise InstallerReleaseBuildError("loaded installer module origin differs from selected source")
            fd = distribution.open_file(_relative_below(distribution_root(distribution), Path(expected_path)))
            try:
                info = os.fstat(fd)
                actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if actual != digest or info.st_dev != device or info.st_ino != inode:
                    raise InstallerReleaseBuildError("loaded installer module bytes or inode changed")
            finally:
                os.close(fd)

    def close(self) -> None:
        os.close(self._pidfd)
        self._pidfd = -1


class RootSourceBootstrapActorVerifier:
    """Finite verifier for first-source root actor, independent of deployed pointers."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 interpreter_registry: RootInstallerInterpreterRegistry):
        if (not isinstance(distribution_registry, RootInstallerDistributionRegistry)
                or not isinstance(interpreter_registry, RootInstallerInterpreterRegistry)
                or interpreter_registry.distribution_registry is not distribution_registry):
            raise TypeError("source actor verifier requires one selected distribution/interpreter registry pair")
        self.distribution_registry, self.interpreter_registry = distribution_registry, interpreter_registry
        self._actors: dict[tuple[str, str], VerifiedRootSourceBootstrapActor] = {}

    @classmethod
    def from_verified_source(cls, distribution_registry: RootInstallerDistributionRegistry,
                             interpreter_registry: RootInstallerInterpreterRegistry) -> "RootSourceBootstrapActorVerifier":
        return cls(distribution_registry, interpreter_registry)

    def verify_current(self, distribution_handle: str,
                       interpreter_handle: str) -> VerifiedRootSourceBootstrapActor:
        _require_linux_root()
        distribution = self.distribution_registry.resolve(distribution_handle)
        interpreter = self.interpreter_registry.resolve(interpreter_handle, distribution_handle)
        if interpreter.candidate_git_sha != distribution.candidate_git_sha:
            raise InstallerReleaseBuildError("bootstrap interpreter was not observed for the selected candidate")
        distribution.verify_current()
        interpreter.verify_current()
        module_rows: list[tuple[str, str, str, int, int]] = []
        loaded_installer = [(name, module) for name, module in tuple(sys.modules.items())
                            if name == "hermes_installer" or name.startswith("hermes_installer.")]
        if not loaded_installer:
            raise BootstrapEnrollmentPending("selected installer source modules are not loaded in the root bootstrap actor")
        source_by_path = {row.relative_path: row for row in distribution.files}
        root = distribution_root(distribution)
        prefix = interpreter.runtime_prefix.resolve(strict=True)
        stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        allowed_paths = {str(prefix), str(root.resolve(strict=True)), str(stdlib)}
        runtime_members = {item.relative_path for item in interpreter.files}
        optional_stdlib_zip = prefix / "lib" / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
        for path in sys.path:
            if not path:
                raise InstallerReleaseBuildError("bootstrap actor imports from the ambient working directory")
            candidate = Path(path)
            try:
                resolved = candidate.resolve(strict=True)
            except FileNotFoundError:
                # CPython includes an optional stdlib zip archive in sys.path
                # even when the standalone runtime ships the expanded stdlib
                # directory only. Permit only that exact absent runtime path;
                # all other missing import roots remain a closed failure.
                if (candidate == optional_stdlib_zip
                        and _is_absent_optional_stdlib_zip(candidate, prefix, runtime_members)):
                    continue
                raise InstallerReleaseBuildError("bootstrap actor import path is unavailable") from None
            if candidate == optional_stdlib_zip and optional_stdlib_zip.relative_to(prefix).as_posix() not in runtime_members:
                raise InstallerReleaseBuildError("optional stdlib archive is absent from the measured runtime closure")
            if not any(_is_beneath(resolved, Path(base)) for base in allowed_paths):
                raise InstallerReleaseBuildError("bootstrap actor import path is outside selected source/runtime closure")
        for name, module in tuple(sys.modules.items()):
            spec = getattr(module, "__spec__", None)
            origin = getattr(spec, "origin", None)
            if origin in {None, "built-in", "frozen"}:
                continue
            if not isinstance(origin, str) or not Path(origin).is_absolute():
                raise InstallerReleaseBuildError("loaded module has a non-file or relative origin")
            resolved_origin = Path(origin).resolve(strict=True)
            if name == "hermes_installer" or name.startswith("hermes_installer."):
                continue
            if not (_is_beneath(resolved_origin, prefix) or _is_beneath(resolved_origin, stdlib)):
                raise InstallerReleaseBuildError("loaded dependency module is outside measured interpreter closure")
        for name, module in sorted(loaded_installer):
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            if not isinstance(origin, str):
                raise InstallerReleaseBuildError("loaded installer module has no immutable source origin")
            relative = _relative_below(root, Path(origin))
            source_path = "src/" + relative.removeprefix("src/")
            row = source_by_path.get(source_path)
            if row is None:
                raise InstallerReleaseBuildError("loaded installer module is outside the verified candidate tree")
            if (name == "hermes_installer.authority.installer_release_build"
                    and not callable(getattr(module, "bootstrap_selected_release", None))):
                raise InstallerReleaseBuildError("selected release module lacks its fixed bootstrap entrypoint")
            fd = distribution.open_file(source_path)
            try:
                info = os.fstat(fd)
                actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if actual != row.sha256:
                    raise InstallerReleaseBuildError("loaded installer module bytes differ from source CAS")
                module_rows.append((name, str(Path(origin)), actual, info.st_dev, info.st_ino))
            finally:
                os.close(fd)
        if not any(row[0] == "hermes_installer.authority.installer_release_build" for row in module_rows):
            raise BootstrapEnrollmentPending("selected release build module is not part of the current root actor")
        pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            now = time.monotonic()
            actor = VerifiedRootSourceBootstrapActor(
                _SEAL, receipt_handle=secrets.token_urlsafe(32),
                distribution_receipt_handle=distribution_handle,
                interpreter_receipt_handle=interpreter_handle,
                candidate_git_sha=distribution.candidate_git_sha,
                module_rows=tuple(module_rows), executable_sha256=interpreter.executable_sha256,
                pid=os.getpid(), pid_start_ticks=_process_start_ticks(os.getpid()), pidfd=pidfd,
                issued_monotonic=now, expires_monotonic=min(interpreter.expires_monotonic,
                                                             now + RECEIPT_TTL_SECONDS))
            actor.verify_current(distribution, interpreter)
            self._actors[(distribution_handle, interpreter_handle)] = actor
            return actor
        except BaseException:
            os.close(pidfd)
            raise

    def resolve_current(self, distribution_handle: str,
                        interpreter_handle: str) -> VerifiedRootSourceBootstrapActor:
        actor = self._actors.get((distribution_handle, interpreter_handle))
        if actor is None:
            raise BootstrapEnrollmentPending("current source bootstrap actor proof is absent")
        actor.verify_current(self.distribution_registry.resolve(distribution_handle),
                             self.interpreter_registry.resolve(interpreter_handle, distribution_handle))
        return actor


BOOTSTRAP_HANDOFF_ROOT = Path("/var/lib/hermes-installer/bootstrap-handoffs")
_HANDOFF_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class RootBootstrapRuntimeHandoff:
    """Sealed identity for the same-PID first-source runtime transition."""

    schema: int
    handoff_handle: str
    candidate_selection_sha256: str
    lifecycle_action: str
    distribution_receipt_handle: str
    interpreter_receipt_handle: str
    candidate_git_sha: str
    source_tree_digest: str
    runtime_closure_sha256: str
    expected_executable_sha256: str
    original_pid: int
    original_start_ticks: int
    original_uid: int
    nonce: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __init__(self, seal: object, **values: Any):
        if seal is not _HANDOFF_SEAL:
            raise TypeError("bootstrap handoffs can only be issued by the root handoff registry")
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", seal)


class RootBootstrapRuntimeHandoffRegistry:
    """Root-owned journal and sealed FD3 transition for the initial runtime."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 interpreter_registry: RootInstallerInterpreterRegistry,
                 candidate_selection_registry: object | None, journal_root: Path):
        if not isinstance(distribution_registry, RootInstallerDistributionRegistry):
            raise TypeError("bootstrap handoff requires the root source CAS registry")
        if not isinstance(interpreter_registry, RootInstallerInterpreterRegistry):
            raise TypeError("bootstrap handoff requires the root interpreter registry")
        if journal_root != BOOTSTRAP_HANDOFF_ROOT:
            raise ValueError("bootstrap handoff journal path is fixed by policy")
        self.distribution_registry = distribution_registry
        self.interpreter_registry = interpreter_registry
        self.candidate_selection_registry = candidate_selection_registry
        self.journal_root = journal_root
        self._memfds: dict[str, int] = {}
        self._pidfds: dict[str, int] = {}
        self._selection_fds: dict[str, tuple[int, int]] = {}
        self._handoffs: dict[str, RootBootstrapRuntimeHandoff] = {}

    @classmethod
    def from_source_bootstrap(cls, distribution_registry: RootInstallerDistributionRegistry,
                              interpreter_registry: RootInstallerInterpreterRegistry,
                              candidate_selection_registry: object,
                              owned_journal_root: Path) -> "RootBootstrapRuntimeHandoffRegistry":
        _require_linux_root()
        _ensure_bootstrap_handoff_root()
        return cls(distribution_registry, interpreter_registry,
                   candidate_selection_registry, owned_journal_root)

    @classmethod
    def from_reexec(cls, distribution_registry: RootInstallerDistributionRegistry,
                    interpreter_registry: RootInstallerInterpreterRegistry) -> "RootBootstrapRuntimeHandoffRegistry":
        _require_linux_root()
        _ensure_bootstrap_handoff_root()
        return cls(distribution_registry, interpreter_registry, None, BOOTSTRAP_HANDOFF_ROOT)

    def create_for_current_process(self, distribution_handle: str,
                                   interpreter_receipt_handle: str,
                                   selection: object) -> RootBootstrapRuntimeHandoff:
        _require_linux_root()
        try:
            from hermes_installer.root_setup import VerifiedRootBootstrapCandidateSelection
        except ImportError:
            raise BootstrapEnrollmentPending("root candidate selection proof type is unavailable") from None
        if not isinstance(selection, VerifiedRootBootstrapCandidateSelection):
            raise TypeError("runtime handoff requires the existing typed root TTY selection proof")
        if self.candidate_selection_registry is None:
            raise TypeError("runtime handoff creation requires the issuing candidate selection registry")
        snapshot = self.candidate_selection_registry.consume_verified_selection(selection)
        controller_pidfd = tty_fd = -1
        try:
            controller_pidfd, tty_fd = snapshot.duplicate_controller_fds()
            selection_values = _candidate_snapshot_fields(snapshot)
        finally:
            close_snapshot = getattr(snapshot, "close", None)
            if callable(close_snapshot):
                close_snapshot()
        memfd = -1
        try:
            source = self.distribution_registry.resolve(distribution_handle)
            runtime = self.interpreter_registry.resolve_interpreter(interpreter_receipt_handle, distribution_handle)
            if source.candidate_git_sha != selection.candidate_git_sha or runtime.candidate_git_sha != source.candidate_git_sha:
                raise InstallerReleaseBuildError("candidate choice, source CAS, and runtime receipt do not join")
            if getattr(selection, "input_origin", None) != "root_tty_explicit":
                raise InstallerReleaseBuildError("bootstrap source selection did not originate at the root TTY")
            if getattr(selection, "lifecycle_action", None) not in {"install", "resume", "update"}:
                raise InstallerReleaseBuildError("bootstrap lifecycle action is not a reviewed finite intent")
            if selection_values.get("lifecycle_action") != selection.lifecycle_action:
                raise InstallerReleaseBuildError("lifecycle action changed between typed choice and TTY snapshot")
            modules = _measure_current_source_modules(source, require_source_origin=False)
            pid, start, uid = os.getpid(), _process_start_ticks(os.getpid()), os.geteuid()
            if uid != 0 or os.getuid() != 0:
                raise BootstrapEnrollmentPending("runtime handoff requires the current Linux root process")
            pidfd = controller_pidfd
            if (not _pidfd_is_live(pidfd) or os.fstat(tty_fd).st_ino != selection_values["tty_inode"]
                    or os.fstat(tty_fd).st_dev != selection_values["tty_device"]
                    or os.fstat(tty_fd).st_rdev != selection_values["tty_rdevice"]):
                raise BootstrapEnrollmentPending("root candidate controller descriptors changed before handoff")
            memfd = os.memfd_create("hermes-bootstrap-handoff", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            handle, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            now = time.monotonic()
            message = _canonical_json({"schema": 1, "handoff_handle": handle, "nonce": nonce})
            if len(message) > 4096:
                raise InstallerReleaseBuildError("bootstrap descriptor message exceeds fixed bound")
            _write_all(memfd, message)
            os.fsync(memfd)
            constants = _memfd_seal_constants()
            seals = (constants["F_SEAL_WRITE"] | constants["F_SEAL_GROW"]
                     | constants["F_SEAL_SHRINK"] | constants["F_SEAL_SEAL"])
            fcntl.fcntl(memfd, constants["F_ADD_SEALS"], seals)
            descriptor = os.fstat(memfd)
            record = {
            "schema": 1, "state": "pending", "handoff_handle": handle,
            "candidate_selection_sha256": hashlib.sha256(_canonical_json(selection_values)).hexdigest(),
            "lifecycle_action": selection_values["lifecycle_action"],
                "selection_snapshot": selection_values,
                "distribution_receipt_handle": distribution_handle,
                "interpreter_receipt_handle": interpreter_receipt_handle,
                "candidate_git_sha": source.candidate_git_sha,
                "source_tree_digest": source.source_tree_sha256,
                "runtime_closure_sha256": runtime.runtime_closure_sha256,
                "site_relative_path": runtime.site_relative_path,
                "expected_executable_sha256": runtime.executable_sha256,
                "expected_executable_device": runtime.executable_device,
                "expected_executable_inode": runtime.executable_inode,
                "original_pid": pid, "original_start_ticks": start, "original_uid": uid,
                "nonce": nonce, "issued_monotonic": now,
                "expires_monotonic": min(runtime.expires_monotonic, now + BOOTSTRAP_RUNTIME_TTL_SECONDS),
                "boot_id": _current_boot_id(),
                "stage_driver_module_closure_sha256": hashlib.sha256(_canonical_json(modules)).hexdigest(),
                "memfd_device": descriptor.st_dev, "memfd_inode": descriptor.st_ino,
                "memfd_sha256": hashlib.sha256(message).hexdigest(),
            }
            _write_handoff_record(handle, record)
            handoff = _handoff_from_record(record)
            self._memfds[handle] = memfd
            self._pidfds[handle] = pidfd
            self._selection_fds[handle] = (pidfd, tty_fd)
            self._handoffs[handle] = handoff
            return handoff
        except (AttributeError, OSError):
            if memfd >= 0:
                os.close(memfd)
            for descriptor in {controller_pidfd, tty_fd}:
                if descriptor >= 0:
                    os.close(descriptor)
            raise BootstrapEnrollmentPending("kernel lacks sealed same-process bootstrap handoff support") from None
        except BaseException:
            if memfd >= 0:
                os.close(memfd)
            for descriptor in {controller_pidfd, tty_fd}:
                if descriptor >= 0:
                    os.close(descriptor)
            raise

    def reexec_selected_bootstrap(self, handoff: RootBootstrapRuntimeHandoff) -> None:
        if (not isinstance(handoff, RootBootstrapRuntimeHandoff) or handoff._seal is not _HANDOFF_SEAL
                or self._handoffs.get(handoff.handoff_handle) is not handoff):
            raise BootstrapEnrollmentPending("runtime re-exec requires this registry's live handoff")
        runtime = self.interpreter_registry.resolve_interpreter(
            handoff.interpreter_receipt_handle, handoff.distribution_receipt_handle)
        memfd = self._memfds.get(handoff.handoff_handle)
        if memfd is None:
            raise BootstrapEnrollmentPending("sealed runtime descriptor is not retained")
        try:
            os.dup2(memfd, 3, inheritable=True)
            os.lseek(3, 0, os.SEEK_SET)
            if memfd != 3:
                os.close(memfd)
            self._memfds.pop(handoff.handoff_handle, None)
            for descriptor in range(4, 4096):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            code = _fixed_reexec_entry_code()
            argv = _fixed_reexec_argv(runtime.executable)
            os.execve(runtime.executable, argv, {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                                                 "LC_ALL": "C.UTF-8"})
        except BaseException:
            self.revoke(handoff.handoff_handle)
            raise

    def take_current_reexec_handoff(self) -> RootBootstrapRuntimeHandoff:
        _require_linux_root()
        memfd = -1
        try:
            memfd = os.dup(3)
            parsed, info, message = _decode_sealed_handoff_descriptor(memfd)
        except (OSError, ValueError, UnicodeError):
            raise BootstrapEnrollmentPending("sealed bootstrap handoff descriptor is absent or malformed") from None
        finally:
            if memfd >= 0:
                os.close(memfd)
        # _decode_sealed_handoff_descriptor already checked kernel seals,
        # exact keys, canonical bytes, and bounded identity fields.
        if (_canonical_json(parsed) != message
                or set(parsed) != {"schema", "handoff_handle", "nonce"} or parsed.get("schema") != 1):
            raise InstallerReleaseBuildError("bootstrap handoff descriptor seals or canonical encoding changed")
        handle = parsed.get("handoff_handle")
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise InstallerReleaseBuildError("bootstrap handoff descriptor identity is malformed")
        record = _read_handoff_record(handle)
        if (parsed.get("nonce") != record.get("nonce") or info.st_dev != record.get("memfd_device")
                or info.st_ino != record.get("memfd_inode")
                or hashlib.sha256(message).hexdigest() != record.get("memfd_sha256")):
            raise InstallerReleaseBuildError("bootstrap handoff descriptor does not match its private journal")
        if (record.get("state") != "pending" or record.get("original_pid") != os.getpid()
                or record.get("original_start_ticks") != _process_start_ticks(os.getpid())
                or record.get("original_uid") != os.geteuid() or os.getuid() != 0
                or record.get("boot_id") != _current_boot_id()
                or time.monotonic() >= record.get("expires_monotonic", 0)):
            raise BootstrapEnrollmentPending("bootstrap handoff is foreign, expired, or already consumed")
        distribution_handle = record["distribution_receipt_handle"]
        source = self.distribution_registry.resolve(distribution_handle)
        runtime = self.interpreter_registry.resolve_interpreter(record["interpreter_receipt_handle"], distribution_handle)
        executable_path = Path(f"/proc/{os.getpid()}/exe").resolve(strict=True)
        executable_info = os.stat(executable_path)
        if (source.candidate_git_sha != record.get("candidate_git_sha")
                or source.source_tree_sha256 != record.get("source_tree_digest")
                or runtime.runtime_closure_sha256 != record.get("runtime_closure_sha256")
                or runtime.executable_sha256 != record.get("expected_executable_sha256")
                or executable_info.st_dev != record.get("expected_executable_device")
                or executable_info.st_ino != record.get("expected_executable_inode")
                or executable_path != runtime.executable.resolve(strict=True)):
            raise InstallerReleaseBuildError("re-executed process does not match selected source/runtime handoff")
        selection_snapshot = record.get("selection_snapshot")
        if (not isinstance(selection_snapshot, dict)
                or hashlib.sha256(_canonical_json(selection_snapshot)).hexdigest()
                != record.get("candidate_selection_sha256")):
            raise InstallerReleaseBuildError("handoff root candidate snapshot digest is invalid")
        _verify_current_selection_snapshot(selection_snapshot, record)
        # Stage-zero modules are a different, bounded driver closure.  The
        # selected image must independently load only matching SourceCAS
        # modules; it is not required to preserve stage-zero module identities.
        _measure_current_source_modules(source, require_source_origin=True)
        _consume_handoff_record(handle, record)
        os.close(3)
        handoff = _handoff_from_record(record)
        return handoff

    def revoke(self, handle: str) -> None:
        fd = self._memfds.pop(handle, None)
        if fd is not None:
            os.close(fd)
        pidfd = self._pidfds.pop(handle, None)
        if pidfd is not None:
            os.close(pidfd)
        retained = self._selection_fds.pop(handle, None)
        if retained is not None:
            for descriptor in set(retained):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self._handoffs.pop(handle, None)
        try:
            record = _read_handoff_record(handle)
            if record.get("state") == "pending":
                _transition_handoff_record(handle, record, "revoked")
        except (OSError, InstallerReleaseBuildError, BootstrapEnrollmentPending):
            # Revocation remains best-effort during teardown. The pending lease
            # is still bounded by its short expiry if the journal is unavailable.
            pass


@dataclass(frozen=True, slots=True)
class BuildOutputFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    roles: tuple[str, ...]
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class DeploymentPredecessor:
    """Exact predecessor snapshot; absent is a proven state, never a wildcard."""

    state: str
    parent_device: int
    parent_inode: int
    sha256: str | None = None
    device: int | None = None
    inode: int | None = None
    candidate_git_sha: str | None = None


class VerifiedDeploymentPredecessor:
    """Short-lived typed observation of the exact protected deployment pointer."""

    __slots__ = ("schema", "state", "parent_device", "parent_inode", "candidate_git_sha",
                 "deployment_receipt_sha256", "deployment_receipt_device", "deployment_receipt_inode",
                 "verified_release_receipt_handle", "issued_monotonic", "expires_monotonic", "_seal")

    def __init__(self, seal: object, *, state: str, parent_device: int, parent_inode: int,
                 candidate_git_sha: str | None, deployment_receipt_sha256: str | None,
                 deployment_receipt_device: int | None, deployment_receipt_inode: int | None,
                 verified_release_receipt_handle: str | None, issued_monotonic: float):
        if seal is not _DEPLOYMENT_PREDECESSOR_SEAL:
            raise TypeError("deployment predecessor proofs are root-minted")
        if state not in {"absent", "present-verified"}:
            raise ValueError("deployment predecessor state is not finite")
        self.schema, self.state = 1, state
        self.parent_device, self.parent_inode = parent_device, parent_inode
        self.candidate_git_sha = candidate_git_sha
        self.deployment_receipt_sha256 = deployment_receipt_sha256
        self.deployment_receipt_device, self.deployment_receipt_inode = (
            deployment_receipt_device, deployment_receipt_inode)
        self.verified_release_receipt_handle = verified_release_receipt_handle
        self.issued_monotonic = issued_monotonic
        self.expires_monotonic = issued_monotonic + 300.0
        self._seal = seal

    def verify_current(self) -> None:
        if self._seal is not _DEPLOYMENT_PREDECESSOR_SEAL or time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("deployment predecessor proof is foreign or expired")
        latest = _read_deployment_predecessor()
        if (latest.state == "absent") != (self.state == "absent"):
            raise BootstrapEnrollmentPending("deployment predecessor state changed")
        if (latest.parent_device != self.parent_device or latest.parent_inode != self.parent_inode
                or latest.candidate_git_sha != self.candidate_git_sha
                or latest.sha256 != self.deployment_receipt_sha256
                or latest.device != self.deployment_receipt_device
                or latest.inode != self.deployment_receipt_inode):
            raise BootstrapEnrollmentPending("deployment predecessor changed after observation")
        if self.state == "present-verified":
            _resolve_verified_deployment_release(self.verified_release_receipt_handle, consume=False)


class VerifiedInstallerReleaseBuildReceipt:
    """Sealed build-output custody consumed by the installed-stage publisher."""

    __slots__ = ("schema", "receipt_handle", "candidate_git_sha", "distribution_receipt_handle",
                 "interpreter_receipt_handle", "source_tree_sha256", "baseline_tree_sha256",
                 "amendment_manifest_sha256", "source_catalog_sha256", "role_closure_manifest_sha256",
                 "root_setup_plan_sha256", "build_output_store_id", "build_output_receipt_handle",
                 "builder_artifact_id", "builder_artifact_sha256", "issued_monotonic", "expires_monotonic",
                 "closure_manifest_relative_path", "closure_manifest_sha256", "deployment_predecessor",
                 "files", "_root_fd", "_root_device", "_root_inode", "_expected_uid", "_seal",
                 "_closed", "_consumed", "_handle")

    def __init__(self, seal: object, *, handle: str, candidate_git_sha: str,
                 distribution_receipt_handle: str, interpreter_receipt_handle: str,
                 source_tree_sha256: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, source_catalog_sha256: str,
                 role_closure_manifest_sha256: str, root_setup_plan_sha256: str,
                 builder_artifact_sha256: str, issued_monotonic: float,
                 deployment_predecessor: DeploymentPredecessor, files: tuple[BuildOutputFile, ...],
                 manifest_sha256: str, root_fd: int, expected_uid: int):
        if seal is not _SEAL:
            raise TypeError("release build receipts can only be minted by RootInstalledReleaseBuilder")
        self.schema = 1
        self.receipt_handle = handle
        self.candidate_git_sha = candidate_git_sha
        self.distribution_receipt_handle = distribution_receipt_handle
        self.interpreter_receipt_handle = interpreter_receipt_handle
        self.source_tree_sha256, self.baseline_tree_sha256 = source_tree_sha256, baseline_tree_sha256
        self.amendment_manifest_sha256, self.source_catalog_sha256 = amendment_manifest_sha256, source_catalog_sha256
        self.role_closure_manifest_sha256, self.root_setup_plan_sha256 = role_closure_manifest_sha256, root_setup_plan_sha256
        self.build_output_store_id, self.build_output_receipt_handle = RELEASE_BUILD_STORE_ID, handle
        self.builder_artifact_id, self.builder_artifact_sha256 = RELEASE_BUILDER_ARTIFACT_ID, builder_artifact_sha256
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, issued_monotonic + RECEIPT_TTL_SECONDS
        self.closure_manifest_relative_path, self.closure_manifest_sha256 = RELEASE_MANIFEST_PATH, manifest_sha256
        self.deployment_predecessor, self.files = deployment_predecessor, files
        info = os.fstat(root_fd)
        self._root_fd, self._root_device, self._root_inode = root_fd, info.st_dev, info.st_ino
        self._expected_uid, self._seal = expected_uid, seal
        self._closed, self._consumed, self._handle = False, False, handle

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._consumed or self._root_fd < 0:
            raise BootstrapEnrollmentPending("release build receipt is absent or already consumed")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("release build receipt expired before stage publication")
        root = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != self._expected_uid
                or stat.S_IMODE(root.st_mode) & 0o077 or root.st_dev != self._root_device
                or root.st_ino != self._root_inode):
            raise InstallerReleaseBuildError("release build output root custody changed")
        for row in self.files:
            fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != self._expected_uid or info.st_dev != row.device
                        or info.st_ino != row.inode or stat.S_IMODE(info.st_mode) != row.mode
                        or digest != row.sha256 or size != row.size_bytes):
                    raise InstallerReleaseBuildError("release build output bytes or identity changed")
            finally:
                os.close(fd)
        if _enumerate_regular_files(self._root_fd) != tuple(sorted(
                [row.relative_path for row in self.files] + [RELEASE_MANIFEST_PATH])):
            raise InstallerReleaseBuildError("release build output contains files outside its sealed closure")
        manifest = _read_relative(self._root_fd, RELEASE_MANIFEST_PATH, 16 * 1024 * 1024)
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        if manifest_sha != self.closure_manifest_sha256 or manifest_sha != self.role_closure_manifest_sha256:
            raise InstallerReleaseBuildError("release manifest bytes changed after build sealing")
        try:
            value = json.loads(manifest.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError, json.JSONDecodeError):
            raise InstallerReleaseBuildError("sealed release manifest is malformed") from None
        expected_rows = [{"relative_path": row.relative_path, "sha256": row.sha256,
                          "size_bytes": row.size_bytes, "mode": row.mode, "roles": list(row.roles)}
                         for row in self.files]
        if (not isinstance(value, dict) or set(value) != {"schema", "candidate_git_sha", "files"}
                or type(value.get("schema")) is not int or value.get("schema") != 1
                or value.get("candidate_git_sha") != self.candidate_git_sha
                or value.get("files") != expected_rows or _canonical_json(value) != manifest):
            raise InstallerReleaseBuildError("sealed manifest does not describe the retained role closure")

    def open_file(self, relative_path: str) -> int:
        # The publisher verifies the complete sealed closure before copying and
        # again before committing its pointer.  Repeating that whole-tree hash
        # here for every member turns a linear publication into O(files * tree
        # size).  Keep each copy independently bound to its exact retained row:
        # a no-follow FD, complete byte hash, metadata identity, and the same
        # live receipt/root custody checks.  The publisher's final full verify
        # detects sibling changes and additions before pointer publication.
        self._verify_live_root()
        row = next((item for item in self.files if item.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("publisher requested a file outside the sealed output closure")
        fd = _open_relative(self._root_fd, relative_path, os.O_RDONLY)
        try:
            before = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            after = os.fstat(fd)
            self._verify_live_root()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != self._expected_uid or before.st_dev != row.device
                    or before.st_ino != row.inode or stat.S_IMODE(before.st_mode) != row.mode
                    or before.st_size != row.size_bytes or digest != row.sha256 or size != row.size_bytes
                    or (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_nlink,
                        before.st_uid, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_nlink,
                        after.st_uid, after.st_mtime_ns, after.st_ctime_ns)):
                raise InstallerReleaseBuildError("release output changed while opening sealed file")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _verify_live_root(self) -> None:
        if self._seal is not _SEAL or self._closed or self._consumed or self._root_fd < 0:
            raise BootstrapEnrollmentPending("release build receipt is absent or already consumed")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("release build receipt expired before stage publication")
        root = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != self._expected_uid
                or stat.S_IMODE(root.st_mode) & 0o077 or root.st_dev != self._root_device
                or root.st_ino != self._root_inode):
            raise InstallerReleaseBuildError("release build output root custody changed")

    def open_manifest(self) -> int:
        self.verify_current()
        fd = _open_relative(self._root_fd, RELEASE_MANIFEST_PATH, os.O_RDONLY)
        digest, _ = _hash_fd(fd, 16 * 1024 * 1024)
        if digest != self.closure_manifest_sha256:
            os.close(fd)
            raise InstallerReleaseBuildError("release manifest changed while opening")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def consume(self) -> None:
        self.verify_current()
        self._consumed = True

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True


class RootInstalledReleaseBuilder:
    """Builds a fixed installed layout solely from retained source/runtime/actor proofs."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 interpreter_registry: RootInstallerInterpreterRegistry,
                 actor_verifier: RootSourceBootstrapActorVerifier):
        if (not isinstance(distribution_registry, RootInstallerDistributionRegistry)
                or not isinstance(interpreter_registry, RootInstallerInterpreterRegistry)
                or not isinstance(actor_verifier, RootSourceBootstrapActorVerifier)
                or interpreter_registry.distribution_registry is not distribution_registry
                or actor_verifier.distribution_registry is not distribution_registry
                or actor_verifier.interpreter_registry is not interpreter_registry):
            raise TypeError("release builder requires one fixed source/interpreter/actor registry graph")
        self.distribution_registry, self.interpreter_registry, self.actor_verifier = (
            distribution_registry, interpreter_registry, actor_verifier)
        self._receipts: dict[str, VerifiedInstallerReleaseBuildReceipt] = {}
        self._used: set[str] = set()

    def build_selected(self, distribution_handle: str, interpreter_handle: str) -> str:
        _require_linux_root()
        source = self.distribution_registry.resolve(distribution_handle)
        interpreter = self.interpreter_registry.resolve(interpreter_handle, distribution_handle)
        actor = self.actor_verifier.resolve_current(distribution_handle, interpreter_handle)
        actor.verify_current(source, interpreter)
        source.verify_current()
        interpreter.verify_current()
        if source.candidate_git_sha != interpreter.candidate_git_sha:
            raise InstallerReleaseBuildError("release source and interpreter receipts select different candidates")
        self._verify_builder_is_loaded_from_source(source)
        _ensure_root_directory(Path("/var/lib/hermes-installer/authority-journal"), 0o700)
        _ensure_root_directory(BUILD_CAS_ROOT.parent, 0o700)
        _ensure_root_directory(BUILD_CAS_ROOT, 0o700)
        if _tree_byte_usage(BUILD_CAS_ROOT) + 2 * MAX_SOURCE_TREE_BYTES > MAX_RELEASE_BUILD_CAS_BYTES:
            raise BootstrapEnrollmentPending("release build CAS has no bounded space for another sealed output")
        output = BUILD_CAS_ROOT / secrets.token_hex(24)
        os.mkdir(output, 0o700)
        root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            rows_without_identity = self._stage_fixed_layout(root_fd, source, interpreter, actor)
            plan_bytes = self._render_plan(source)
            _write_relative(root_fd, STAGED_PLAN_PATH, plan_bytes, mode=0o444)
            rows_without_identity.append((STAGED_PLAN_PATH, hashlib.sha256(plan_bytes).hexdigest(),
                                          len(plan_bytes), 0o444, ("plan",)))
            rows = self._seal_output_rows(root_fd, rows_without_identity)
            source.verify_current()
            interpreter.verify_current()
            actor.verify_current(source, interpreter)
            manifest_value = {"schema": 1, "candidate_git_sha": source.candidate_git_sha,
                              "files": [{"relative_path": row.relative_path, "sha256": row.sha256,
                                         "size_bytes": row.size_bytes, "mode": row.mode,
                                         "roles": list(row.roles)} for row in rows]}
            manifest_bytes = _canonical_json(manifest_value)
            if sum(row.size_bytes for row in rows) + len(manifest_bytes) > 2 * MAX_SOURCE_TREE_BYTES:
                raise InstallerReleaseBuildError("release output exceeds its fixed build-CAS size limit")
            _write_relative(root_fd, RELEASE_MANIFEST_PATH, manifest_bytes, mode=0o444)
            _fsync_tree(root_fd)
            _fsync_dir(output.parent)
            receipt_handle = secrets.token_urlsafe(32)
            receipt = VerifiedInstallerReleaseBuildReceipt(
                _SEAL, handle=receipt_handle, candidate_git_sha=source.candidate_git_sha,
                distribution_receipt_handle=distribution_handle, interpreter_receipt_handle=interpreter_handle,
                source_tree_sha256=source.source_tree_sha256,
                baseline_tree_sha256=source.baseline_tree_sha256,
                amendment_manifest_sha256=source.amendment_manifest_sha256,
                source_catalog_sha256=source.source_catalog_sha256,
                role_closure_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                root_setup_plan_sha256=next(row.sha256 for row in rows if row.relative_path == STAGED_PLAN_PATH),
                builder_artifact_sha256=self._builder_digest(source), issued_monotonic=time.monotonic(),
                deployment_predecessor=_read_deployment_predecessor(), files=rows,
                manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), root_fd=root_fd,
                expected_uid=os.geteuid())
            receipt.verify_current()
            self._receipts[receipt_handle] = receipt
            return receipt_handle
        except BaseException:
            os.close(root_fd)
            _remove_tree_no_follow(output)
            raise

    def resolve_build_receipt(self, handle: str, *, consume: bool = False) -> VerifiedInstallerReleaseBuildReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle) or handle in self._used:
            raise BootstrapEnrollmentPending("release build receipt is absent or already consumed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            raise BootstrapEnrollmentPending("release build receipt belongs to another root builder")
        receipt.verify_current()
        if consume:
            self._used.add(handle)
        return receipt

    @staticmethod
    def observe_deployment_predecessor() -> VerifiedDeploymentPredecessor:
        return observe_deployment_predecessor()

    def _verify_builder_is_loaded_from_source(self, source: VerifiedInstallerDistributionReceipt) -> None:
        module = sys.modules.get("hermes_installer.authority.installer_release_build")
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not isinstance(origin, str):
            raise BootstrapEnrollmentPending("release builder module is not loaded from selected source")
        relative = _relative_below(distribution_root(source), Path(origin))
        row = next((row for row in source.files if row.relative_path == relative), None)
        if row is None:
            raise InstallerReleaseBuildError("release builder is outside selected candidate source")
        fd = source.open_file(relative)
        try:
            actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if actual != row.sha256:
                raise InstallerReleaseBuildError("loaded release builder source bytes changed")
        finally:
            os.close(fd)

    def _builder_digest(self, source: VerifiedInstallerDistributionReceipt) -> str:
        module = sys.modules["hermes_installer.authority.installer_release_build"]
        relative = _relative_below(distribution_root(source), Path(module.__spec__.origin))
        row = next(item for item in source.files if item.relative_path == relative)
        return row.sha256

    def _stage_fixed_layout(self, output_fd: int, source: VerifiedInstallerDistributionReceipt,
                            interpreter: VerifiedInstallerInterpreterReceipt,
                            actor: VerifiedRootSourceBootstrapActor) -> list[tuple[str, str, int, int, tuple[str, ...]]]:
        source_files = {row.relative_path: row for row in source.files}
        staged: list[tuple[str, str, int, int, tuple[str, ...]]] = []
        self._copy_source(source, output_fd, STAGED_LAUNCHER_SOURCE, STAGED_LAUNCHER_PATH,
                          ("launcher",), executable=True)
        staged.append(self._last_output_row)
        runtime_fd = interpreter.open_executable()
        try:
            digest, size, body = _hash_and_read_fd(runtime_fd, MAX_SOURCE_FILE_BYTES)
            _write_relative(output_fd, STAGED_INTERPRETER_PATH, body, mode=0o555)
            staged.append((STAGED_INTERPRETER_PATH, digest, size, 0o555,
                           _runtime_output_roles(STAGED_INTERPRETER_PATH)))
        finally:
            os.close(runtime_fd)
        for row in interpreter.files:
            if row.relative_path.startswith("bin/") and row.relative_path == "bin/python" and row.relative_path != STAGED_INTERPRETER_PATH:
                continue
            if row.relative_path == _relative_below(interpreter.runtime_prefix, Path(sysconfig.get_path("stdlib")).resolve(strict=True)):
                pass
            fd = interpreter.open_runtime_file(row.relative_path)
            try:
                body = _read_exact_fd(fd, row.size_bytes)
            finally:
                os.close(fd)
            path = "runtime/" + row.relative_path
            if path == STAGED_INTERPRETER_PATH:
                continue
            mode = 0o555 if row.mode & 0o111 else 0o444
            _write_relative(output_fd, path, body, mode=mode)
            staged.append((path, row.sha256, row.size_bytes,
                           mode, _runtime_output_roles(path)))
        for source_path, target, role, expected_sha256, expected_size in (
            (PLAN_TEMPLATE_PATH, STAGED_PLAN_TEMPLATE_PATH, "template", PLAN_TEMPLATE_SHA256, PLAN_TEMPLATE_BYTES),
            (COMPILER_TEMPLATE_PATH, STAGED_COMPILER_TEMPLATE_PATH, "template",
             COMPILER_TEMPLATE_SHA256, COMPILER_TEMPLATE_BYTES),
            (IDENTITY_TEMPLATE_PATH, STAGED_IDENTITY_TEMPLATE_PATH, "template",
             IDENTITY_TEMPLATE_SHA256, IDENTITY_TEMPLATE_BYTES),
            (PREPARED_BASE_TEMPLATE_PATH, STAGED_PREPARED_BASE_TEMPLATE_PATH, "template",
             PREPARED_BASE_TEMPLATE_SHA256, PREPARED_BASE_TEMPLATE_BYTES),
            (RECEIPT_BINDINGS_TEMPLATE_PATH, STAGED_RECEIPT_BINDINGS_TEMPLATE_PATH, "template",
             RECEIPT_BINDINGS_TEMPLATE_SHA256, RECEIPT_BINDINGS_TEMPLATE_BYTES),
            (COMPOSIO_POLICY_TEMPLATE_PATH, STAGED_COMPOSIO_POLICY_TEMPLATE_PATH, "template",
             COMPOSIO_POLICY_TEMPLATE_SHA256, COMPOSIO_POLICY_TEMPLATE_BYTES),
            (EXISTING_MODEL_STORE_TEMPLATE_PATH, STAGED_EXISTING_MODEL_STORE_TEMPLATE_PATH, "template",
             EXISTING_MODEL_STORE_TEMPLATE_SHA256, EXISTING_MODEL_STORE_TEMPLATE_BYTES),
            (PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH, STAGED_PRIVATE_LOOPBACK_POLICY_TEMPLATE_PATH, "template",
             PRIVATE_LOOPBACK_POLICY_TEMPLATE_SHA256, PRIVATE_LOOPBACK_POLICY_TEMPLATE_BYTES),
            (REVIEWED_CAPABILITY_MAP_PATH, STAGED_REVIEWED_CAPABILITY_MAP_PATH, "template",
             REVIEWED_CAPABILITY_MAP_SHA256, REVIEWED_CAPABILITY_MAP_BYTES),
            (CATALOG_SOURCE_PATH, STAGED_CATALOG_PATH, "artifact-catalog", None, None),
        ):
            if source_path not in source_files:
                raise InstallerReleaseBuildError("fixed release layout source input is absent")
            row = source_files[source_path]
            if (expected_sha256 is not None
                    and (row.sha256 != expected_sha256 or row.size_bytes != expected_size)):
                raise InstallerReleaseBuildError("fixed installed template differs from its reviewed bytes")
            self._copy_source(source, output_fd, source_path, target, (role,))
            staged.append(self._last_output_row)
        helper_row = self._stage_network_startup_helper(source, output_fd)
        if helper_row is not None:
            staged.append(helper_row)
        # The v175 descriptor selects the exact setup-only effect source rows.
        effect_catalog = source_files.get(APPLICATION_EFFECT_SOURCE_CATALOG_PATH)
        if (effect_catalog is None or effect_catalog.sha256 != APPLICATION_EFFECT_SOURCE_CATALOG_SHA256
                or effect_catalog.size_bytes != APPLICATION_EFFECT_SOURCE_CATALOG_SIZE):
            raise InstallerReleaseBuildError("application effect source descriptor differs from its fixed pin")
        # Include exact full frozen baseline and selected amendment bytes under stable roots.
        for row in source.files:
            if row.relative_path.startswith(BASELINE_DIRECTORY + "/"):
                target = row.relative_path
                self._copy_source(source, output_fd, row.relative_path, target, ("baseline",))
                staged.append(self._last_output_row)
            elif row.relative_path.startswith("plans/amendments/"):
                target = "plans/" + row.relative_path.removeprefix("plans/")
                self._copy_source(source, output_fd, row.relative_path, target, ("amendment",))
                staged.append(self._last_output_row)
        staged.extend(self._stage_actor_module_rows(source, output_fd, actor.module_rows))
        staged_paths = {row[0] for row in staged}
        for _name, source_rel, target, expected_digest, expected_size, role in REVIEWED_SOURCE_MODULES:
            source_row = source_files.get(source_rel)
            if (source_row is None or source_row.sha256 != expected_digest
                    or source_row.size_bytes != expected_size):
                raise InstallerReleaseBuildError("finite native target source module differs from its reviewed pin")
            if target not in staged_paths:
                self._copy_source(source, output_fd, source_rel, target, (role,))
                staged.append(self._last_output_row)
                staged_paths.add(target)

        for source_rel, target, expected_digest, expected_size in REVIEWED_HEALTH_FIXTURES:
            source_row = source_files.get(source_rel)
            if (source_row is None or source_row.sha256 != expected_digest
                    or source_row.size_bytes != expected_size):
                raise InstallerReleaseBuildError("native health fixture source differs from its exact reviewed pin")
            if target not in staged_paths:
                self._copy_source(source, output_fd, source_rel, target, ("native-health-fixture",))
                staged.append(self._last_output_row)
                staged_paths.add(target)
        driver_id, driver_source, driver_target, driver_digest, driver_size, driver_role = APPLICATION_BUILD_DRIVER
        driver_source_row = source_files.get(driver_source)
        if (driver_source_row is None or driver_source_row.sha256 != driver_digest
                or driver_source_row.size_bytes != driver_size or driver_source_row.mode & 0o111):
            raise InstallerReleaseBuildError("application build driver source differs from its execution-only pin")
        if driver_target in staged_paths:
            raise InstallerReleaseBuildError("application build driver path was already staged under another role")
        self._copy_source(source, output_fd, driver_source, driver_target, (driver_role,))
        staged.append(self._last_output_row)
        staged_paths.add(driver_target)
        self._stage_application_effect_sources(source, output_fd, staged, staged_paths)
        return staged

    def _stage_actor_module_rows(self, source: VerifiedInstallerDistributionReceipt, output_fd: int,
                                 module_rows: tuple[tuple[str, str, str, int, int], ...]) \
        -> list[tuple[str, str, int, int, tuple[str, ...]]]:
        """Stage only modules captured in the verified root source actor."""
        source_files = {row.relative_path: row for row in source.files}
        staged: list[tuple[str, str, int, int, tuple[str, ...]]] = []
        for name, _, digest, _, _ in module_rows:
            if not (name == "hermes_installer" or name.startswith("hermes_installer.")):
                continue
            parts = name.split(".")
            source_path = "src/" + "/".join(parts) + ".py"
            package_init = "src/" + "/".join(parts) + "/__init__.py"
            if source_path in source_files:
                source_rel, target = source_path, "lib/python/" + "/".join(parts) + ".py"
            elif package_init in source_files:
                source_rel, target = package_init, "lib/python/" + "/".join(parts) + "/__init__.py"
            else:
                raise InstallerReleaseBuildError("loaded installer module has no fixed source module path")
            source_row = source_files[source_rel]
            if source_row.sha256 != digest:
                raise InstallerReleaseBuildError("loaded module digest differs from the exact source module")
            self._copy_source(source, output_fd, source_rel, target, ("module",))
            staged.append(self._last_output_row)
        return staged

    def _stage_application_effect_sources(
            self, source: VerifiedInstallerDistributionReceipt, output_fd: int,
            staged: list[tuple[str, str, int, int, tuple[str, ...]]], staged_paths: set[str]) -> None:
        source_files = {row.relative_path: row for row in source.files}
        for artifact_id, source_rel, role, expected_digest, expected_size in APPLICATION_EFFECT_SOURCE_MEMBERS:
            source_row = source_files.get(source_rel)
            if (source_row is None or source_row.sha256 != expected_digest
                    or source_row.size_bytes != expected_size):
                raise InstallerReleaseBuildError(
                    f"application effect source member {artifact_id} differs from its reviewed pin")
            if source_rel not in staged_paths:
                self._copy_source(source, output_fd, source_rel, source_rel, (role,))
                staged.append(self._last_output_row)
                staged_paths.add(source_rel)

    def _stage_network_startup_helper(
        self, source: VerifiedInstallerDistributionReceipt,
        output_fd: int,
    ) -> tuple[str, str, int, int, tuple[str, ...]] | None:
        artifact_id, source_path, target_path, expected_digest, expected_size, role = NETWORK_STARTUP_HELPER
        if (role != "network-startup-helper"
                or artifact_id != "installer-private-loopback-worker-gate-v180"
                or source_path != "helpers/private-loopback-worker-gate.py"
                or target_path != source_path):
            raise InstallerReleaseBuildError("fixed native worker helper source policy is malformed")
        if expected_digest is None and expected_size is None:
            # The native launch owner has no approved installed helper in a
            # release until review seals the final coherent source tuple.
            return None
        if (not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest)
                or type(expected_size) is not int or expected_size <= 0):
            raise InstallerReleaseBuildError("fixed native worker helper source policy is malformed")
        row = next((item for item in source.files if item.relative_path == source_path), None)
        if row is None or (row.sha256, row.size_bytes) != (expected_digest, expected_size):
            raise InstallerReleaseBuildError("fixed native worker helper source differs from its reviewed pin")
        fd = source.open_file(source_path)
        try:
            body = _read_exact_fd(fd, expected_size)
        finally:
            os.close(fd)
        if hashlib.sha256(body).hexdigest() != expected_digest:
            raise InstallerReleaseBuildError("fixed native worker helper bytes differ from its reviewed pin")
        _write_relative(output_fd, target_path, body, mode=0o444)
        return (target_path, expected_digest, expected_size, 0o444, (role,))

    def _copy_source(self, source: VerifiedInstallerDistributionReceipt, output_fd: int,
                     source_path: str, target_path: str, roles: tuple[str, ...],
                     executable: bool = False) -> None:
        row = next((item for item in source.files if item.relative_path == source_path), None)
        if row is None:
            raise InstallerReleaseBuildError("release builder requested a source outside its receipt")
        if executable and not row.mode & 0o111:
            raise InstallerReleaseBuildError("fixed root setup launcher source is not executable")
        fd = source.open_file(source_path)
        try:
            body = _read_exact_fd(fd, row.size_bytes)
        finally:
            os.close(fd)
        if hashlib.sha256(body).hexdigest() != row.sha256:
            raise InstallerReleaseBuildError("release builder source bytes differ from sealed source row")
        mode = 0o555 if executable or row.mode & 0o111 else 0o444
        _write_relative(output_fd, target_path, body, mode=mode)
        self._last_output_row = (target_path, row.sha256, row.size_bytes, mode, roles)

    def _seal_output_rows(self, root_fd: int,
                          staged: list[tuple[str, str, int, int, tuple[str, ...]]]) -> tuple[BuildOutputFile, ...]:
        rows: list[BuildOutputFile] = []
        seen: set[str] = set()
        for path, digest, size, mode, roles in sorted(staged):
            if path in seen:
                raise InstallerReleaseBuildError("fixed release builder produced a duplicate output path")
            seen.add(path)
            _validate_relative_path(path)
            if (not _SHA256.fullmatch(digest) or type(size) is not int or size < 0
                    or type(mode) is not int or not 0 <= mode <= 0o7777
                    or not roles or len(set(roles)) != len(roles)
                    or any(role not in RELEASE_ROLES for role in roles)):
                raise InstallerReleaseBuildError("fixed release output row is outside the finite schema")
            fd = _open_relative(root_fd, path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                actual, actual_size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if (info.st_nlink != 1 or actual != digest or actual_size != size
                        or stat.S_IMODE(info.st_mode) != mode or not roles):
                    raise InstallerReleaseBuildError("staged release output differs from its sealed source mapping")
                rows.append(BuildOutputFile(path, actual, actual_size, mode, roles, info.st_dev, info.st_ino))
            finally:
                os.close(fd)
        return tuple(rows)

    def _render_plan(self, source: VerifiedInstallerDistributionReceipt) -> bytes:
        template = _read_relative(source._root_fd, PLAN_TEMPLATE_PATH, 1024 * 1024)
        if hashlib.sha256(template).hexdigest() != PLAN_TEMPLATE_SHA256 or len(template) != PLAN_TEMPLATE_BYTES:
            raise InstallerReleaseBuildError("root setup plan template changed after source verification")
        value = json.loads(template.decode("utf-8"), object_pairs_hook=_unique_pairs)
        catalog = _validate_source_catalog(_read_relative(source._root_fd, CATALOG_SOURCE_PATH, 16 * 1024 * 1024))
        allowed_ids = sorted({row["artifact_id"] for row in catalog["artifacts"]
                              if isinstance(row.get("sha256"), str) and _SHA256.fullmatch(row["sha256"])})
        value.pop("artifact_selection", None)
        value.pop("plan_artifact_id", None)
        value["id"] = "installer-root-setup-plan-v1"
        value["candidate_git_sha"] = source.candidate_git_sha
        value["baseline_tag"] = BASELINE_TAG
        value["baseline_tag_object"] = BASELINE_TAG_OBJECT
        value["baseline_commit"] = BASELINE_COMMIT
        value["baseline_tree_sha256"] = source.baseline_tree_sha256
        value["amendment_manifest_sha256"] = source.amendment_manifest_sha256
        value["allowed_artifact_ids"] = allowed_ids
        value["bootstrap_policy_artifact_id"] = "installer-bootstrap-policy-v1"
        value["template_artifact_ids"] = list(ROOT_PLAN_TEMPLATE_ARTIFACT_IDS)
        return _canonical_json(value)


def bootstrap_selected_release(choices: object, candidate_selection_registry: object) -> None:
    """Stage the explicit root-selected source and exec its exact isolated runtime.

    This pre-exec call is staging-only: it can fetch the fixed-origin source
    candidate and the two reviewed payloads, then records the actual root TTY
    choice in a sealed same-process handoff. It issues no setup actor or
    service/policy effects. The candidate SHA comes only from the typed proof
    minted by the root selection registry, never from argv or environment.
    """
    _require_linux_root()
    try:
        from hermes_installer.root_setup import (
            RootBootstrapCandidateSelectionRegistry,
            RootSetupExplicitChoices,
        )
    except ImportError:
        raise BootstrapEnrollmentPending("root TTY candidate-selection API is unavailable") from None
    if (not isinstance(choices, RootSetupExplicitChoices)
            or not isinstance(candidate_selection_registry, RootBootstrapCandidateSelectionRegistry)):
        raise TypeError("first-source bootstrap requires the sealed root TTY choice and its registry")
    selection = candidate_selection_registry.resolve(choices)
    journal = candidate_selection_registry
    source_cas = RootInstallerDistributionSourceCAS.from_root_bootstrap(
        journal, fixed_source_origin_policy_for_root_bootstrap())
    distribution_registry = RootInstallerDistributionRegistry.from_owned_source_CAS(source_cas, journal)
    distribution_handle = source_cas.acquire_selected(selection.candidate_git_sha)
    source = distribution_registry.resolve(distribution_handle)
    if source.candidate_git_sha != selection.candidate_git_sha:
        raise InstallerReleaseBuildError("fixed-origin source CAS does not match the root TTY choice")
    runtime_artifact_registry = RootInstallerRuntimeArtifactRegistry()
    interpreter_registry = RootInstallerInterpreterRegistry.from_owned_source_CAS(
        distribution_registry, journal, runtime_artifact_registry)
    interpreter_handle = interpreter_registry.provision_selected_bootstrap_interpreter(distribution_handle)
    handoff_registry = RootBootstrapRuntimeHandoffRegistry.from_source_bootstrap(
        distribution_registry, interpreter_registry, candidate_selection_registry, BOOTSTRAP_HANDOFF_ROOT)
    handoff = handoff_registry.create_for_current_process(distribution_handle, interpreter_handle, selection)
    handoff_registry.reexec_selected_bootstrap(handoff)
    raise BootstrapEnrollmentPending("isolated source bootstrap exec returned without replacing the current process")


def _bootstrap_after_reexec() -> Any:
    """Private selected-source entry reached only through the sealed FD3 exec."""
    _require_linux_root()
    distribution_registry = RootInstallerDistributionRegistry()
    runtime_artifact_registry = RootInstallerRuntimeArtifactRegistry()
    interpreter_registry = RootInstallerInterpreterRegistry(distribution_registry, runtime_artifact_registry)
    handoff_registry = RootBootstrapRuntimeHandoffRegistry.from_reexec(
        distribution_registry, interpreter_registry)
    handoff = handoff_registry.take_current_reexec_handoff()
    distribution_handle = handoff.distribution_receipt_handle
    source = distribution_registry.resolve(distribution_handle)
    if source.candidate_git_sha != handoff.candidate_git_sha:
        raise InstallerReleaseBuildError("consumed bootstrap handoff is not bound to retained source CAS")
    interpreter_handle = interpreter_registry.observe_current_bootstrap_interpreter(distribution_handle)
    interpreter = interpreter_registry.resolve(interpreter_handle, distribution_handle)
    if (interpreter.candidate_git_sha != handoff.candidate_git_sha
            or interpreter.runtime_prefix_sha256 != handoff.runtime_closure_sha256
            or interpreter.executable_sha256 != handoff.expected_executable_sha256):
        raise InstallerReleaseBuildError("observed root actor interpreter differs from the consumed handoff")
    _load_installed_setup_module_closure()
    actor_verifier = RootSourceBootstrapActorVerifier.from_verified_source(
        distribution_registry, interpreter_registry)
    actor = actor_verifier.verify_current(distribution_handle, interpreter_handle)
    actor.verify_current(source, interpreter)
    builder = RootInstalledReleaseBuilder(distribution_registry, interpreter_registry, actor_verifier)
    build_handle = builder.build_selected(distribution_handle, interpreter_handle)
    try:
        from .installed_stage_publisher import RootInstalledStagePublisher
    except ImportError:
        raise BootstrapEnrollmentPending("installed-stage publisher is not available in the selected source closure") from None
    publisher = RootInstalledStagePublisher.from_root_setup(builder)
    installed = publisher.publish_installed_stage(build_handle)
    try:
        installed.verify_current()
        launcher_rows = [row for row in installed.files
                         if row.relative_path == STAGED_LAUNCHER_PATH and "launcher" in row.roles]
        if (installed.release_commit != handoff.candidate_git_sha or len(launcher_rows) != 1
                or not launcher_rows[0].mode & 0o111):
            raise InstallerReleaseBuildError("installed release does not contain the selected executable launcher")
        launcher = installed.release_root / STAGED_LAUNCHER_PATH
        launcher_fd = installed.open_file("installer-root-setup-launcher-v1")
        try:
            info = os.fstat(launcher_fd)
            digest, _ = _hash_fd(launcher_fd, MAX_SOURCE_FILE_BYTES)
            path_info = os.stat(launcher, follow_symlinks=False)
            if (digest != launcher_rows[0].sha256 or info.st_dev != launcher_rows[0].device
                    or info.st_ino != launcher_rows[0].inode or path_info.st_dev != info.st_dev
                    or path_info.st_ino != info.st_ino or not stat.S_ISREG(path_info.st_mode)):
                raise InstallerReleaseBuildError("installed launcher changed after fixed-path publication")
        finally:
            os.close(launcher_fd)
        try:
            os.execve(launcher, [str(launcher), handoff.lifecycle_action],
                      {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        except OSError:
            raise BootstrapEnrollmentPending(
                "the verified installed launcher could not start; retry its fixed lifecycle action") from None
        raise BootstrapEnrollmentPending("installed lifecycle launcher exec returned unexpectedly")
    finally:
        installed.close()


def _load_installed_setup_module_closure() -> None:
    """Load the exact future installed-launcher imports into the observed source closure.

    The first-source actor execs the installed launcher after publishing its
    release. Importing these fixed modules now lets the normal source actor
    verifier bind their actual selected SourceCAS bytes into the release, so
    the installed launcher does not depend on checkout-only Python modules.
    No setup action is invoked here.
    """
    import importlib

    try:
        root_setup = importlib.import_module("hermes_installer.root_setup")
        importlib.import_module("hermes_installer.authority.installer_release")
        importlib.import_module("hermes_installer.authority.bootstrap_runtime_factory")
        # These two fixed import-only entry points are the authoritative setup
        # and listener closures used by the published root launcher. Loading
        # them before actor verification makes every actually selected
        # transitive module (including registry.resources_runtime) part of the
        # observed SourceCAS module rows that the release builder stages.
        root_setup._import_v180_native_support_closure()
        root_setup._import_v187_listener_activation_closure()
    except ImportError:
        raise BootstrapEnrollmentPending(
            "installed root setup module closure is unavailable from selected source") from None


def _verify_frozen_baseline(root_fd: int, rows: tuple[DistributionFile, ...]) -> str:
    prefix = BASELINE_DIRECTORY + "/"
    actual = {row.relative_path[len(prefix):]: row.sha256 for row in rows
              if row.relative_path.startswith(prefix)}
    if not actual or any(not name for name in actual):
        raise InstallerReleaseBuildError("complete frozen baseline tree is missing")
    digest = _manifest_digest(actual)
    try:
        hashes = json.loads(_read_relative(root_fd, BASELINE_DIRECTORY + "/hashes.json", 4 * 1024 * 1024))
    except (ValueError, UnicodeError):
        raise InstallerReleaseBuildError("frozen 160-file snapshot manifest is malformed") from None
    expected_files = hashes.get("files") if isinstance(hashes, dict) else None
    if (not isinstance(hashes, dict) or hashes.get("baseline_tag") != BASELINE_TAG
            or not isinstance(expected_files, dict) or len(expected_files) != 160):
        raise InstallerReleaseBuildError("frozen 160-file snapshot manifest differs from the protected baseline")
    for path, expected in expected_files.items():
        if not isinstance(path, str) or not _SHA256.fullmatch(str(expected)):
            raise InstallerReleaseBuildError("frozen snapshot manifest contains an invalid row")
        relative = path.removeprefix(BASELINE_DIRECTORY + "/")
        if actual.get(relative) != expected:
            raise InstallerReleaseBuildError("frozen 160-file snapshot content differs from its manifest")
    return digest


def _amendment_digest(rows: tuple[DistributionFile, ...]) -> str:
    prefix = "plans/amendments/"
    selected = {row.relative_path: row.sha256 for row in rows if row.relative_path.startswith(prefix)}
    if not selected:
        raise InstallerReleaseBuildError("append-only reviewed amendment inputs are missing")
    template = next((row for row in rows if row.relative_path == PLAN_TEMPLATE_PATH), None)
    if (template is None or template.sha256 != PLAN_TEMPLATE_SHA256
            or template.size_bytes != PLAN_TEMPLATE_BYTES):
        raise InstallerReleaseBuildError("root setup plan template differs from its reviewed v53 bytes")
    return _manifest_digest(selected)


def _validate_source_catalog(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseBuildError("candidate artifact catalog is malformed") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "artifacts", "packages"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["artifacts"], list) or not isinstance(value["packages"], list)):
        raise InstallerReleaseBuildError("candidate artifact catalog has an unsupported schema")
    ids: set[str] = set()
    for item in value["artifacts"]:
        if (not isinstance(item, dict) or not isinstance(item.get("artifact_id"), str)
                or not _ID.fullmatch(item["artifact_id"]) or item["artifact_id"] in ids
                or not _SHA256.fullmatch(str(item.get("sha256", "")))
                or type(item.get("size_bytes")) is not int or item["size_bytes"] < 0):
            raise InstallerReleaseBuildError("candidate artifact catalog contains an invalid or duplicate pin")
        ids.add(item["artifact_id"])
    return value


def _manifest_digest(value: Mapping[str, str]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


def _inspect_source_tree(root_fd: int, exported: tuple[tuple[str, str, int], ...]) -> tuple[DistributionFile, ...]:
    by_path = {path: (digest, size) for path, digest, size in exported}
    rows: list[DistributionFile] = []
    for relative, (expected_digest, expected_size) in sorted(by_path.items()):
        fd = _open_relative(root_fd, relative, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or digest != expected_digest or size != expected_size
                    or stat.S_IMODE(info.st_mode) not in {0o444, 0o555}):
                raise InstallerReleaseBuildError("exported source file differs from exact Git blob bytes")
            rows.append(DistributionFile(relative, digest, size, stat.S_IMODE(info.st_mode),
                                         info.st_dev, info.st_ino, info.st_ctime_ns))
        finally:
            os.close(fd)
    if len(rows) != len(by_path) or _enumerate_regular_files(root_fd) != tuple(sorted(by_path)):
        raise InstallerReleaseBuildError("candidate source tree has missing or duplicate files")
    return tuple(rows)


def _ensure_root_directory(path: Path, mode: int) -> None:
    if not path.exists():
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode):
        raise InstallerReleaseBuildError("fixed source CAS directory ownership or mode is invalid")


def _verify_private_cas_root(path: Path) -> None:
    fd = _open_secure_directory(path, expected_uid=0)
    try:
        info = os.fstat(fd)
        if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != os.stat(path.parent, follow_symlinks=False).st_dev):
            raise InstallerReleaseBuildError("fixed source CAS root is not private root-owned storage")
    finally:
        os.close(fd)


def _enumerate_regular_files(root_fd: int) -> tuple[str, ...]:
    files: list[str] = []
    def walk(directory_fd: int, prefix: str) -> None:
        scan = os.dup(directory_fd)
        try:
            with os.scandir(scan) as entries:
                for entry in entries:
                    relative = f"{prefix}/{entry.name}" if prefix else entry.name
                    _validate_relative_path(relative)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=directory_fd)
                        try:
                            walk(child, relative)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        files.append(relative)
                    else:
                        raise InstallerReleaseBuildError("sealed source/output contains a link or special file")
        finally:
            os.close(scan)
    walk(root_fd, "")
    return tuple(sorted(files))


def _make_immutable_tree(root: Path) -> None:
    """Seal an already-built private source tree before making it addressable."""
    for directory, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            path = current / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise InstallerReleaseBuildError("source staging contains a linked or special file")
            os.chmod(path, 0o555 if info.st_mode & 0o111 else 0o444, follow_symlinks=False)
        for name in dirs:
            path = current / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise InstallerReleaseBuildError("source staging contains a linked or special directory")
            os.chmod(path, 0o555, follow_symlinks=False)
        os.chmod(current, 0o555, follow_symlinks=False)
        _fsync_dir(current)


def _tree_byte_usage(root: Path) -> int:
    total = 0
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        for name in dirs:
            info = (current / name).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                raise InstallerReleaseBuildError("source CAS contains an unsafe directory entry")
        for name in files:
            info = (current / name).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1):
                raise InstallerReleaseBuildError("source CAS contains a linked or unowned file")
            total += info.st_size
            if total > MAX_SOURCE_CAS_BYTES:
                return total
    return total


def _write_distribution_receipt(candidate_dir: Path,
                                receipt: VerifiedInstallerDistributionReceipt) -> None:
    source_manifest_rows: list[dict[str, Any]] = []
    for row in receipt.files:
        fd = receipt.open_file(row.relative_path)
        try:
            body = _read_exact_fd(fd, row.size_bytes)
        finally:
            os.close(fd)
        blob = hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
        source_manifest_rows.append({"path": row.relative_path, "sha256": row.sha256,
                                     "size_bytes": row.size_bytes, "mode": row.mode,
                                     "git_blob_sha1": blob})
    manifest = _canonical_json(source_manifest_rows)
    _create_private_file(candidate_dir, "source-manifest.json", manifest)
    record = {
        "schema": 1, "receipt_handle": receipt.receipt_handle,
        "candidate_git_sha": receipt.candidate_git_sha, "git_tree_sha1": receipt.git_tree_sha1,
        "source_tree_sha256": receipt.source_tree_sha256,
        "baseline_tree_sha256": receipt.baseline_tree_sha256,
        "amendment_manifest_sha256": receipt.amendment_manifest_sha256,
        "source_catalog_sha256": receipt.source_catalog_sha256,
        "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "source_device": receipt.root_device, "source_inode": receipt.root_inode,
        "files": [
            {"relative_path": row.relative_path, "sha256": row.sha256,
             "size_bytes": row.size_bytes, "mode": row.mode,
             "device": row.device, "inode": row.inode, "ctime_ns": row.ctime_ns}
            for row in receipt.files
        ],
    }
    _create_private_file(candidate_dir, "source-receipt.json", _canonical_json(record))
    _fsync_dir(candidate_dir)


def _create_private_file(parent: Path, name: str, body: bytes) -> None:
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short private receipt write")
                view = view[written:]
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _read_private_json(path: Path, maximum: int) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentPending("root-owned source receipt is unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise InstallerReleaseBuildError("source receipt custody or size is invalid")
        raw = _read_exact_fd(fd, info.st_size)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise InstallerReleaseBuildError("root-owned source receipt is malformed") from None
    finally:
        os.close(fd)


def _ensure_fixed_deployment_parent() -> None:
    """Create only the root-owned fixed state prefix needed on first install."""
    _require_linux_root()
    varlib_fd = _open_secure_directory(Path("/var/lib"), expected_uid=0)
    app_fd = deployments_fd = -1
    try:
        app_fd = _ensure_owned_directory_child(varlib_fd, "hermes-installer")
        deployments_fd = _ensure_owned_directory_child(app_fd, "deployments")
        for parent_fd, name, held_fd in ((varlib_fd, "hermes-installer", app_fd),
                                         (app_fd, "deployments", deployments_fd)):
            current_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent_fd)
            try:
                held, current = os.fstat(held_fd), os.fstat(current_fd)
                if (current.st_uid != 0 or stat.S_IMODE(current.st_mode) != 0o700
                        or current.st_dev != held.st_dev or current.st_ino != held.st_ino):
                    raise InstallerReleaseBuildError("fixed deployment parent changed during provisioning")
            finally:
                os.close(current_fd)
    finally:
        if deployments_fd >= 0:
            os.close(deployments_fd)
        if app_fd >= 0:
            os.close(app_fd)
        os.close(varlib_fd)


def _ensure_owned_directory_child(parent_fd: int, name: str) -> int:
    if name not in {"hermes-installer", "deployments"}:
        raise InstallerReleaseBuildError("directory target is outside fixed installer state")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError:
        raise InstallerReleaseBuildError("fixed deployment parent cannot be provisioned") from None
    else:
        os.fsync(parent_fd)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
    except OSError:
        raise InstallerReleaseBuildError("fixed deployment parent is not a nofollow directory") from None
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise InstallerReleaseBuildError("fixed deployment parent ownership or mode conflicts")
    return fd


def _read_deployment_predecessor() -> DeploymentPredecessor:
    parent_path = Path("/var/lib/hermes-installer/deployments")
    parent_fd = _open_secure_directory(parent_path, expected_uid=0)
    try:
        parent = os.fstat(parent_fd)
        try:
            fd = os.open("current.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        except FileNotFoundError:
            return DeploymentPredecessor("absent", parent.st_dev, parent.st_ino)
        except OSError:
            raise InstallerReleaseBuildError("deployment predecessor cannot be securely opened") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024):
                raise InstallerReleaseBuildError("deployment predecessor receipt custody is invalid")
            raw = _read_exact_fd(fd, info.st_size)
            try:
                record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
            except (ValueError, UnicodeError, json.JSONDecodeError):
                raise InstallerReleaseBuildError("deployment predecessor receipt is malformed") from None
            candidate = record.get("candidate_git_sha") if isinstance(record, dict) else None
            if not isinstance(candidate, str) or not _GIT_SHA.fullmatch(candidate):
                raise InstallerReleaseBuildError("deployment predecessor has no exact candidate identity")
            return DeploymentPredecessor("present", parent.st_dev, parent.st_ino,
                                         hashlib.sha256(raw).hexdigest(), info.st_dev, info.st_ino, candidate)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def observe_deployment_predecessor() -> VerifiedDeploymentPredecessor:
    """Observe only the fixed deployment pointer, distinguishing proven absence.

    Present pointers must also resolve to a complete verified immutable release.
    The returned opaque handle retains that verifier receipt inside this process;
    no caller path, bool, or parsed mapping is accepted as evidence.
    """
    _require_linux_root()
    _ensure_fixed_deployment_parent()
    predecessor = _read_deployment_predecessor()
    now = time.monotonic()
    if predecessor.state == "absent":
        return VerifiedDeploymentPredecessor(
            _DEPLOYMENT_PREDECESSOR_SEAL, state="absent",
            parent_device=predecessor.parent_device, parent_inode=predecessor.parent_inode,
            candidate_git_sha=None, deployment_receipt_sha256=None,
            deployment_receipt_device=None, deployment_receipt_inode=None,
            verified_release_receipt_handle=None, issued_monotonic=now)
    try:
        from .installer_release import InstalledRootReleaseVerifier
        release = InstalledRootReleaseVerifier.verify_installed_release()
    except Exception as exc:
        raise InstallerReleaseBuildError(
            "present deployment predecessor is not a verified installed release"
        ) from exc
    if (release.release_commit != predecessor.candidate_git_sha
            or release.deployment_receipt_sha256 != predecessor.sha256):
        release.close()
        raise InstallerReleaseBuildError(
            "verified installed release does not match the fixed predecessor snapshot")
    handle = secrets.token_urlsafe(32)
    proof = VerifiedDeploymentPredecessor(
        _DEPLOYMENT_PREDECESSOR_SEAL, state="present-verified",
        parent_device=predecessor.parent_device, parent_inode=predecessor.parent_inode,
        candidate_git_sha=predecessor.candidate_git_sha,
        deployment_receipt_sha256=predecessor.sha256,
        deployment_receipt_device=predecessor.device, deployment_receipt_inode=predecessor.inode,
        verified_release_receipt_handle=handle, issued_monotonic=now)
    with _DEPLOYMENT_PREDECESSOR_LOCK:
        _DEPLOYMENT_PREDECESSOR_RECEIPTS[handle] = (proof, release)
        expired = [key for key, (item, _) in _DEPLOYMENT_PREDECESSOR_RECEIPTS.items()
                   if time.monotonic() >= item.expires_monotonic]
        for key in expired:
            _, held = _DEPLOYMENT_PREDECESSOR_RECEIPTS.pop(key)
            held.close()
    return proof


def resolve_verified_deployment_release(handle: str, *, consume: bool = False) -> Any:
    return _resolve_verified_deployment_release(handle, consume=consume)


def _resolve_verified_deployment_release(handle: str | None, *, consume: bool) -> Any:
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise BootstrapEnrollmentPending("verified predecessor release handle is malformed")
    with _DEPLOYMENT_PREDECESSOR_LOCK:
        entry = _DEPLOYMENT_PREDECESSOR_RECEIPTS.get(handle)
        if entry is None:
            raise BootstrapEnrollmentPending("verified predecessor release is absent or expired")
        proof, release = entry
        if proof.verified_release_receipt_handle != handle:
            raise InstallerReleaseBuildError("verified predecessor release handle does not join")
        proof_expired = time.monotonic() >= proof.expires_monotonic
        if proof_expired:
            _DEPLOYMENT_PREDECESSOR_RECEIPTS.pop(handle, None)
            release.close()
            raise BootstrapEnrollmentPending("verified predecessor release is expired")
        release.verify_current()
        if consume:
            _DEPLOYMENT_PREDECESSOR_RECEIPTS.pop(handle, None)
        return release


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _open_relative(root_fd: int, relative: str, flags: int) -> int:
    _validate_relative_path(relative)
    parts = relative.split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
    finally:
        os.close(current)


def _readlink_at(directory_fd: int, name: str) -> str:
    target = os.readlink(name, dir_fd=directory_fd)
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        raise InstallerReleaseBuildError("runtime alias target is absolute or malformed")
    return target


def _readlink_relative(root_fd: int, relative: str) -> str:
    _validate_relative_path(relative)
    parent, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
    current = os.dup(root_fd)
    try:
        for part in parent.split("/") if parent else ():
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current); current = next_fd
        return _readlink_at(current, name)
    finally:
        os.close(current)


def _contained_alias_target(root_fd: int, relative: str, link_target: str) -> str:
    _validate_relative_path(relative)
    if not link_target or link_target.startswith("/") or "\\" in link_target or "\x00" in link_target:
        raise InstallerReleaseBuildError("runtime alias target is absolute or malformed")
    root_path = Path(os.readlink(f"/proc/self/fd/{root_fd}")).resolve(strict=True)
    alias_path = root_path / relative
    try:
        target = (alias_path.parent / link_target).resolve(strict=True)
        rel = target.relative_to(root_path).as_posix()
    except (OSError, ValueError):
        raise InstallerReleaseBuildError("runtime archive alias escapes or dangles within its prefix") from None
    _validate_relative_path(rel)
    return rel


def _read_relative(root_fd: int, relative: str, maximum: int) -> bytes:
    fd = _open_relative(root_fd, relative, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise InstallerReleaseBuildError("protected source file type or size is invalid")
        body = _read_exact_fd(fd, info.st_size)
        if os.read(fd, 1):
            raise InstallerReleaseBuildError("protected source file grew during read")
        return body
    finally:
        os.close(fd)


def _write_relative(root_fd: int, relative: str, body: bytes, *, mode: int) -> None:
    _validate_relative_path(relative)
    parts = relative.split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=current)
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short source CAS write")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(current)


def _hash_fd(fd: int, maximum: int) -> tuple[str, int]:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        part = os.read(fd, min(1024 * 1024, maximum + 1 - total))
        if not part:
            break
        total += len(part)
        if total > maximum:
            raise InstallerReleaseBuildError("source file exceeds the protected byte bound")
        digest.update(part)
    return digest.hexdigest(), total


def _hash_and_read_fd(fd: int, maximum: int) -> tuple[str, int, bytes]:
    digest, size = _hash_fd(fd, maximum)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest, size, _read_exact_fd(fd, size)


def _read_exact_fd(fd: int, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = os.read(fd, size - len(chunks))
        if not part:
            raise InstallerReleaseBuildError("protected source file ended during read")
        chunks.extend(part)
    return bytes(chunks)


def _read_exact(stream: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(min(1024 * 1024, size - len(chunks)))
        if not part:
            raise InstallerReleaseBuildError("Git source object ended during export")
        chunks.extend(part)
    return bytes(chunks)


def _validate_relative_path(value: str) -> None:
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or "\x00" in value or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise InstallerReleaseBuildError("source path is not a normalized portable relative path")


def _validate_git_sha(value: str) -> None:
    if not isinstance(value, str) or not _GIT_SHA.fullmatch(value):
        raise InstallerReleaseBuildError("selected installer candidate must be an exact 40-character Git commit")


def distribution_root(receipt: VerifiedInstallerDistributionReceipt) -> Path:
    if not isinstance(receipt, VerifiedInstallerDistributionReceipt) or receipt._seal is not _SEAL:
        raise TypeError("candidate source root requires a sealed distribution receipt")
    return SOURCE_CAS_V65_ROOT / receipt.candidate_git_sha / "source"


def _open_secure_directory(path: Path, *, expected_uid: int) -> int:
    if not path.is_absolute():
        raise InstallerReleaseBuildError("managed runtime prefix must be absolute")
    parts = path.parts
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
            info = os.fstat(current)
            if (info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022):
                raise InstallerReleaseBuildError("managed interpreter prefix ancestry is not root-owned and protected")
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid:
            raise InstallerReleaseBuildError("managed interpreter prefix is not a root-owned directory")
        result, current = current, -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def ensure_initial_setup_fixed_prefixes() -> None:
    """Create only the two fixed first-install config directories, without repair.

    The installed root actor needs these directories before constructing its
    credential-vault and first-selection registries. Existing objects are
    observed and must already have the exact reviewed owner, group, and mode;
    this routine never chmods, chowns, follows, or replaces an existing path.
    """
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        raise InstallerReleaseBuildError("initial setup prefixes require the installed Linux root actor")
    etc_fd = _open_secure_directory(Path("/etc"), expected_uid=0)
    try:
        _ensure_owned_child_directory(etc_fd, "hermes-installer", 0o755)
        setup_fd = os.open("hermes-installer", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=etc_fd)
        try:
            _ensure_owned_child_directory(setup_fd, "credentials", 0o700)
        finally:
            os.close(setup_fd)
    finally:
        os.close(etc_fd)


def _ensure_owned_child_directory(parent_fd: int, name: str, mode: int, *,
                                  expected_uid: int = 0, expected_gid: int = 0) -> None:
    if (name not in {"hermes-installer", "credentials"}
            or (name == "hermes-installer" and mode != 0o755)
            or (name == "credentials" and mode != 0o700)
            or type(expected_uid) is not int or type(expected_gid) is not int):
        raise InstallerReleaseBuildError("first-install directory is outside its fixed layout")
    created = False
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    try:
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
    except OSError:
        raise InstallerReleaseBuildError("fixed first-install directory is not a real directory") from None
    try:
        info = os.fstat(child_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise InstallerReleaseBuildError("fixed first-install path is not a directory")
        if created:
            # Only the directory exclusively created above may be normalized.
            os.fchown(child_fd, expected_uid, expected_gid)
            os.fchmod(child_fd, mode)
            os.fsync(child_fd)
            info = os.fstat(child_fd)
        if (info.st_uid != expected_uid or info.st_gid != expected_gid
                or stat.S_IMODE(info.st_mode) != mode):
            raise InstallerReleaseBuildError("fixed first-install directory has conflicting custody or mode")
    finally:
        os.close(child_fd)
    if created:
        os.fsync(parent_fd)


def _relative_below(root: Path, path: Path) -> str:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        relative = resolved_path.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        raise InstallerReleaseBuildError("observed file is outside its selected root") from None
    _validate_relative_path(relative)
    return relative


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _scan_runtime_prefix(root_fd: int, *, expected_uid: int, expected_gid: int) -> tuple[RuntimeFile, ...]:
    rows: list[RuntimeFile] = []
    total = 0

    def walk(fd: int, prefix: str) -> None:
        nonlocal total
        scan_fd = os.dup(fd)
        try:
            with os.scandir(scan_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if name in {".", ".."} or "/" in name or "\\" in name:
                        raise InstallerReleaseBuildError("runtime prefix contains an invalid path entry")
                    relative = f"{prefix}/{name}" if prefix else name
                    _validate_relative_path(relative)
                    info = entry.stat(follow_symlinks=False)
                    if info.st_uid != expected_uid or info.st_gid != expected_gid or info.st_dev != os.fstat(root_fd).st_dev:
                        raise InstallerReleaseBuildError("runtime prefix contains foreign-owned or cross-device content")
                    if stat.S_ISDIR(info.st_mode):
                        if stat.S_IMODE(info.st_mode) & 0o022:
                            raise InstallerReleaseBuildError("runtime directory is writable by group or others")
                        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=fd)
                        try:
                            walk(child_fd, relative)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
                            raise InstallerReleaseBuildError("runtime file is linked or writable by group or others")
                        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            digest, size = _hash_fd(file_fd, MAX_SOURCE_FILE_BYTES)
                        finally:
                            os.close(file_fd)
                        total += size
                        if total > MAX_SOURCE_TREE_BYTES or len(rows) >= MAX_SOURCE_FILES:
                            raise InstallerReleaseBuildError("isolated runtime closure exceeds its protected bound")
                        rows.append(RuntimeFile(relative, digest, size, stat.S_IMODE(info.st_mode),
                                                info.st_dev, info.st_ino))
                    elif stat.S_ISLNK(info.st_mode):
                        link_target = _readlink_at(fd, name)
                        target_relative = _contained_alias_target(root_fd, relative, link_target)
                        target_fd = _open_relative(root_fd, target_relative, os.O_RDONLY)
                        try:
                            target_info = os.fstat(target_fd)
                            if (not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != expected_uid
                                    or target_info.st_gid != expected_gid or target_info.st_dev != info.st_dev
                                    or target_info.st_nlink != 1):
                                raise InstallerReleaseBuildError("runtime alias target is linked, foreign, or special")
                            digest, size = _hash_fd(target_fd, MAX_SOURCE_FILE_BYTES)
                            mode = stat.S_IMODE(target_info.st_mode)
                        finally:
                            os.close(target_fd)
                        total += size
                        if total > MAX_SOURCE_TREE_BYTES or len(rows) >= MAX_SOURCE_FILES:
                            raise InstallerReleaseBuildError("isolated runtime closure exceeds its protected bound")
                        rows.append(RuntimeFile(relative, digest, size, mode, info.st_dev, info.st_ino,
                                                link_target, target_relative, target_info.st_dev,
                                                target_info.st_ino))
                    else:
                        raise InstallerReleaseBuildError("runtime prefix contains a special file")
        finally:
            os.close(scan_fd)

    walk(root_fd, "")
    rows.sort(key=lambda row: row.relative_path)
    if not rows:
        raise BootstrapEnrollmentPending("selected installer runtime has no measured file closure")
    return tuple(rows)


def _verify_runtime_files(root_fd: int, rows: tuple[RuntimeFile, ...], expected_uid: int,
                          expected_gid: int) -> None:
    actual = _scan_runtime_prefix(root_fd, expected_uid=expected_uid, expected_gid=expected_gid)
    if actual != rows:
        raise InstallerReleaseBuildError("isolated installer runtime closure changed after observation")


def _require_python_requirement(project_bytes: bytes) -> None:
    try:
        project = tomllib.loads(project_bytes.decode("utf-8"))
        requires = project["project"]["requires-python"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        raise InstallerReleaseBuildError("selected source has no valid installer Python requirement") from None
    if not isinstance(requires, str) or not re.search(r"(?:^|,)\s*>=\s*3\.11(?:\.|,|$)", requires):
        raise BootstrapEnrollmentPending("selected installer source does not allow the required Python 3.11 runtime")


def _locked_package_versions(lock_bytes: bytes) -> Mapping[str, frozenset[str]]:
    try:
        text = lock_bytes.decode("utf-8")
    except UnicodeError:
        raise InstallerReleaseBuildError("selected installer runtime lock is malformed") from None
    result: dict[str, set[str]] = {}
    current: tuple[str, str] | None = None
    hashes: set[str] = set()
    for raw_line in text.splitlines() + [""]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            if current is not None and not raw_line.rstrip().endswith("\\"):
                if not hashes:
                    raise InstallerReleaseBuildError("installer runtime lock package lacks verified hashes")
                name, version = current
                result.setdefault(_normalize_package_name(name), set()).add(version)
                current, hashes = None, set()
            continue
        if current is None:
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(\\?)", line)
            if match is None:
                raise InstallerReleaseBuildError("installer runtime lock contains an unpinned requirement")
            current = (match.group(1), match.group(2))
            if not match.group(3):
                raise InstallerReleaseBuildError("installer runtime lock package lacks explicit hashes")
            continue
        match = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})\s*(\\?)", line)
        if match is None:
            raise InstallerReleaseBuildError("installer runtime lock contains an invalid hash continuation")
        hashes.add(match.group(1))
        if not match.group(2):
            name, version = current
            result.setdefault(_normalize_package_name(name), set()).add(version)
            current, hashes = None, set()
    if current is not None or not result:
        raise InstallerReleaseBuildError("installer runtime lock is incomplete or empty")
    return {name: frozenset(versions) for name, versions in result.items()}


def _runtime_dependency_receipts(prefix: Path,
                                 locked: Mapping[str, frozenset[str]],
                                 registry: RootInstallerRuntimeArtifactRegistry) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    packages: list[tuple[str, str]] = []
    handles: list[str] = []
    seen: set[tuple[str, str]] = set()
    search_paths = _runtime_site_search_paths()
    for dist in importlib.metadata.distributions(path=search_paths):
        name = dist.metadata.get("Name")
        version = dist.version
        if not isinstance(name, str) or not isinstance(version, str):
            raise InstallerReleaseBuildError("installed runtime dependency identity is incomplete")
        normalized = _normalize_package_name(name)
        if normalized == "pip":
            _verify_bundled_pip_distribution(dist, prefix)
            continue
        if version not in locked.get(normalized, frozenset()):
            raise InstallerReleaseBuildError("installed runtime dependency is not pinned by selected requirements-runtime.txt")
        identity = (normalized, version)
        if identity in seen:
            raise InstallerReleaseBuildError("installer runtime contains duplicate package distributions")
        seen.add(identity)
        files = dist.files
        if not files:
            raise BootstrapEnrollmentPending("runtime dependency has no installed file manifest")
        file_digests: dict[str, str] = {}
        for item in files:
            path = Path(dist.locate_file(item))
            relative = _relative_below(prefix, path)
            fd = _open_secure_file(path, expected_uid=0)
            try:
                digest, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            finally:
                os.close(fd)
            file_digests[relative] = digest
        digest = _manifest_digest(file_digests)
        packages.append((normalized + "@" + version, digest))
        handle = registry._mint_observed(name, version, file_digests, locked[normalized])
        handles.append(handle)
    packages.sort()
    if not packages:
        raise BootstrapEnrollmentPending("selected installer runtime has no verified locked dependencies")
    return packages, tuple(handles)


def _runtime_site_search_paths() -> list[str]:
    paths: list[str] = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_path(key)
        if not value:
            continue
        try:
            resolved = str(Path(value).resolve(strict=True))
        except OSError:
            raise InstallerReleaseBuildError("isolated runtime dependency directory is unavailable") from None
        if resolved not in paths:
            paths.append(resolved)
    return paths


def _is_absent_optional_stdlib_zip(path: Path, runtime_prefix: Path,
                                   runtime_members: set[str] | frozenset[str]) -> bool:
    """Recognize CPython's one optional archive entry when it is truly absent."""
    expected = runtime_prefix / "lib" / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    if path != expected or expected.relative_to(runtime_prefix).as_posix() in runtime_members:
        return False
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    else:
        # Existing files, directories, and even dangling symlinks must go
        # through normal strict resolution and closure verification.
        return False
    try:
        library_info = os.lstat(path.parent)
        if not stat.S_ISDIR(library_info.st_mode):
            return False
        library_dir = (runtime_prefix / "lib").resolve(strict=True)
        return path.parent.resolve(strict=True) == library_dir
    except OSError:
        return False


def _verify_bundled_pip_distribution(dist: Any, prefix: Path) -> None:
    """Bind the runtime's bundled pip metadata to its fixed CPython closure.

    The pinned standalone CPython archive includes pip; it is not selected from
    requirements-runtime.txt and receives no separate dependency receipt. Its
    complete bytes are already covered by the verified runtime closure.
    """
    files = dist.files
    if not files:
        raise BootstrapEnrollmentPending("bundled runtime pip has no installed file manifest")
    version = dist.version
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", version):
        raise InstallerReleaseBuildError("bundled runtime pip version is malformed")
    site_root = "lib/python3.14/site-packages/"
    package_root = site_root + "pip/"
    metadata_root = site_root + "pip-" + version + ".dist-info/"
    bundled_scripts = {"bin/pip", "bin/pip3", "bin/pip3.14"}
    for item in files:
        relative = _relative_below(prefix, Path(dist.locate_file(item)))
        if not (relative.startswith(package_root) or relative.startswith(metadata_root)
                or relative in bundled_scripts):
            raise InstallerReleaseBuildError("bundled runtime pip escaped its fixed CPython site directory")


def _runtime_artifact_current_files(
        interpreter: VerifiedInstallerInterpreterReceipt,
        receipt: VerifiedInstallerRuntimeArtifactReceipt) -> tuple[tuple[str, str], ...]:
    current: list[tuple[str, str]] = []
    for relative, expected in receipt.files:
        fd = interpreter.open_runtime_file(relative)
        try:
            actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        finally:
            os.close(fd)
        current.append((relative, actual))
    return tuple(current)


def _open_secure_file(path: Path, *, expected_uid: int) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseBuildError("runtime dependency file is unavailable without following links") from None
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise InstallerReleaseBuildError("runtime dependency file custody is unsafe")
    return fd


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _current_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        raise BootstrapEnrollmentPending("kernel boot identity is unavailable") from None
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise InstallerReleaseBuildError("kernel boot identity is malformed")
    return value


def _ensure_bootstrap_handoff_root() -> None:
    parent_fd = _open_secure_directory(Path("/var/lib/hermes-installer"), expected_uid=0)
    try:
        try:
            os.mkdir(BOOTSTRAP_HANDOFF_ROOT.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        child = os.open(BOOTSTRAP_HANDOFF_ROOT.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent_fd)
        try:
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise InstallerReleaseBuildError("bootstrap handoff journal custody is invalid")
            os.fsync(parent_fd)
        finally:
            os.close(child)
    finally:
        os.close(parent_fd)


def _candidate_snapshot_fields(snapshot: object) -> dict[str, Any]:
    if not is_dataclass(snapshot) or type(snapshot).__name__ != "RootBootstrapCandidateSelectionSnapshot":
        raise TypeError("root selection registry did not return its sealed typed candidate snapshot")
    names = ("candidate_git_sha", "input_origin", "choice_sha256", "controller_pid",
             "controller_start_ticks", "controller_uid", "controller_gid", "session_id",
             "process_group_id", "tty_device", "tty_inode", "tty_rdevice", "lifecycle_action",
             "issued_monotonic", "expires_monotonic")
    values = {name: getattr(snapshot, name) for name in names}
    if (values.get("input_origin") != "root_tty_explicit"
            or not isinstance(values.get("candidate_git_sha"), str)
            or not _GIT_SHA.fullmatch(values["candidate_git_sha"])
            or not isinstance(values.get("choice_sha256"), str)
            or not _SHA256.fullmatch(values["choice_sha256"])
            or values.get("lifecycle_action") not in {"install", "resume", "update"}):
        raise InstallerReleaseBuildError("root TTY selection snapshot is malformed")
    return values


def _module_identity_projection(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    return [{"name": str(row["name"]), "relative_path": str(row["relative_path"]),
             "sha256": str(row["sha256"])} for row in rows]


def _pidfd_is_live(pidfd: int) -> bool:
    poll = __import__("select").poll()
    poll.register(pidfd, __import__("select").POLLIN | __import__("select").POLLHUP)
    return not bool(poll.poll(0))


def _memfd_seal_constants() -> dict[str, int]:
    """Return Linux memfd seal commands if CPython omitted their names.

    These values are architecture-independent Linux fcntl UAPI constants.
    The pinned standalone CPython build omits the Python bindings, although
    the kernel memfd sealing operations are available.
    """
    if not sys.platform.startswith("linux"):
        raise InstallerReleaseBuildError("sealed bootstrap handoff requires Linux memfd support")
    uapi = {
        "F_ADD_SEALS": 1033,
        "F_GET_SEALS": 1034,
        "F_SEAL_SEAL": 0x0001,
        "F_SEAL_SHRINK": 0x0002,
        "F_SEAL_GROW": 0x0004,
        "F_SEAL_WRITE": 0x0008,
    }
    return {name: int(getattr(fcntl, name, value)) for name, value in uapi.items()}


def _decode_sealed_handoff_descriptor(fd: int) -> tuple[dict[str, Any], os.stat_result, bytes]:
    constants = _memfd_seal_constants()
    seals = fcntl.fcntl(fd, constants["F_GET_SEALS"])
    required = (constants["F_SEAL_WRITE"] | constants["F_SEAL_GROW"]
                | constants["F_SEAL_SHRINK"] | constants["F_SEAL_SEAL"])
    info = os.fstat(fd)
    if (seals & required != required or not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0 or info.st_size > 4096):
        raise InstallerReleaseBuildError("bootstrap transition descriptor is not bounded and sealed")
    os.lseek(fd, 0, os.SEEK_SET)
    message = _read_exact_fd(fd, info.st_size)
    if os.read(fd, 1):
        raise InstallerReleaseBuildError("bootstrap transition descriptor grew during read")
    value = json.loads(message.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if (not isinstance(value, dict) or _canonical_json(value) != message
            or set(value) != {"schema", "handoff_handle", "nonce"} or value.get("schema") != 1
            or not isinstance(value.get("handoff_handle"), str)
            or not _HANDLE.fullmatch(value["handoff_handle"])
            or not isinstance(value.get("nonce"), str) or not value["nonce"]
            or len(value["nonce"]) > 128):
        raise InstallerReleaseBuildError("bootstrap transition descriptor identity is malformed")
    return value, info, message


def _verify_current_selection_snapshot(snapshot: Mapping[str, Any], record: Mapping[str, Any]) -> None:
    required = {"candidate_git_sha", "input_origin", "choice_sha256", "controller_pid",
                "controller_start_ticks", "controller_uid", "controller_gid", "session_id",
                "process_group_id", "tty_device", "tty_inode", "tty_rdevice",
                "issued_monotonic", "expires_monotonic", "lifecycle_action"}
    if not required.issubset(snapshot):
        raise InstallerReleaseBuildError("root candidate snapshot lacks current controller/TTY facts")
    if (snapshot["candidate_git_sha"] != record.get("candidate_git_sha")
            or snapshot["input_origin"] != "root_tty_explicit"
            or snapshot["lifecycle_action"] != record.get("lifecycle_action")
            or snapshot["lifecycle_action"] not in {"install", "resume", "update"}
            or snapshot["controller_pid"] != os.getpid()
            or snapshot["controller_pid"] != record.get("original_pid")
            or snapshot["controller_start_ticks"] != _process_start_ticks(os.getpid())
            or snapshot["controller_start_ticks"] != record.get("original_start_ticks")
            or snapshot["controller_uid"] != 0 or os.getuid() != 0 or os.geteuid() != 0
            or snapshot["controller_gid"] != os.getgid()
            or snapshot["session_id"] != os.getsid(0)
            or snapshot["process_group_id"] != os.getpgrp()
            or time.monotonic() >= min(snapshot["expires_monotonic"], record.get("expires_monotonic", 0))
            or time.monotonic() < snapshot["issued_monotonic"]):
        raise BootstrapEnrollmentPending("root TTY candidate controller is no longer current")
    try:
        tty = os.fstat(0)
        if (not os.isatty(0) or tty.st_dev != snapshot["tty_device"]
                or tty.st_ino != snapshot["tty_inode"] or tty.st_rdev != snapshot["tty_rdevice"]
                or os.tcgetpgrp(0) != snapshot["process_group_id"]):
            raise BootstrapEnrollmentPending("root candidate controlling TTY changed during runtime handoff")
    except OSError:
        raise BootstrapEnrollmentPending("root candidate controlling TTY is unavailable after re-exec") from None


def _write_handoff_record(handle: str, record: Mapping[str, Any]) -> None:
    _ensure_bootstrap_handoff_root()
    root_fd = _open_secure_directory(BOOTSTRAP_HANDOFF_ROOT, expected_uid=0)
    lock_fd = -1
    try:
        lock_fd = os.open(".handoff.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=root_fd)
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or lock_info.st_nlink != 1
                or stat.S_IMODE(lock_info.st_mode) != 0o600):
            raise InstallerReleaseBuildError("bootstrap handoff journal lock custody is invalid")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        destination = handle + ".json"
        try:
            os.stat(destination, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InstallerReleaseBuildError("bootstrap handoff identifier already exists")
        temporary = ".tmp-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=root_fd)
        try:
            _write_all(fd, _canonical_json(record))
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temporary, destination, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(root_fd)


def _read_handoff_record(handle: str) -> dict[str, Any]:
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise InstallerReleaseBuildError("bootstrap handoff journal identifier is malformed")
    root_fd = _open_secure_directory(BOOTSTRAP_HANDOFF_ROOT, expected_uid=0)
    try:
        fd = os.open(handle + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 64 * 1024):
                raise InstallerReleaseBuildError("bootstrap handoff journal record custody is invalid")
            raw = _read_exact_fd(fd, info.st_size)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError):
        raise InstallerReleaseBuildError("bootstrap handoff journal record is malformed") from None
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise InstallerReleaseBuildError("bootstrap handoff journal record is not canonical")
    return value


def _consume_handoff_record(handle: str, record: dict[str, Any]) -> None:
    _transition_handoff_record(handle, record, "consumed")


def _transition_handoff_record(handle: str, record: dict[str, Any], state: str) -> None:
    if state not in {"consumed", "revoked"} or record.get("state") != "pending":
        raise BootstrapEnrollmentPending("bootstrap handoff is not pending for this transition")
    # Keep only non-bearer audit evidence after the one-use transition. In
    # particular, drop the nonce, receipt handles, and TTY/controller snapshot.
    updated = {
        "schema": 1,
        "state": state,
        "handoff_handle": handle,
        "candidate_git_sha": record["candidate_git_sha"],
        "candidate_selection_sha256": record["candidate_selection_sha256"],
        "runtime_closure_sha256": record["runtime_closure_sha256"],
        "issued_monotonic": record["issued_monotonic"],
        "expires_monotonic": record["expires_monotonic"],
        "transitioned_monotonic": time.monotonic(),
    }
    root_fd = _open_secure_directory(BOOTSTRAP_HANDOFF_ROOT, expected_uid=0)
    try:
        lock_fd = os.open(".handoff.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            current = _read_handoff_record(handle)
            if (_canonical_json(current) != _canonical_json(record)
                    or current.get("state") != "pending"):
                raise BootstrapEnrollmentPending("bootstrap handoff changed before consumption")
            temporary = ".tmp-" + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=root_fd)
            try:
                _write_all(fd, _canonical_json(updated))
                os.fchown(fd, 0, 0); os.fchmod(fd, 0o600); os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(temporary, handle + ".json", src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(root_fd)


def _handoff_from_record(record: Mapping[str, Any]) -> RootBootstrapRuntimeHandoff:
    fields = {name: record[name] for name in (
        "candidate_selection_sha256", "lifecycle_action", "distribution_receipt_handle", "interpreter_receipt_handle",
        "candidate_git_sha", "source_tree_digest", "runtime_closure_sha256",
        "expected_executable_sha256", "original_pid", "original_start_ticks", "original_uid",
        "nonce", "issued_monotonic", "expires_monotonic")}
    fields.update(schema=1, handoff_handle=record["handoff_handle"])
    return RootBootstrapRuntimeHandoff(_HANDOFF_SEAL, **fields)


def _fixed_reexec_argv(executable: Path) -> list[str]:
    """Start the sealed runtime without bytecode writes to its closure."""
    return [str(executable), "-B", "-I", "-S", "-c", _fixed_reexec_entry_code()]


def _fixed_reexec_entry_code() -> str:
    return '''
import fcntl, hashlib, json, os, re, stat, sys

seal_uapi = {"F_GET_SEALS": 1034, "F_SEAL_WRITE": 0x0008, "F_SEAL_GROW": 0x0004,
             "F_SEAL_SHRINK": 0x0002, "F_SEAL_SEAL": 0x0001}
def seal_constant(name):
    return int(getattr(fcntl, name, seal_uapi[name]))

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

descriptor = os.fstat(3)
seals = fcntl.fcntl(3, seal_constant("F_GET_SEALS"))
required = (seal_constant("F_SEAL_WRITE") | seal_constant("F_SEAL_GROW")
            | seal_constant("F_SEAL_SHRINK") | seal_constant("F_SEAL_SEAL"))
message = os.read(3, 4097)
if seals & required != required or len(message) > 4096:
    raise RuntimeError("invalid bootstrap transition descriptor")
transport = json.loads(message.decode("utf-8"), object_pairs_hook=unique)
handle = transport.get("handoff_handle")
if (canonical(transport) != message or set(transport) != {"schema", "handoff_handle", "nonce"}
        or transport["schema"] != 1 or not isinstance(handle, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", handle)):
    raise RuntimeError("malformed bootstrap transition descriptor")
root = "/var/lib/hermes-installer/bootstrap-handoffs"
root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
root_info = os.fstat(root_fd)
if root_info.st_uid != 0 or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700:
    raise RuntimeError("bootstrap transition journal custody changed")
record_fd = os.open(handle + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
record_info = os.fstat(record_fd)
if (record_info.st_uid != 0 or record_info.st_gid != 0 or record_info.st_nlink != 1
        or stat.S_IMODE(record_info.st_mode) != 0o600 or record_info.st_size > 65536):
    raise RuntimeError("bootstrap transition record custody changed")
raw = os.read(record_fd, record_info.st_size + 1)
os.close(record_fd)
os.close(root_fd)
record = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
if (canonical(record) != raw or record.get("state") != "pending"
        or record.get("handoff_handle") != handle or record.get("nonce") != transport.get("nonce")
        or descriptor.st_dev != record.get("memfd_device")
        or descriptor.st_ino != record.get("memfd_inode")
        or hashlib.sha256(message).hexdigest() != record.get("memfd_sha256")):
    raise RuntimeError("bootstrap transition record does not match its sealed descriptor")
candidate = record.get("candidate_git_sha")
runtime_closure = record.get("runtime_closure_sha256")
if (not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-f]{40}", candidate)
        or not isinstance(runtime_closure, str) or not re.fullmatch(r"[0-9a-f]{64}", runtime_closure)):
    raise RuntimeError("bootstrap transition selection is malformed")
runtime = "/var/lib/hermes-installer/bootstrap-runtimes/" + runtime_closure + "/python"
source = "/var/lib/hermes-installer/source-cas/installer/" + candidate + "/source/src"
if not os.path.isdir(runtime) or not os.path.isdir(source):
    raise RuntimeError("selected source or isolated runtime is absent")
os.chdir("/")
sys.dont_write_bytecode = True
sys.path = [entry for entry in sys.path if os.path.realpath(entry).startswith(os.path.realpath(runtime) + os.sep)]
sys.path.insert(0, runtime + "/" + record["site_relative_path"])
sys.path.insert(0, source)
from hermes_installer.authority.installer_release_build import _bootstrap_after_reexec
_bootstrap_after_reexec()
'''


def _measure_current_source_modules(source: VerifiedInstallerDistributionReceipt,
                                    *, require_source_origin: bool) -> list[dict[str, Any]]:
    root = distribution_root(source).resolve(strict=True)
    source_files = {row.relative_path: row for row in source.files}
    rows: list[dict[str, Any]] = []
    for name, module in sorted(sys.modules.items()):
        if name != "hermes_installer" and not name.startswith("hermes_installer."):
            continue
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not isinstance(origin, str) or not Path(origin).is_absolute():
            continue
        actual_path = Path(origin).resolve(strict=True)
        try:
            relative_in_source = actual_path.relative_to(root).as_posix()
        except ValueError:
            # Host stage-zero modules must byte-match the selected candidate;
            # after exec, their origins must actually be within SourceCAS.
            if require_source_origin:
                raise InstallerReleaseBuildError("bootstrap actor module origin is outside selected SourceCAS") from None
            actual_sha, _ = _hash_path(actual_path, MAX_SOURCE_FILE_BYTES)
            module_path = "src/" + name.replace(".", "/")
            candidates = [candidate for candidate in (module_path + ".py", module_path + "/__init__.py")
                          if candidate in source_files and source_files[candidate].sha256 == actual_sha]
            if len(candidates) != 1:
                raise InstallerReleaseBuildError("stage-zero module does not uniquely byte-match the selected source")
            source_relative = candidates[0]
        else:
            source_relative = relative_in_source
        row = source_files.get(source_relative)
        if row is None:
            if require_source_origin:
                raise InstallerReleaseBuildError("loaded installer module is not a selected source member")
            continue
        fd = source.open_file(source_relative)
        try:
            source_sha, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        finally:
            os.close(fd)
        actual_sha, _ = _hash_path(actual_path, MAX_SOURCE_FILE_BYTES)
        if actual_sha != source_sha or source_sha != row.sha256:
            raise InstallerReleaseBuildError("loaded stage-zero source module differs from authorized candidate bytes")
        rows.append({"name": name, "relative_path": source_relative, "sha256": actual_sha,
                     "device": actual_path.stat().st_dev, "inode": actual_path.stat().st_ino})
    if not any(row["name"] == "hermes_installer.authority.installer_release_build" for row in rows):
        raise BootstrapEnrollmentPending("release build source module is not loaded in the current root process")
    return rows


def _process_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw[raw.rfind(")") + 2:].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        raise BootstrapEnrollmentPending("root bootstrap process start time is unavailable") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _remove_tree_no_follow(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
        return
    for entry in path.iterdir():
        _remove_tree_no_follow(entry)
    path.rmdir()


def _fsync_tree(root_fd: int) -> None:
    def walk(directory_fd: int) -> None:
        with os.scandir(os.dup(directory_fd)) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory_fd)
                    try:
                        walk(child)
                    finally:
                        os.close(child)
        os.fsync(directory_fd)
    walk(root_fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_linux_root() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or os.getuid() != 0:
        raise BootstrapEnrollmentPending("installer source CAS acquisition requires the managed Linux root bootstrap")
