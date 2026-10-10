from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_installer.authority.initial_policy_compiler import (
    TEMPLATE_ARTIFACT_ID,
    TEMPLATE_SHA256,
    InitialPolicyCompilationError,
    _RootBindings,
    _render_closed_template,
    _parse_receipt_bindings_template,
    _render_prepared_receipt_bindings,
    _render_prepared_authority_base,
)


REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "plans/amendments/2026-10-09-closed-bootstrap-compiler-template-v30/bootstrap-compiler-template-v1.json"
PREPARED_BASE = REPO / "plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63/prepared-authority-base-template-v1.json"
RECEIPT_BINDINGS = REPO / "plans/amendments/2026-10-10-literal-bootstrap-receipt-bindings-v72/bootstrap-receipt-bindings-template-v1.json"


def _binding_names(value):
    if isinstance(value, dict):
        if set(value) == {"root_binding"}:
            yield value["root_binding"]
        for item in value.values():
            yield from _binding_names(item)
    elif isinstance(value, list):
        for item in value:
            yield from _binding_names(item)


def _fixture_bindings(raw: bytes) -> _RootBindings:
    template = json.loads(raw)
    values = {}
    for name in set(_binding_names(template)):
        if name == "principal.principal_id":
            continue
        if name in {"nss.service_uid", "nss.service_gid"}:
            values[name] = 41001 if name.endswith("uid") else 41002
        elif name.endswith("sha256"):
            values[name] = "a" * 64
        elif name in {"roots.home", "roots.work", "roots.data", "pm.catalog_executable_path"}:
            values[name] = "/owned/fixture/path"
        elif name in {"pm.runtime_artifact_ids", "pm.package_runtime_records", "native.child_artifact_refs"}:
            values[name] = ["fixture-observation"]
        else:
            values[name] = "fixture-observation"
    return _RootBindings(values=values, principal_id="selected-principal-1")


def test_renders_only_the_pinned_v30_template_and_finite_root_facts():
    raw = TEMPLATE.read_bytes()
    assert len(raw) == 4281
    import hashlib
    assert hashlib.sha256(raw).hexdigest() == TEMPLATE_SHA256

    rendered = _render_closed_template(raw, _fixture_bindings(raw))

    assert rendered["id"] == TEMPLATE_ARTIFACT_ID
    assert rendered["source_artifact_id"] == "hermes-source-7085fbf7753266fc4943c55ac04926186bc90005"
    assert rendered["service_record_template"]["principal_id"] == "selected-principal-1"
    assert rendered["service_record_template"]["roots"]["home"] == "/owned/fixture/path"
    assert not list(_binding_names(rendered))


@pytest.mark.parametrize("mutate", [
    lambda raw: raw + b" ",
    lambda raw: raw.replace(b'"root_binding":"roots.home"', b'"root_binding":"caller.path"'),
    lambda raw: raw.replace(b'"schema":1', b'"schema":NaN', 1),
])
def test_rejects_template_drift_and_unknown_or_invalid_binding_inputs(mutate):
    raw = TEMPLATE.read_bytes()
    with pytest.raises(InitialPolicyCompilationError):
        _render_closed_template(mutate(raw), _fixture_bindings(raw))


def test_missing_principal_or_uid_fact_stays_pending():
    raw = TEMPLATE.read_bytes()
    bindings = _fixture_bindings(raw)
    with pytest.raises(InitialPolicyCompilationError, match="principal.principal_id"):
        _render_closed_template(raw, _RootBindings(bindings.values, None))

    values = dict(bindings.values)
    values["nss.service_uid"] = 0
    with pytest.raises(InitialPolicyCompilationError, match="service ID"):
        _render_closed_template(raw, _RootBindings(values, bindings.principal_id))


def test_namespace_identity_remains_pending_without_a_root_issued_observation():
    raw = TEMPLATE.read_bytes()
    bindings = _fixture_bindings(raw)
    values = dict(bindings.values)
    values.pop("transaction.namespace_identity", None)
    with pytest.raises(InitialPolicyCompilationError, match="transaction.namespace_identity"):
        _render_closed_template(raw, _RootBindings(values, bindings.principal_id))


def test_v63_prepared_authority_binds_actual_key_and_exact_dormant_snapshot():
    journal = {
        "root_id": "installer-authority-journal-v1", "absolute_path": "/owned/journal",
        "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 4, "inode": 9,
        "generation": "journal-4-9", "purpose": "authority-journal",
    }
    rendered = _render_prepared_authority_base(
        PREPARED_BASE.read_bytes(), key_id="authority-key-" + "a" * 32,
        root_journal_root=journal, generation_id="prepared-test")

    assert rendered["key_id"] == "authority-key-" + "a" * 32
    assert rendered["authentik"] == {}
    assert rendered["principals"] == rendered["rules"] == rendered["process_profiles"] == {}
    snapshot = rendered["service_generations"]
    assert snapshot["generation_id"] == "prepared-test"
    assert snapshot["service_records"] == []
    assert snapshot["root_journal_roots"] == [journal]
    assert snapshot["remote_startup_enrollments"] == []
    assert snapshot["private_loopback_networks"] == []
    assert snapshot["selected_resource_executions"] == []
    assert snapshot["selected_application_runtimes"] == []
    assert snapshot["private_memory_endpoint_selections"] == []
    assert snapshot["private_memory_model_selections"] == []
    assert snapshot["public_web_scopes"] == []
    assert snapshot["memory_service_enablement_projections"] == []
    assert snapshot["native_worker_network_records"] == []
    assert snapshot["active_network_generation_records"] == []
    assert snapshot["native_worker_runtime_records"] == []
    assert snapshot["owner_overlay_observer_records"] == []
    assert set(snapshot) == {
        "schema", "generation_id", "service_records", "protected_devices", "protected_build_records",
        "native_packages", "memory_enrollments", "memory_service_enablement_projections", "operation_parameter_schemas", "source_issuers",
        "resource_jobs", "remote_session_enrollments", "resource_backend_enrollments",
        "resource_body_recipes", "resource_scope_bindings", "resource_validators", "root_journal_roots",
        "resource_controller_roles", "native_mcp_tool_bindings", "remote_observation_enrollments",
        "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings",
        "remote_startup_enrollments", "private_loopback_networks",
        "selected_resource_executions", "selected_application_runtimes",
        "private_memory_endpoint_selections", "private_memory_model_selections",
        "public_web_scopes",
        "native_worker_network_records", "active_network_generation_records",
        "native_worker_runtime_records", "owner_overlay_observer_records",
        "generation_digest",
    }


@pytest.mark.parametrize("key_id", ["guessed", "authority-key-abc", "authority-key-" + "A" * 32])
def test_prepared_authority_rejects_unverified_or_malformed_key_ids(key_id):
    journal = {
        "root_id": "installer-authority-journal-v1", "absolute_path": "/owned/journal",
        "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 4, "inode": 9,
        "generation": "journal-4-9", "purpose": "authority-journal",
    }
    with pytest.raises(InitialPolicyCompilationError, match="verified root key receipt"):
        _render_prepared_authority_base(PREPARED_BASE.read_bytes(), key_id=key_id,
                                        root_journal_root=journal, generation_id="prepared-test")


def test_prepared_authority_rejects_template_drift_and_nonempty_policy_rows():
    journal = {
        "root_id": "installer-authority-journal-v1", "absolute_path": "/owned/journal",
        "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 4, "inode": 9,
        "generation": "journal-4-9", "purpose": "authority-journal",
    }
    raw = PREPARED_BASE.read_bytes()
    with pytest.raises(InitialPolicyCompilationError, match="wrong size"):
        _render_prepared_authority_base(raw + b" ", key_id="authority-key-" + "a" * 32,
                                        root_journal_root=journal, generation_id="prepared-test")
    with pytest.raises(InitialPolicyCompilationError, match="installed authority schema"):
        _render_prepared_authority_base(raw, key_id="authority-key-" + "a" * 32,
                                        root_journal_root={**journal, "owner_uid": 1000},
                                        generation_id="prepared-test")


def test_v72_literal_receipt_bindings_source_is_closed_and_typed():
    doc = _parse_receipt_bindings_template(RECEIPT_BINDINGS.read_bytes())
    assert doc["id"] == "installer-bootstrap-receipt-bindings-template-v1"
    assert len(doc["service_record_templates"]) == 1
    assert [row["receipt_role"] for row in doc["receipt_binding_rules"]] == [
        "official-agent-source", "official-installer-script", "official-pm-lock",
        "official-pm-runtime", "resources-source-bundle", "native-compiled-closure",
        "native-entrypoint-manifest", "native-action-resolver", "native-boundary-overlay",
        "native-candidate-index", "native-health",
    ]
    assert doc["typed_receipt_fields"]["official-pm-runtime"] == [
        "catalog_executable_path", "executable_sha256", "runtime_artifact_ids",
        "package_runtime_records", "executable_artifact_id",
    ]


def test_v72_literal_receipt_bindings_reject_source_drift():
    raw = RECEIPT_BINDINGS.read_bytes()
    with pytest.raises(InitialPolicyCompilationError, match="wrong size"):
        _parse_receipt_bindings_template(raw + b" ")


def test_prepared_receipt_rules_resolve_only_pinned_source_ids_and_keep_future_roles_empty():
    raw = RECEIPT_BINDINGS.read_bytes()
    record = _render_closed_template(raw=TEMPLATE.read_bytes(), bindings=_RootBindings(
        values={"transaction.process_generation": "tx-" + "a" * 32,
                "transaction.namespace_identity": "namespace-reviewed",
                "roots.home": "/var/lib/hermes-installer/services/hermes-agent-native-v1/home",
                "roots.work": "/var/lib/hermes-installer/services/hermes-agent-native-v1/work",
                "roots.data": "/var/lib/hermes-installer/services/hermes-agent-native-v1/data"},
        principal_id="principal-reviewed"))["service_record_template"]
    catalog = json.loads((REPO / "src/hermes_installer/authority/artifact-catalog.json").read_text())
    # Use the actual checked-in source row and full metadata, as the installed
    # release compiler does; do not synthesize catalog authority in the fixture.
    allowed = tuple(sorted(row["artifact_id"] for row in catalog["artifacts"]))
    rules, service = _render_prepared_receipt_bindings(
        raw, source_template_raw=TEMPLATE.read_bytes(), service_record=record, artifact_catalog=catalog,
        allowed_plan_artifact_ids=allowed)
    assert service["id"] == "hermes-agent-native-template-v1"
    assert service["record"] == record
    assert service["record"]["executable"] is None
    assert service["record"]["service_uid"] is None
    assert next(row for row in rules if row["receipt_role"] == "official-installer-script")[
        "allowed_artifact_ids"] == ["hermes-agent-install-script"]
    assert all(row["allowed_artifact_ids"] == [] for row in rules
               if row["required_phase"] in {"runnable", "functional-health"})


def test_prepared_receipt_rules_reject_wrong_script_or_future_receipt_ids():
    raw = RECEIPT_BINDINGS.read_bytes()
    record = {"profile_id": "hermes-agent-native-v1"}
    catalog = json.loads((REPO / "src/hermes_installer/authority/artifact-catalog.json").read_text())
    allowed = tuple(sorted(row["artifact_id"] for row in catalog["artifacts"]))
    wrong = json.loads(json.dumps(catalog))
    script = next(row for row in wrong["artifacts"] if row["artifact_id"] == "hermes-agent-install-script")
    script["sha256"] = "0" * 64
    with pytest.raises(InitialPolicyCompilationError, match="script catalog role"):
        _render_prepared_receipt_bindings(raw, service_record=record,
                                          source_template_raw=TEMPLATE.read_bytes(),
                                          artifact_catalog=wrong,
                                          allowed_plan_artifact_ids=allowed)


def test_prepared_receipt_rules_fail_closed_when_selected_plan_lacks_resources_role():
    raw = RECEIPT_BINDINGS.read_bytes()
    record = _render_closed_template(raw=TEMPLATE.read_bytes(), bindings=_RootBindings(
        values={"transaction.process_generation": "tx-" + "a" * 32,
                "transaction.namespace_identity": "namespace-reviewed",
                "roots.home": "/var/lib/hermes-installer/services/hermes-agent-native-v1/home",
                "roots.work": "/var/lib/hermes-installer/services/hermes-agent-native-v1/work",
                "roots.data": "/var/lib/hermes-installer/services/hermes-agent-native-v1/data"},
        principal_id="principal-reviewed"))["service_record_template"]
    catalog = json.loads((REPO / "src/hermes_installer/authority/artifact-catalog.json").read_text())
    allowed = tuple(sorted(row["artifact_id"] for row in catalog["artifacts"]
                           if row["artifact_id"] != "resources-source-113f42d33be9e0c8f0f47f5ca998e687323dec83"))
    with pytest.raises(InitialPolicyCompilationError, match="escapes the selected plan/catalog"):
        _render_prepared_receipt_bindings(
            raw, source_template_raw=TEMPLATE.read_bytes(), service_record=record,
            artifact_catalog=catalog, allowed_plan_artifact_ids=allowed)
