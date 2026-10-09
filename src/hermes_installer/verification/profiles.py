"""Installer-owned assertion contracts for every acceptance evidence ID.

Profiles are intentionally keyed by evidence ID (not broad acceptance groups)
so a target owner cannot replace a missing behavior with a generic ``true``
assertion or submit one evidence row for an unrelated probe.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ProbeProfile:
    acceptance_ids: tuple[str, ...]
    assertions: tuple[str, ...]


_ROWS = {
    "EV-R0169": ProbeProfile(("AC01",), ("fresh_install_complete", "existing_install_adopted", "unrelated_files_preserved", "configuration_preserved")),
    "EV-R0170": ProbeProfile(("AC02",), ("second_run_completed", "services_unique", "profiles_skills_jobs_accounts_mcp_unique")),
    "EV-R0171": ProbeProfile(("AC03",), ("interrupted_download_resumed", "interrupted_install_resumed", "package_lock_failure_actionable", "network_dns_failure_actionable", "disk_exhaustion_recoverable")),
    "EV-R0172": ProbeProfile(("AC04",), ("failed_update_preserved_prior_generation", "backup_archive_integrity", "compatible_restore_verified")),
    "EV-R0173": ProbeProfile(("AC05",), ("native_discovery", "declaration_validation", "source_runtime_mapping", "missing_dependency_pending", "inheritance_resolved", "skill_references_resolved", "profile_isolation_verified")),
    "EV-R0174": ProbeProfile(("AC06",), ("enabled_boundary_enforced", "unauthorized_effect_denied", "denial_had_no_effect", "prompt_only_configuration_rejected")),
    "EV-R0175": ProbeProfile(("AC07",), ("official_desktop_launched", "backend_connected", "hello_response", "cancellation_observed", "restart_verified", "harmless_tool_effect")),
    "EV-R0176": ProbeProfile(("AC08",), ("provider_inference_completed", "tool_call_completed", "ineligible_account_denied", "rate_limit_bounded", "paid_fallback_denied", "private_route_preserved_through_extraction_and_retry")),
    "EV-R0177": ProbeProfile(("AC09",), ("glm52_artifact_identity_verified", "arm64_engine_inference", "resource_performance_measured", "slow_path_bounded_and_reported")),
    "EV-R0178": ProbeProfile(("AC10",), ("coral_device_selected", "delegate_loaded", "delegate_used", "inference_completed", "output_digest_recorded")),
    "EV-R0179": ProbeProfile(("AC11",), ("selected_mcp_read_completed", "mcp_init_bounded", "playwright_fixture_screenshot", "memory_cross_session_retrieval")),
    "EV-R0180": ProbeProfile(("AC12",), ("component_coverage_complete", "representative_integrations_completed", "core_chat_usable_during_heavy_workloads")),
    "EV-R0196": ProbeProfile(("AC13",), ("hostname_prompt_blank", "hostname_validated", "noninteractive_selection_explicit")),
    "EV-R0197": ProbeProfile(("AC13",), ("scoped_secret_input", "authorized_account_zone_discovered", "secret_absent_from_logs")),
    "EV-R0198": ProbeProfile(("AC13",), ("owned_tunnel_reused_or_created", "least_privilege_runtime_credential", "unowned_conflict_preserved")),
    "EV-R0199": ProbeProfile(("AC13",), ("exact_dns_route_configured", "loopback_gateway_origin", "terminal_404_catchall")),
    "EV-R0200": ProbeProfile(("AC13",), ("access_application_owned", "email_otp_enabled", "explicit_email_allowlist")),
    "EV-R0201": ProbeProfile(("AC14", "AC15"), ("jwt_signature_algorithm_issuer_audience_time_verified", "principal_authorized_before_any_response_bytes")),
    "EV-R0202": ProbeProfile(("AC14",), ("registered_desktop_routes_only", "arbitrary_paths_origins_targets_denied", "backend_management_routes_denied")),
    "EV-R0203": ProbeProfile(("AC14",), ("official_native_desktop_pixels", "dedicated_constrained_session", "not_dashboard_or_host_desktop")),
    "EV-R0204": ProbeProfile(("AC14",), ("new_command_shell_control_denied", "file_clipboard_device_audio_proxy_debug_controls_disabled")),
    "EV-R0205": ProbeProfile(("AC14", "AC15"), ("session_bound_to_verified_principal", "native_profile_bound_to_session", "cross_user_session_hijack_denied", "concurrent_session_limit_enforced")),
    "EV-R0206": ProbeProfile(("AC15",), ("stream_closed_by_lease_deadline", "frame_activity_did_not_renew_lease", "fresh_http_reauthorization_required", "revocation_closed_stream_within_bound")),
    "EV-R0207": ProbeProfile(("AC13",), ("setup_resume_idempotent", "update_rollback_owned", "disable_uninstall_preserve_unowned_resources")),
    "EV-R0208": ProbeProfile(("AC13",), ("origin_protection_ready_before_dns_activation", "unsafe_origin_prevented_ingress")),
    "EV-R0209": ProbeProfile(("AC13",), ("management_secret_setup_only", "runtime_tunnel_credential_isolated", "gateway_has_no_management_secret")),
    "EV-R0210": ProbeProfile(("AC13",), ("configure_later_supported", "secure_reference_resumed", "routine_setup_no_repeat_prompt", "doctor_reports_exact_pending_step")),
    "EV-R0211": ProbeProfile(("AC14", "AC15"), ("unauthorized_http_denied", "unauthorized_websocket_denied", "official_desktop_only", "expiry_and_revocation_bounded", "replay_and_contention_denied")),
    "EV-RB01": ProbeProfile(("AC16",), ("packaged_bundle_digest_verified", "no_resources_network_access", "native_materialization_from_packaged_input")),
    "EV-RB02": ProbeProfile(("AC16",), ("all_692_items_have_destination_or_exact_blocker", "native_profile_and_skill_discovery", "selected_native_workflow_invoked")),
    "EV-RB03": ProbeProfile(("AC16",), ("all_required_handlers_mapped", "required_hook_effect_observed", "incompatible_or_unlicensed_item_incomplete")),
    "EV-RB04": ProbeProfile(("AC16",), ("all_739_source_paths_and_digests_preserved", "user_overlay_preserved", "conflict_quarantined", "failed_generation_rolled_back")),
    "EV-RB05": ProbeProfile(("AC16",), ("missing_account_dependency_remains_incomplete", "no_native_operation_fabricated", "exhaustive_item_ledger_retained")),
    "EV-RP01": ProbeProfile(("AC17",), ("separate_read_credential_required", "no_setup_token_runtime_fallback", "remote_incomplete_without_read_authority")),
    "EV-RP02": ProbeProfile(("AC17",), ("credential_read_denied_to_workers", "secret_canary_absent_from_all_surfaces", "verifier_rejected_before_network_effect")),
    "EV-RP03": ProbeProfile(("AC17",), ("fresh_exact_access_membership_read", "no_new_grant_or_lease_extension", "malformed_policy_response_safe")),
    "EV-RP04": ProbeProfile(("AC17",), ("read_deadline_bounded", "cancelled_result_discarded", "lease_not_extended_while_waiting", "no_thread_or_replay_accumulation")),
    "EV-RP05": ProbeProfile(("AC17",), ("rotation_resumable_and_revalidated", "leases_stop_at_existing_deadline", "no_setup_secret_promotion", "plaintext_backup_absent")),
    "EV-RP06": ProbeProfile(("AC17",), ("policy_revocation_recorded_separately", "token_logout_revocation_pending_without_proof", "event_and_provider_visibility_times_recorded")),
    "EV-HI01": ProbeProfile(("AC18",), ("privileged_authority_outside_worker_writable_namespace", "distinct_host_identity", "authenticated_scoped_ipc", "untrusted_activation_rejected_before_effect")),
    "EV-HI02": ProbeProfile(("AC18",), ("actual_uid_namespace_target_identified", "host_file_read_denied", "proc_visibility_and_signal_denied", "inet_socket_denied", "hostile_descendant_emptied")),
    "EV-HI03": ProbeProfile(("AC18",), ("authoritative_identity_recipient_checked", "unauthorized_host_write_denied", "no_outbound_effect", "no_cached_claim_fallback")),
    "EV-HI04": ProbeProfile(("AC18",), ("native_dispatch_mediated", "direct_native_bypass_denied", "ineligible_route_receives_no_request_or_secret")),
    "EV-HI05": ProbeProfile(("AC18",), ("owned_generation_recovered_or_disabled", "stale_grant_rejected", "unrelated_bytes_preserved", "credentials_preserved")),
    "EV-HI06": ProbeProfile(("AC18",), ("implementation_and_target_evidence_separate", "target_tasks_remain_open_without_observation", "no_full_compliance_label")),
    "EV-HI07": ProbeProfile(("AC18",), ("connector_target_principal_generation_bound", "caller_destination_override_denied_before_bytes", "expired_stream_cancelled_at_original_deadline", "worker_external_network_remains_denied")),
    "EV-HI08": ProbeProfile(("AC18",), ("host_receipt_binds_source_bytes_and_lineage", "sensitivity_inherits_all_contributors", "final_payload_digest_verified", "missing_or_stale_lineage_denied_before_effect")),
    "EV-HI09": ProbeProfile(("AC18",), ("opaque_enrollment_selects_fixed_executable_and_socket", "service_home_work_data_roots_are_distinct", "caller_physical_root_override_rejected", "attested_process_identity_matches_enrollment")),
    "EV-HI11": ProbeProfile(("AC18",), ("producer_gateway_identity_and_generation_bound", "complete_source_closure_and_final_payload_bound", "operation_retry_and_bounded_lease_bound", "gateway_peer_authenticated_and_admission_atomically_consumed", "opaque_reference_and_caller_header_authority_denied")),
    "EV-HI12": ProbeProfile(("AC18",), ("capability_operation_target_and_canonical_payload_bound", "shared_target_does_not_imply_cross_operation_permission", "fresh_one_use_frame_grants_preserve_original_stream_deadline", "trusted_expiry_and_revocation_cleanup_independent_and_observed")),
    "EV-HI10": ProbeProfile(("AC18",), ("registered_process_handle_required", "current_cgroup_descendants_attested", "stable_kernel_identity_and_executable_pin_verified", "renderer_lineage_and_sandbox_attested", "caller_pid_path_argv_and_sibling_handles_denied")),
    "EV-HW01": ProbeProfile(("AC10",), ("protected_manifest_runtime_and_generation_bound", "only_exact_pinned_numpy_tflite_wheels_selected", "target_abi_and_attested_runtime_match", "offline_fixed_install_succeeds_without_host_or_hermes_mutation", "caller_paths_urls_pip_args_extra_wheels_rejected", "wrong_hash_runtime_abi_root_network_enospc_cancel_preserve_prior_generation")),
    "EV-RB06": ProbeProfile(("AC16",), ("fixed_service_action_and_public_query_bound", "bounded_metadata_parameters_before_network", "redirects_private_unknown_query_and_arbitrary_destination_denied", "read_results_untrusted_and_never_activate_resources")),
    "EV-RB07": ProbeProfile(("AC16",), ("selected_enabled_generation_and_authenticated_event_verified", "single_bounded_job_admission_consumed", "fresh_reduced_grant_per_child_and_attempt", "source_lineage_sensitivity_and_recipient_bound", "budget_concurrency_runtime_payload_replay_limits_enforced", "unselected_stale_or_replayed_event_denied_before_effect")),
    "EV-RB08": ProbeProfile(("AC16",), ("root_enrolled_finite_action_and_handler_digest_bound", "exact_capability_operation_target_generation_bound", "canonical_arguments_and_final_digest_bound_to_one_use_grant", "principal_profile_recipient_and_credential_scope_verified", "confirmation_and_idempotency_enforced", "wrong_action_identity_scope_confirmation_replay_and_duplicate_denied_before_effect", "private_recipient_and_cancellation_preserved", "unsupported_or_unqualified_actions_unavailable")),
    "EV-PR01": ProbeProfile(("AC08",), ("public_client_pkce_state_nonce_loopback_bound", "id_token_signature_issuer_audience_expiry_nonce_account_checked", "documented_plan_usage_scope_granted", "credential_reference_single_host_custody_and_rotation", "root_only_tls_sse_store_false_stream_true", "response_completed_required_and_failed_partial_or_cancelled_streams_rejected", "unsupported_fields_tools_and_retries_rejected_without_paid_fallback")),
}

PROBE_PROFILES = MappingProxyType(_ROWS)


def profile_for(evidence_id: str, acceptance_id: str) -> ProbeProfile:
    profile = PROBE_PROFILES.get(evidence_id)
    if profile is None or acceptance_id not in profile.acceptance_ids:
        raise ValueError("no installer-owned target probe profile exists for this evidence and acceptance ID")
    return profile
