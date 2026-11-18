"""Source-bound partial specialist components with a closed inert-data dispatcher."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .army_expansion import ArmyExpansionRoadmap
from .attack_vectors import AttackVectorCatalog
from .aws_scp_analysis import analyze_aws_scp
from .aws_vpc_flow_analysis import analyze_supplied_aws_vpc_flow
from .azure_rbac_analysis import analyze_azure_rbac
from .candidate_blueprints_v2 import CandidateBlueprintCatalogV2
from .candidate_implementation_strategy import CandidateImplementationStrategy
from .errors import QualificationError
from .gcp_iam_analysis import analyze_gcp_iam
from .implementation_program_v2 import build_implementation_program_v2
from .kubernetes_network_policy_analysis import analyze_supplied_kubernetes_network_policy
from .kubernetes_pod_security_analysis import analyze_supplied_kubernetes_pod_security
from .kubernetes_rbac_analysis import analyze_kubernetes_rbac
from .offline_account_recovery_threshold import analyze_supplied_account_recovery
from .offline_analytics_sharing import analyze_supplied_analytics_sharing
from .offline_archive_member_paths import analyze_supplied_archive_member_paths
from .offline_agent_plan_integrity import analyze_supplied_agent_plan_integrity
from .offline_agent_output_handling import analyze_supplied_agent_output_handling
from .offline_indirect_prompt_boundary import analyze_supplied_indirect_prompt_boundary
from .offline_rag_provenance import analyze_supplied_rag_provenance
from .offline_agent_memory_provenance import analyze_supplied_agent_memory_provenance
from .offline_agent_resource_budget import analyze_supplied_agent_resource_budget
from .offline_pickle_opcode_safety import (
    analyze_supplied_pickle_opcodes as analyze_supplied_model_pickle_opcodes,
)
from .offline_model_artifact_integrity import analyze_supplied_model_artifact_integrity
from .offline_agent_credential_boundary import analyze_supplied_agent_credential_boundary
from .offline_evasion_delta_measurement import analyze_supplied_evasion_deltas
from .offline_training_label_drift import analyze_supplied_training_label_drift
from .offline_model_trigger_selectivity import analyze_supplied_model_trigger_selectivity
from .offline_mlops_lineage import analyze_supplied_mlops_lineage
from .offline_model_output_similarity import analyze_supplied_model_output_similarity
from .offline_membership_score_separation import analyze_supplied_membership_scores
from .offline_prompt_canary_exposure import analyze_supplied_prompt_canaries
from .offline_s3_public_grant_controls import analyze_supplied_s3_public_grants
from .offline_proxy_storage_layout import analyze_supplied_proxy_storage_layout
from .offline_reentrancy_state_order import analyze_supplied_reentrancy_state_order
from .offline_oracle_twap_deviation import analyze_supplied_oracle_twap
from .offline_bridge_claim_replay import analyze_supplied_bridge_claims
from .offline_governance_quorum_reconciliation import analyze_supplied_governance_quorum
from .offline_consensus_vote_equivocation import analyze_supplied_consensus_votes
from .offline_wallet_threshold_authorization import analyze_supplied_wallet_threshold
from .offline_rpc_response_discrepancy import analyze_supplied_rpc_responses
from .offline_evm_origin_authorization import analyze_supplied_evm_origin_authorization
from .offline_wasm_host_import_boundary import analyze_supplied_wasm_host_imports
from .offline_token_transfer_arithmetic import analyze_supplied_token_transfers
from .offline_mev_trade_order_pattern import analyze_supplied_mev_trade_order
from .offline_private_endpoint_path import analyze_supplied_private_endpoint_paths
from .offline_kms_grant_separation import analyze_supplied_kms_grants
from .offline_cloud_logging_guardrail_timeline import analyze_supplied_cloud_logging
from .offline_workspace_external_sharing import analyze_supplied_workspace_sharing
from .offline_compute_ingress_scope import analyze_supplied_compute_ingress
from .offline_managed_paas_grant_scope import analyze_supplied_managed_paas_grants
from .offline_workforce_idp_mfa_paths import analyze_supplied_workforce_idp_mfa_paths
from .offline_data_cloud_grant_scope import analyze_supplied_data_cloud_grants
from .offline_bacnet_device_identity import analyze_supplied_bacnet_device_identity
from .offline_ros2_security_declaration import analyze_supplied_ros2_security
from .offline_iec61850_subscription_refs import analyze_supplied_iec61850_subscriptions
from .offline_cip_security_declaration import analyze_supplied_cip_security
from .offline_acpi_table_integrity import analyze_supplied_acpi_table
from .offline_redfish_role_privileges import analyze_supplied_redfish_role_privileges
from .offline_usb_descriptor_framing import analyze_supplied_usb_descriptors
from .offline_iommu_group_separation import analyze_supplied_iommu_groups
from .offline_gpu_instance_tenant_boundary import analyze_supplied_gpu_tenant_boundary
from .offline_riscv_pmp_projection import analyze_supplied_riscv_pmp
from .offline_tpm_pcr_replay import analyze_supplied_tpm_pcr
from .offline_ot_zone_conduit_projection import analyze_supplied_ot_zone_conduits
from .offline_gpu_management_node_permissions import (
    analyze_supplied_gpu_management_node_permissions,
)
from .offline_firmware_update_metadata import analyze_supplied_esrt_update_metadata
from .offline_management_engine_state import analyze_supplied_management_engine_state
from .offline_ot_remote_access_policy import analyze_supplied_ot_remote_access
from .offline_firmware_inventory_sbom import analyze_supplied_firmware_inventory_sbom
from .offline_firmware_emulation_trace import analyze_supplied_firmware_emulation_trace
from .offline_firmware_rtos_task_policy import analyze_supplied_firmware_rtos_task_policy
from .offline_firmware_debug_interface_inventory import (
    analyze_supplied_firmware_debug_interface_inventory,
)
from .offline_firmware_secure_element_assertions import (
    analyze_supplied_firmware_secure_element_assertions,
)
from .offline_firmware_tamper_provenance import analyze_supplied_firmware_tamper_provenance
from .offline_secure_boot_update_chain import analyze_supplied_secure_boot_update_chain
from .offline_oci_image_layers import analyze_supplied_oci_image_layers
from .offline_third_party_trust_paths import analyze_supplied_third_party_trust_paths
from .offline_adcs_template_rights import analyze_supplied_adcs_template_rights
from .offline_vehicle_gateway_graph import analyze_supplied_vehicle_gateway_graph
from .offline_vehicle_diagnostic_policy import analyze_supplied_vehicle_diagnostic_policy
from .offline_vehicle_service_declarations import analyze_supplied_vehicle_service_declarations
from .offline_kubernetes_api_authentication import analyze_supplied_kubernetes_api_authentication
from .offline_kubernetes_secret_references import analyze_supplied_kubernetes_secret_references
from .offline_oci_registry_signature_bindings import (
    analyze_supplied_oci_registry_signature_bindings,
)
from .offline_kubernetes_runtime_reconciliation import (
    analyze_supplied_kubernetes_runtime_reconciliation,
)
from .offline_container_runtime_declarations import (
    analyze_supplied_container_runtime_declarations,
)
from .offline_kubernetes_control_plane_declarations import (
    analyze_supplied_kubernetes_control_plane_declarations,
)
from .offline_container_boundary_path_declarations import (
    analyze_supplied_container_boundary_paths,
)
from .offline_serverless_event_declarations import (
    analyze_supplied_serverless_event_declarations,
)
from .offline_multicluster_tenant_declarations import (
    analyze_supplied_multicluster_tenant_declarations,
)
from .offline_kerberos_ad_declarations import analyze_supplied_kerberos_ad
from .offline_ntlm_control_pairs import analyze_supplied_ntlm_control_pairs
from .offline_dc_topology_declarations import analyze_supplied_dc_topology
from .offline_hybrid_identity_mappings import analyze_supplied_hybrid_identity_mappings
from .offline_secondary_cloud_control_declarations import (
    analyze_supplied_secondary_cloud_controls,
)
from .offline_cloud_org_support_billing_boundary import (
    analyze_supplied_cloud_org_support_billing,
)
from .offline_enterprise_saas_admin_delegation import analyze_supplied_enterprise_saas_admin
from .offline_cloud_post_compromise_timeline import analyze_supplied_cloud_post_compromise
from .offline_ot_controller_configuration import analyze_supplied_ot_controller_configuration
from .offline_seccomp_bpf_subset import analyze_supplied_seccomp_bpf_subset
from .offline_fhir_device_association_review import analyze_supplied_fhir_device_association
from .offline_ot_hmi_tag_mapping import analyze_supplied_ot_hmi_tag_mapping
from .offline_ot_engineering_project_provenance import (
    analyze_supplied_ot_engineering_project_provenance,
)
from .offline_agent_tool_authority import analyze_supplied_agent_tool_authority
from .offline_amqp091_content_analysis import analyze_supplied_amqp091_content
from .offline_android_component_analysis import analyze_supplied_android_components
from .offline_android_dex_analysis import analyze_supplied_android_dex
from .offline_api_downstream_trust import analyze_supplied_api_downstream_trust
from .offline_api_function_authorization import analyze_supplied_api_function_authorization
from .offline_api_gateway_routes import analyze_supplied_api_gateway_routes
from .offline_api_inventory_drift import analyze_supplied_api_inventory_drift
from .offline_api_object_authorization import analyze_supplied_api_object_authorization
from .offline_authorization_model_projection import analyze_supplied_authorization_model
from .offline_api_rate_limit import analyze_supplied_api_rate_limit
from .offline_attack_graph_model import analyze_supplied_attack_graph
from .offline_auction_bid_timeline import analyze_supplied_auction_bids
from .offline_backup_chain_projection import analyze_supplied_backup_chain
from .offline_cross_channel_balance import analyze_supplied_cross_channel_balance
from .offline_cross_channel_session import analyze_supplied_cross_channel_session
from .offline_aws_identity_policy_analysis import analyze_aws_identity_policy_set
from .offline_aws_policy_scp_join import analyze_supplied_aws_policy_scp_pair
from .offline_azure_nsg_analysis import analyze_supplied_azure_nsg
from .offline_bgp_update_analysis import analyze_supplied_bgp_update
from .offline_browser_message_boundary import analyze_supplied_browser_message_boundary
from .offline_cache_key_differential import analyze_supplied_cache_key_differential
from .offline_cd_release_provenance import analyze_supplied_cd_release_provenance
from .offline_ci_workflow_trust import analyze_supplied_ci_workflow_trust
from .offline_cloud_inventory_drift import analyze_supplied_cloud_inventory_drift
from .offline_configuration_defaults import analyze_supplied_configuration_defaults
from .offline_confused_deputy_boundary import analyze_supplied_confused_deputy_boundary
from .offline_cms_permission_graph import analyze_supplied_cms_permission_graph
from .offline_coap_analysis import analyze_supplied_coap
from .offline_consent_purpose_timeline import analyze_supplied_consent_purposes
from .offline_content_type_differential import analyze_supplied_content_type_differential
from .offline_cookie_selection import analyze_supplied_cookie_selection
from .offline_cors_analysis import analyze_supplied_cors
from .offline_coupon_redemption_timeline import analyze_supplied_coupon_redemptions
from .offline_credential_exposure_review import analyze_supplied_credential_exposure
from .offline_cross_surface_authorization import analyze_supplied_cross_surface_authorization
from .offline_csp_fetch_analysis import analyze_supplied_csp_fetch
from .offline_debit_idempotency_timeline import analyze_supplied_debit_timeline
from .offline_deception_evidence import analyze_supplied_deception_cues
from .offline_dependency_resolution import analyze_supplied_dependency_resolution
from .offline_dependency_fail_closed import analyze_supplied_dependency_fail_closed
from .offline_directory_entitlement_path import analyze_supplied_directory_paths
from .offline_directory_trust_paths import analyze_supplied_directory_trusts
from .offline_dhcpv4_analysis import analyze_supplied_dhcpv4
from .offline_dns_scope_timeline import analyze_supplied_dns_scope_timeline
from .offline_dicom_pdv_analysis import analyze_supplied_dicom_pdv
from .offline_dkim_canonicalization import analyze_supplied_dkim_canonicalization
from .offline_dns_message_analysis import analyze_supplied_dns_message
from .offline_dns_zone_analysis import analyze_supplied_dns_zone
from .offline_dom_dataflow import analyze_supplied_dom_dataflow
from .offline_dotnet_middleware_boundary import analyze_supplied_dotnet_middleware_boundary
from .offline_electron_bridge_origin import analyze_supplied_electron_bridge_origin
from .offline_elf64_layout_analysis import analyze_supplied_elf64_layout
from .offline_entra_role_claim_review import analyze_supplied_entra_role_claims
from .offline_etl_watermark_projection import analyze_supplied_etl_watermarks
from .offline_entitlement_toxic_combination import analyze_supplied_entitlement_toxic_combination
from .offline_fraud_decision_review import analyze_supplied_fraud_decisions
from .offline_gcp_firewall_analysis import analyze_supplied_gcp_firewall
from .offline_git_pack_analysis import analyze_supplied_git_pack
from .offline_graphql_analysis import GraphQLAnalysisLimits, analyze_graphql_operation
from .offline_http_byte_range_analysis import analyze_supplied_http_byte_ranges
from .offline_http_cache_freshness import analyze_supplied_http_cache_freshness
from .offline_http_etag_preconditions import analyze_supplied_http_etag_preconditions
from .offline_http_request_framing import analyze_supplied_http_request_framing
from .offline_ios_entitlement_analysis import analyze_supplied_ios_entitlements
from .offline_build_reproducibility import analyze_supplied_build_reproducibility
from .offline_backup_recovery_posture import analyze_supplied_backup_recovery_posture
from .offline_hypervisor_management_posture import analyze_supplied_hypervisor_management_posture
from .offline_enterprise_server_management import analyze_supplied_enterprise_server_management
from .offline_rmm_control_posture import analyze_supplied_rmm_control_posture
from .offline_hpc_queue_posture import analyze_supplied_hpc_queue_posture
from .offline_key_lifecycle_posture import analyze_supplied_key_lifecycle
from .offline_coverage_seed_selection import analyze_supplied_coverage_seeds
from .offline_grammar_plan import analyze_supplied_finite_grammar
from .offline_path_constraint_feasibility import analyze_supplied_path_constraints
from .offline_binary_reference_graph import analyze_supplied_binary_references
from .offline_source_variant_tokens import analyze_supplied_source_variant_tokens
from .offline_happens_before_conflicts import analyze_supplied_happens_before
from .offline_integer_width_arithmetic import analyze_supplied_integer_width
from .offline_heap_trace_consistency import analyze_supplied_heap_trace
from .offline_chain_trial_accounting import analyze_supplied_chain_trials
from .offline_threat_scenario_graph import analyze_supplied_threat_scenario
from .offline_rng_sample_consistency import analyze_supplied_rng_samples
from .offline_crypto_protocol_state_graph import analyze_supplied_crypto_protocol
from .offline_e2ee_epoch_membership import analyze_supplied_e2ee_epochs
from .offline_hybrid_kem_lineage import analyze_supplied_hybrid_kem_lineage
from .offline_side_channel_timing_projection import analyze_supplied_side_channel_timings
from .offline_custom_protocol_framing import analyze_supplied_custom_protocol_framing
from .offline_protocol_trace_differential import analyze_supplied_protocol_trace_differential
from .offline_digest_vector_consistency import analyze_supplied_digest_vectors
from .offline_mobile_pinset_projection import analyze_supplied_mobile_pinsets
from .offline_mobile_storage_controls import analyze_supplied_mobile_storage
from .offline_mobile_distribution import analyze_supplied_mobile_distribution
from .offline_desktop_ipc_boundary import analyze_supplied_desktop_ipc
from .offline_mobile_protection_coverage import analyze_supplied_mobile_protection
from .offline_macos_release_metadata import analyze_supplied_macos_releases
from .offline_adc_route_projection import analyze_supplied_adc_routes
from .offline_sip_dialog_sequence import analyze_supplied_sip_dialog
from .offline_traffic_cadence_projection import analyze_supplied_traffic_cadence
from .offline_ble_gatt_permissions import analyze_supplied_ble_gatt
from .offline_i2c_write_frame import analyze_supplied_i2c_write
from .offline_flash_region_map import analyze_supplied_flash_regions
from .offline_smartcard_file_access import analyze_supplied_smartcard_files
from .offline_scan_scope_projection import analyze_supplied_scan_scopes
from .offline_sudo_grant_policy import analyze_supplied_sudo_grants
from .offline_namespace_cgroup_policy import analyze_supplied_namespace_cgroups
from .offline_scheduled_artifact_policy import analyze_supplied_schedules
from .offline_mailbox_forwarding_policy import analyze_supplied_mailbox_forwarding
from .offline_collaboration_sharing_policy import analyze_supplied_collaboration_sharing
from .offline_endpoint_assignment_policy import analyze_supplied_endpoint_assignments
from .offline_windows_privilege_artifacts import analyze_supplied_privilege_artifacts
from .offline_windows_autostart_policy import analyze_supplied_autostarts
from .offline_windows_admin_invocations import analyze_supplied_admin_invocations
from .offline_windows_material_access import analyze_supplied_material_access
from .offline_windows_remote_routes import analyze_supplied_remote_routes
from .offline_windows_control_state import analyze_supplied_control_states
from .offline_ebpf_helper_policy import analyze_supplied_ebpf_helpers
from .offline_linux_shell_policy import analyze_supplied_shell_tools
from .offline_linux_logging_routes import analyze_supplied_logging_routes
from .offline_macos_privilege_items import analyze_supplied_macos_privilege_items
from .offline_macos_security_controls import analyze_supplied_macos_controls
from .offline_macos_launch_policy import analyze_supplied_launch_jobs
from .offline_macos_store_access import analyze_supplied_store_access
from .offline_macos_ipc_clients import analyze_supplied_ipc_clients
from .offline_oran_policy_targets import analyze_supplied_oran_policy_targets
from .offline_legacy_platform_grant_policy import (
    analyze_supplied_ibmi_grants,
    analyze_supplied_oracle_enterprise_grants,
    analyze_supplied_sap_grants,
    analyze_supplied_unix_enterprise_grants,
    analyze_supplied_zos_grants,
)
from .offline_mobile_trace_policy import (
    analyze_supplied_android_device_trust,
    analyze_supplied_android_instrumentation,
    analyze_supplied_ios_device_trust,
    analyze_supplied_ios_instrumentation,
)
from .offline_direct_instruction_boundary import analyze_supplied_direct_instruction_boundary
from .offline_multimodal_provenance_claims import analyze_supplied_multimodal_provenance
from .offline_pe_section_permission_policy import analyze_supplied_pe_section_permissions
from .offline_elf_section_permission_policy import analyze_supplied_elf_section_permissions
from .offline_initial_access_chain_controls import analyze_supplied_initial_access_chain
from .offline_hardware_trace_difference import analyze_supplied_hardware_traces
from .offline_path_review_checkpoint import analyze_supplied_path_review
from .offline_thread_mac_frame_control import analyze_supplied_thread_frame_control
from .offline_privilege_transition_controls import analyze_supplied_privilege_transitions
from .offline_windows_driver_pe_markers import analyze_supplied_windows_driver_pe_markers
from .offline_linux_module_info import analyze_supplied_linux_module_info
from .offline_yosys_netlist_delta import analyze_supplied_yosys_netlist_delta
from .offline_apple_kernel_macho_markers import (
    analyze_supplied_apple_kernel_macho_markers,
)
from .offline_hexagon_elf32_layout import analyze_supplied_hexagon_elf32_layout
from .offline_cache_set_projection import analyze_supplied_cache_set_projection
from .offline_socketcan_classical_frames import (
    analyze_supplied_socketcan_classical_frames,
)
from .offline_mavlink2_packet_envelope import (
    analyze_supplied_mavlink2_packet_envelope,
)
from .offline_ccsds_space_packet import analyze_supplied_ccsds_space_packet
from .offline_rinex_observation_header import (
    analyze_supplied_rinex_observation_header,
)
from .offline_ais_position_report import analyze_supplied_ais_position_report
from .offline_ocpp16_data_transfer import analyze_supplied_ocpp16_data_transfer
from .offline_browser_minidump_directory import (
    analyze_supplied_browser_minidump_directory,
)
from .offline_sis_bpcs_resource_projection import (
    analyze_supplied_sis_bpcs_resource_projection,
)
from .offline_pe_packing_triage import analyze_supplied_pe_packing_triage
from .offline_oauth_consent_uri_review import analyze_supplied_oauth_consent_uri
from .offline_ooxml_relationship_review import analyze_supplied_ooxml_relationships
from .offline_sms_uri_review import analyze_supplied_sms_uri
from .offline_email_auth_results_review import analyze_supplied_email_auth_results
from .offline_activitystreams_create_review import analyze_supplied_activitystreams_create
from .offline_power_recovery_cadence_review import analyze_supplied_power_recovery_cadence
from .offline_operator_offboarding_review import analyze_supplied_operator_offboarding
from .offline_passport_claim_review import analyze_supplied_passport_claim
from .offline_ot_vendor_support_map import analyze_supplied_ot_vendor_support_map
from .offline_mfa_registration_audit_review import analyze_supplied_mfa_registration_audit
from .offline_visitor_escort_record_review import analyze_supplied_visitor_escort_records
from .offline_osdp_poll_frame_review import analyze_supplied_osdp_poll_frame
from .offline_windows_device_event_review import analyze_supplied_windows_device_event
from .offline_esim_profile_transitions import analyze_supplied_esim_profile_transitions
from .offline_rf_capture_declarations import analyze_supplied_rf_receive_policy
from .offline_telecom_relation_policies import (
    analyze_supplied_appliance_management,
    analyze_supplied_mobile_core_relations,
    analyze_supplied_signaling_routes,
)
from .offline_unix_ipc_permissions import analyze_supplied_unix_ipc
from .offline_public_key_policy import analyze_supplied_public_key_policy
from .offline_token_payload_views import analyze_supplied_token_payload_views
from .offline_vdi_session_posture import analyze_supplied_vdi_session_posture
from .offline_storage_access_posture import analyze_supplied_storage_access_posture
from .offline_managed_package_feed import analyze_supplied_managed_package_feed
from .offline_native_target_compatibility import analyze_supplied_native_target_compatibility
from .offline_iac_change_graph import analyze_supplied_iac_change_graph
from .offline_devcontainer_boundary import analyze_supplied_devcontainer_boundary
from .offline_vendor_update_lineage import analyze_supplied_vendor_update_lineage
from .offline_repository_secret_metadata import analyze_supplied_repository_secret_metadata
from .offline_integrity_poisoning import analyze_supplied_integrity_poisoning
from .offline_interpreter_input_boundary import analyze_supplied_interpreter_input_boundary
from .offline_ipv4_fragment_analysis import analyze_supplied_ipv4_fragments
from .offline_java_filter_boundary import analyze_supplied_java_filter_boundary
from .offline_json_key_policy_differential import analyze_supplied_json_key_policies
from .offline_jose_analysis import analyze_supplied_jose
from .offline_jit_privilege_windows import analyze_supplied_jit_privilege_windows
from .offline_service_secret_lifecycle import analyze_supplied_service_secret_lifecycle
from .offline_spiffe_id_trust_projection import analyze_supplied_spiffe_id_trust
from .offline_guest_trust_projection import analyze_supplied_guest_trust
from .offline_certificate_auth_metadata import analyze_supplied_certificate_auth_metadata
from .offline_kerberos_realm_path import analyze_supplied_kerberos_realm_path
from .offline_password_lockout_timeline import analyze_supplied_password_lockout
from .offline_mfa_factor_rebind import analyze_supplied_mfa_factor_rebind
from .offline_biometric_assurance_projection import analyze_supplied_biometric_assurance
from .offline_passive_source_freshness import analyze_supplied_passive_sources
from .offline_organization_relationship_provenance import (
    analyze_supplied_organization_relationships,
)
from .offline_kdf_policy_comparison import analyze_supplied_kdf_policy
from .offline_symmetric_nonce_reuse import analyze_supplied_symmetric_nonce_reuse
from .offline_switch_vlan_projection import analyze_supplied_switch_vlan
from .offline_firewall_rule_order_projection import analyze_supplied_firewall_rule_order
from .offline_nac_admission_projection import analyze_supplied_nac_admission
from .offline_wifi_policy_projection import analyze_supplied_wifi_policy
from .offline_snmp_view_projection import analyze_supplied_snmp_view
from .offline_sdwan_overlay_projection import analyze_supplied_sdwan_overlay
from .offline_kubernetes_admission_boundary import analyze_supplied_kubernetes_admission_boundary
from .offline_kubernetes_service_analysis import analyze_supplied_kubernetes_service_endpoints
from .offline_macho_analysis import analyze_supplied_macho_layout
from .offline_modbus_tcp_analysis import analyze_supplied_modbus_tcp
from .offline_mqtt_topic_analysis import analyze_supplied_mqtt_topics
from .offline_multi_agent_coordination import analyze_supplied_multi_agent_coordination
from .offline_multicloud_federation import analyze_supplied_multicloud_federation
from .offline_nosql_access_grants import analyze_supplied_nosql_access_grants
from .offline_observable_discrepancy import analyze_supplied_observable_discrepancy
from .offline_oauth_pkce_transcript import analyze_supplied_oauth_pkce_transcript
from .offline_oci_blob_integrity import analyze_supplied_oci_blob_graph
from .offline_openapi_security_evolution import analyze_openapi_security_evolution
from .offline_partner_connector_trust import analyze_supplied_partner_connector_trust
from .offline_pickle_opcode_inventory import analyze_supplied_pickle_opcodes
from .offline_payment_reversal_ledger import analyze_supplied_payment_reversals
from .offline_pe32_layout_analysis import analyze_supplied_pe32plus_layout
from .offline_posix_acl_analysis import analyze_supplied_posix_acl
from .offline_postgresql_rls_analysis import analyze_supplied_postgresql_rls
from .offline_prefix_origin_mapping import analyze_supplied_prefix_origins
from .offline_query_input_boundary import analyze_supplied_query_input_boundary
from .offline_price_rounding_analysis import analyze_supplied_price_rounding
from .offline_property_authorization import analyze_supplied_property_authorization
from .offline_protobuf_analysis import (
    ProtobufAnalysisLimits,
    analyze_protobuf_schema_evolution,
)
from .offline_protobuf_wire_analysis import analyze_supplied_protobuf_wire
from .offline_redis_acl_analysis import analyze_supplied_redis_acl
from .offline_relational_grant_path import analyze_supplied_relational_grants
from .offline_graph_tenant_routes import analyze_supplied_graph_tenant_routes
from .offline_repository_reference_graph import analyze_supplied_repository_references
from .offline_request_origin_trust import analyze_supplied_request_origin_trust
from .offline_resource_expansion_budget import analyze_supplied_resource_expansion_budget
from .offline_saas_signal_correlation import analyze_supplied_saas_signals
from .offline_scalping_window_review import analyze_supplied_scalping_windows
from .offline_search_alias_projection import analyze_supplied_search_alias
from .offline_saml_conditions_analysis import analyze_supplied_saml_conditions
from .offline_scim_lifecycle import analyze_supplied_scim_lifecycle
from .offline_semver_interval_analysis import analyze_supplied_semver_intervals
from .offline_service_mesh_trust import analyze_supplied_service_mesh_trust
from .offline_service_worker_scope import analyze_supplied_service_worker_scope
from .offline_session_binding_timeline import analyze_supplied_session_binding_timeline
from .offline_soap_analysis import SoapAnalysisLimits, analyze_soap_contract_instance
from .offline_ssh_kexinit_analysis import analyze_supplied_ssh_kexinit_pair
from .offline_stream_offset_projection import analyze_supplied_stream_offsets
from .offline_spark_job_plan import analyze_supplied_spark_job_plan
from .offline_warehouse_lineage import analyze_supplied_warehouse_lineage
from .offline_template_context import analyze_supplied_template_context
from .offline_tenant_ownership_reconciliation import analyze_supplied_tenant_ownership
from .offline_technology_evidence import analyze_supplied_technology_evidence
from .offline_tls_hello_analysis import analyze_supplied_tls_hello_pair
from .offline_toctou_state_schedule import analyze_supplied_toctou_state_schedule
from .offline_url_navigation import analyze_supplied_url_navigation
from .offline_vector_tenant_boundary import analyze_supplied_vector_tenant_boundary
from .offline_wasm_numeric_stack_analysis import analyze_supplied_wasm_numeric_stack
from .offline_web_content_handling import analyze_supplied_web_content_handling
from .offline_web_framework_stack import analyze_supplied_web_framework_stack
from .offline_web_route_authorization import analyze_supplied_web_route_authorization
from .offline_webauthn_assertion_analysis import analyze_supplied_webauthn_assertion
from .offline_webhook_callback_trust import analyze_supplied_webhook_callback_trust
from .offline_webrtc_signaling import analyze_supplied_webrtc_signaling
from .offline_websocket_frame_analysis import analyze_supplied_websocket_frames
from .offline_webview_bridge_origin import analyze_supplied_webview_bridge_origin
from .offline_wheel_record_analysis import analyze_supplied_wheel_record
from .offline_windows_dacl_analysis import analyze_supplied_windows_dacl
from .offline_workflow_state_replay import analyze_supplied_workflow_states
from .offline_workload_identity_trust import analyze_supplied_workload_identity_trust
from .offline_x509_chain_analysis import analyze_supplied_x509_chain
from .offline_x509_san_analysis import analyze_supplied_x509_san
from .qualification import QualificationStandard, _canonical_json, _canonical_sha256
from .qualification_plans_v2 import QualificationPlanCatalogV2
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .validation import loads_json_without_duplicate_keys

CATALOG_DOMAIN = "sunderkey.offline-specialist-components.v1"
RESULT_DOMAIN = "sunderkey.offline-specialist-component-result.v1"
CATALOG_PATH = "registry/offline-specialist-components-v1.json"
STRATEGY_PATH = "registry/candidate-implementation-strategy-v1.json"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_CATALOG_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 8 * 1024 * 1024
FOUNDATION_PATHS = (
    "registry/army-v2.json",
    "registry/capabilities-army-v2.json",
    "registry/army-expansion-roadmap-v1.json",
    "registry/attack-vectors-v2.json",
    "registry/qualification-standard-v2.json",
    "registry/qualification-plans-army-v2.json",
    "registry/candidate-blueprints-army-v2.json",
    "registry/implementation-work-packages-v2.json",
    "registry/specialist-implementation-roadmap-v2.json",
)
COMPONENTS = (
    (
        "AOE-GE-D21-S08", "army.ge.d21.s08", "IW2-020",
        "exploit_supplied_seccomp_bpf_subset_projection",
        "src/sunderkey/offline_seccomp_bpf_subset.py",
        "tests/agents/test_offline_seccomp_bpf_subset.py",
        "docs/offline-seccomp-bpf-subset.md",
    ),
    (
        "AOE-GD-D25-S11", "army.gd.d25.s11", "IW2-011",
        "clinical_supplied_fhir_device_association_review",
        "src/sunderkey/offline_fhir_device_association_review.py",
        "tests/agents/test_offline_fhir_device_association_review.py",
        "docs/offline-fhir-device-association-review.md",
    ),
    (
        "AOE-GA-D02-S02", "army.ga.d02.s02", "IW2-003",
        "social_supplied_passport_claim_review",
        "src/sunderkey/offline_passport_claim_review.py",
        "tests/agents/test_offline_passport_claim_review.py",
        "docs/offline-passport-claim-review.md",
    ),
    (
        "AOE-GD-D19-S07", "army.gd.d19.s07", "IW2-017",
        "industrial_supplied_ot_vendor_support_map",
        "src/sunderkey/offline_ot_vendor_support_map.py",
        "tests/agents/test_offline_ot_vendor_support_map.py",
        "docs/offline-ot-vendor-support-map.md",
    ),
    (
        "AOE-GA-D02-S04", "army.ga.d02.s04", "IW2-005",
        "social_supplied_activitystreams_create_review",
        "src/sunderkey/offline_activitystreams_create_review.py",
        "tests/agents/test_offline_activitystreams_create_review.py",
        "docs/offline-activitystreams-create-review.md",
    ),
    (
        "AOE-GD-D19-S09", "army.gd.d19.s09", "IW2-019",
        "industrial_supplied_power_recovery_cadence_review",
        "src/sunderkey/offline_power_recovery_cadence_review.py",
        "tests/agents/test_offline_power_recovery_cadence_review.py",
        "docs/offline-power-recovery-cadence-review.md",
    ),
    (
        "AOE-GA-D02-S13", "army.ga.d02.s13", "IW2-001",
        "social_supplied_operator_offboarding_review",
        "src/sunderkey/offline_operator_offboarding_review.py",
        "tests/agents/test_offline_operator_offboarding_review.py",
        "docs/offline-operator-offboarding-review.md",
    ),
    (
        "AOE-GA-D02-S05", "army.ga.d02.s05", "IW2-006",
        "social_supplied_mfa_registration_audit_review",
        "src/sunderkey/offline_mfa_registration_audit_review.py",
        "tests/agents/test_offline_mfa_registration_audit_review.py",
        "docs/offline-mfa-registration-audit-review.md",
    ),
    (
        "AOE-GA-D02-S09", "army.ga.d02.s09", "IW2-010",
        "social_supplied_visitor_escort_record_review",
        "src/sunderkey/offline_visitor_escort_record_review.py",
        "tests/agents/test_offline_visitor_escort_record_review.py",
        "docs/offline-visitor-escort-record-review.md",
    ),
    (
        "AOE-GA-D02-S10", "army.ga.d02.s10", "IW2-011",
        "social_supplied_osdp_poll_frame_review",
        "src/sunderkey/offline_osdp_poll_frame_review.py",
        "tests/agents/test_offline_osdp_poll_frame_review.py",
        "docs/offline-osdp-poll-frame-review.md",
    ),
    (
        "AOE-GA-D02-S11", "army.ga.d02.s11", "IW2-012",
        "social_supplied_windows_device_event_review",
        "src/sunderkey/offline_windows_device_event_review.py",
        "tests/agents/test_offline_windows_device_event_review.py",
        "docs/offline-windows-device-event-review.md",
    ),
    (
        "AOE-GA-D02-S01", "army.ga.d02.s01", "IW2-002",
        "social_supplied_email_auth_results_review",
        "src/sunderkey/offline_email_auth_results_review.py",
        "tests/agents/test_offline_email_auth_results_review.py",
        "docs/offline-email-auth-results-review.md",
    ),
    (
        "AOE-GA-D02-S03", "army.ga.d02.s03", "IW2-004",
        "social_supplied_sms_uri_review",
        "src/sunderkey/offline_sms_uri_review.py",
        "tests/agents/test_offline_sms_uri_review.py",
        "docs/offline-sms-uri-review.md",
    ),
    (
        "AOE-GA-D02-S06", "army.ga.d02.s06", "IW2-007",
        "social_supplied_oauth_consent_uri_review",
        "src/sunderkey/offline_oauth_consent_uri_review.py",
        "tests/agents/test_offline_oauth_consent_uri_review.py",
        "docs/offline-oauth-consent-uri-review.md",
    ),
    (
        "AOE-GA-D02-S08", "army.ga.d02.s08", "IW2-009",
        "social_supplied_ooxml_relationship_review",
        "src/sunderkey/offline_ooxml_relationship_review.py",
        "tests/agents/test_offline_ooxml_relationship_review.py",
        "docs/offline-ooxml-relationship-review.md",
    ),
    (
        "AOE-GE-D21-S20", "army.ge.d21.s20", "IW2-002",
        "exploit_supplied_pe_packing_triage",
        "src/sunderkey/offline_pe_packing_triage.py",
        "tests/agents/test_offline_pe_packing_triage.py",
        "docs/offline-pe-packing-triage.md",
    ),
    (
        "AOE-GD-D19-S05", "army.gd.d19.s05", "IW2-015",
        "industrial_supplied_sis_bpcs_resource_projection",
        "src/sunderkey/offline_sis_bpcs_resource_projection.py",
        "tests/agents/test_offline_sis_bpcs_resource_projection.py",
        "docs/offline-sis-bpcs-resource-projection.md",
    ),
    (
        "AOE-GE-D21-S07", "army.ge.d21.s07", "IW2-019",
        "exploit_supplied_browser_minidump_directory",
        "src/sunderkey/offline_browser_minidump_directory.py",
        "tests/agents/test_offline_browser_minidump_directory.py",
        "docs/offline-browser-minidump-directory.md",
    ),
    (
        "AOE-GD-D25-S04", "army.gd.d25.s04", "IW2-004",
        "transport_supplied_ocpp16_data_transfer_projection",
        "src/sunderkey/offline_ocpp16_data_transfer.py",
        "tests/agents/test_offline_ocpp16_data_transfer.py",
        "docs/offline-ocpp16-data-transfer.md",
    ),
    (
        "AOE-GD-D25-S07", "army.gd.d25.s07", "IW2-007",
        "transport_supplied_ais_position_report_projection",
        "src/sunderkey/offline_ais_position_report.py",
        "tests/agents/test_offline_ais_position_report.py",
        "docs/offline-ais-position-report.md",
    ),
    (
        "AOE-GD-D25-S08", "army.gd.d25.s08", "IW2-008",
        "transport_supplied_ccsds_space_packet_projection",
        "src/sunderkey/offline_ccsds_space_packet.py",
        "tests/agents/test_offline_ccsds_space_packet.py",
        "docs/offline-ccsds-space-packet.md",
    ),
    (
        "AOE-GD-D25-S09", "army.gd.d25.s09", "IW2-009",
        "transport_supplied_rinex_observation_header_projection",
        "src/sunderkey/offline_rinex_observation_header.py",
        "tests/agents/test_offline_rinex_observation_header.py",
        "docs/offline-rinex-observation-header.md",
    ),
    (
        "AOE-GD-D25-S10", "army.gd.d25.s10", "IW2-010",
        "transport_supplied_mavlink2_packet_envelope",
        "src/sunderkey/offline_mavlink2_packet_envelope.py",
        "tests/agents/test_offline_mavlink2_packet_envelope.py",
        "docs/offline-mavlink2-packet-envelope.md",
    ),
    (
        "AOE-GD-D19-S12", "army.gd.d19.s12", "IW2-022",
        "industrial_supplied_socketcan_classical_frame_projection",
        "src/sunderkey/offline_socketcan_classical_frames.py",
        "tests/agents/test_offline_socketcan_classical_frames.py",
        "docs/offline-socketcan-classical-frames.md",
    ),
    (
        "AOE-GD-D18-S11", "army.gd.d18.s11", "IW2-015",
        "hardware_supplied_cache_set_mapping_projection",
        "src/sunderkey/offline_cache_set_projection.py",
        "tests/agents/test_offline_cache_set_projection.py",
        "docs/offline-cache-set-projection.md",
    ),
    (
        "AOE-GE-D21-S06", "army.ge.d21.s06", "IW2-018",
        "exploit_engineering_supplied_hexagon_elf32_layout",
        "src/sunderkey/offline_hexagon_elf32_layout.py",
        "tests/agents/test_offline_hexagon_elf32_layout.py",
        "docs/offline-hexagon-elf32-layout.md",
    ),
    (
        "AOE-GE-D21-S05", "army.ge.d21.s05", "IW2-017",
        "exploit_engineering_supplied_apple_kernel_macho_markers",
        "src/sunderkey/offline_apple_kernel_macho_markers.py",
        "tests/agents/test_offline_apple_kernel_macho_markers.py",
        "docs/offline-apple-kernel-macho-markers.md",
    ),
    (
        "AOE-GD-D18-S12", "army.gd.d18.s12", "IW2-016",
        "hardware_supplied_yosys_netlist_structural_delta",
        "src/sunderkey/offline_yosys_netlist_delta.py",
        "tests/agents/test_offline_yosys_netlist_delta.py",
        "docs/offline-yosys-netlist-delta.md",
    ),
    (
        "AOE-GE-D21-S04", "army.ge.d21.s04", "IW2-016",
        "exploit_engineering_supplied_linux_module_info_projection",
        "src/sunderkey/offline_linux_module_info.py",
        "tests/agents/test_offline_linux_module_info.py",
        "docs/offline-linux-module-info.md",
    ),
    (
        "AOE-GE-D21-S03", "army.ge.d21.s03", "IW2-015",
        "exploit_engineering_supplied_windows_driver_pe_marker_projection",
        "src/sunderkey/offline_windows_driver_pe_markers.py",
        "tests/agents/test_offline_windows_driver_pe_markers.py",
        "docs/offline-windows-driver-pe-markers.md",
    ),
    (
        "AOE-GA-D04-S07", "army.ga.d04.s07", "IW2-008",
        "campaign_supplied_privilege_transition_controls",
        "src/sunderkey/offline_privilege_transition_controls.py",
        "tests/agents/test_offline_privilege_transition_controls.py",
        "docs/offline-privilege-transition-controls.md",
    ),
    (
        "AOE-GD-D18-S14", "army.gd.d18.s14", "IW2-018",
        "hardware_supplied_thread_mac_frame_control_projection",
        "src/sunderkey/offline_thread_mac_frame_control.py",
        "tests/agents/test_offline_thread_mac_frame_control.py",
        "docs/offline-thread-mac-frame-control.md",
    ),
    (
        "AOE-GA-D04-S09", "army.ga.d04.s09", "IW2-010",
        "campaign_supplied_path_review_checkpoint_projection",
        "src/sunderkey/offline_path_review_checkpoint.py",
        "tests/agents/test_offline_path_review_checkpoint.py",
        "docs/offline-path-review-checkpoint.md",
    ),
    (
        "AOE-GD-D18-S08", "army.gd.d18.s08", "IW2-012",
        "hardware_supplied_trace_difference_projection",
        "src/sunderkey/offline_hardware_trace_difference.py",
        "tests/agents/test_offline_hardware_trace_difference.py",
        "docs/offline-hardware-trace-difference.md",
    ),
    (
        "AOE-GA-D04-S02", "army.ga.d04.s02", "IW2-003",
        "campaign_supplied_initial_access_chain_controls",
        "src/sunderkey/offline_initial_access_chain_controls.py",
        "tests/agents/test_offline_initial_access_chain_controls.py",
        "docs/offline-initial-access-chain-controls.md",
    ),
    (
        "AOE-GE-D21-S02", "army.ge.d21.s02", "IW2-014",
        "exploit_engineering_supplied_aarch64_elf_section_permission_projection",
        "src/sunderkey/offline_elf_section_permission_policy.py",
        "tests/agents/test_offline_elf_section_permission_policy.py",
        "docs/offline-elf-section-permissions.md",
    ),
    (
        "AOE-GE-D21-S01", "army.ge.d21.s01", "IW2-013",
        "exploit_engineering_supplied_pe_section_permission_projection",
        "src/sunderkey/offline_pe_section_permission_policy.py",
        "tests/agents/test_offline_pe_section_permission_policy.py",
        "docs/offline-pe-section-permissions.md",
    ),
    (
        "AOE-GB-D08-S02", "army.gb.d08.s02", "IW2-006",
        "mobile_supplied_android_instrumentation_trace_projection",
        "src/sunderkey/offline_mobile_trace_policy.py",
        "tests/agents/test_offline_mobile_trace_policy.py",
        "docs/offline-android-instrumentation-trace.md",
    ),
    (
        "AOE-GB-D08-S04", "army.gb.d08.s04", "IW2-008",
        "mobile_supplied_android_device_trust_trace_projection",
        "src/sunderkey/offline_mobile_trace_policy.py",
        "tests/agents/test_offline_mobile_trace_policy.py",
        "docs/offline-android-device-trust-trace.md",
    ),
    (
        "AOE-GB-D08-S06", "army.gb.d08.s06", "IW2-010",
        "mobile_supplied_ios_instrumentation_trace_projection",
        "src/sunderkey/offline_mobile_trace_policy.py",
        "tests/agents/test_offline_mobile_trace_policy.py",
        "docs/offline-ios-instrumentation-trace.md",
    ),
    (
        "AOE-GB-D08-S08", "army.gb.d08.s08", "IW2-012",
        "mobile_supplied_ios_device_trust_trace_projection",
        "src/sunderkey/offline_mobile_trace_policy.py",
        "tests/agents/test_offline_mobile_trace_policy.py",
        "docs/offline-ios-device-trust-trace.md",
    ),
    (
        "AOE-GD-D20-S09", "army.gd.d20.s09", "IW2-013",
        "model_supplied_direct_instruction_boundary_projection",
        "src/sunderkey/offline_direct_instruction_boundary.py",
        "tests/agents/test_offline_direct_instruction_boundary.py",
        "docs/offline-direct-instruction-boundary.md",
    ),
    (
        "AOE-GD-D20-S17", "army.gd.d20.s17", "IW2-019",
        "model_supplied_multimodal_provenance_claim_projection",
        "src/sunderkey/offline_multimodal_provenance_claims.py",
        "tests/agents/test_offline_multimodal_provenance_claims.py",
        "docs/offline-multimodal-provenance.md",
    ),
    (
        "AOE-GC-D16-S01", "army.gc.d16.s01", "IW2-013",
        "legacy_supplied_zos_grant_policy_projection",
        "src/sunderkey/offline_legacy_platform_grant_policy.py",
        "tests/agents/test_offline_legacy_platform_grant_policy.py",
        "docs/offline-zos-grants.md",
    ),
    (
        "AOE-GC-D16-S02", "army.gc.d16.s02", "IW2-014",
        "legacy_supplied_ibmi_grant_policy_projection",
        "src/sunderkey/offline_legacy_platform_grant_policy.py",
        "tests/agents/test_offline_legacy_platform_grant_policy.py",
        "docs/offline-ibmi-grants.md",
    ),
    (
        "AOE-GC-D16-S03", "army.gc.d16.s03", "IW2-015",
        "legacy_supplied_unix_grant_policy_projection",
        "src/sunderkey/offline_legacy_platform_grant_policy.py",
        "tests/agents/test_offline_legacy_platform_grant_policy.py",
        "docs/offline-unix-enterprise-grants.md",
    ),
    (
        "AOE-GC-D16-S04", "army.gc.d16.s04", "IW2-016",
        "legacy_supplied_sap_grant_policy_projection",
        "src/sunderkey/offline_legacy_platform_grant_policy.py",
        "tests/agents/test_offline_legacy_platform_grant_policy.py",
        "docs/offline-sap-grants.md",
    ),
    (
        "AOE-GC-D16-S05", "army.gc.d16.s05", "IW2-017",
        "legacy_supplied_oracle_grant_policy_projection",
        "src/sunderkey/offline_legacy_platform_grant_policy.py",
        "tests/agents/test_offline_legacy_platform_grant_policy.py",
        "docs/offline-oracle-enterprise-grants.md",
    ),
    (
        "AOE-GC-D13-S06", "army.gc.d13.s06", "IW2-009",
        "telecom_supplied_appliance_management_relation_projection",
        "src/sunderkey/offline_telecom_relation_policies.py",
        "tests/agents/test_offline_telecom_relation_policies.py",
        "docs/offline-telecom-appliance-relations.md",
    ),
    (
        "AOE-GC-D13-S10", "army.gc.d13.s10", "IW2-013",
        "telecom_supplied_rf_receive_policy_projection",
        "src/sunderkey/offline_rf_capture_declarations.py",
        "tests/agents/test_offline_rf_capture_declarations.py",
        "docs/offline-rf-receive-policy.md",
    ),
    (
        "AOE-GC-D13-S11", "army.gc.d13.s11", "IW2-014",
        "telecom_supplied_mobile_core_relation_projection",
        "src/sunderkey/offline_telecom_relation_policies.py",
        "tests/agents/test_offline_telecom_relation_policies.py",
        "docs/offline-mobile-core-relations.md",
    ),
    (
        "AOE-GC-D13-S12", "army.gc.d13.s12", "IW2-015",
        "telecom_supplied_signaling_route_projection",
        "src/sunderkey/offline_telecom_relation_policies.py",
        "tests/agents/test_offline_telecom_relation_policies.py",
        "docs/offline-signaling-routes.md",
    ),
    (
        "AOE-GC-D13-S19", "army.gc.d13.s19", "IW2-001",
        "telecom_supplied_oran_policy_target_projection",
        "src/sunderkey/offline_oran_policy_targets.py",
        "tests/agents/test_offline_oran_policy_targets.py",
        "docs/offline-oran-policy-targets.md",
    ),
    (
        "AOE-GC-D13-S20", "army.gc.d13.s20", "IW2-002",
        "telecom_supplied_esim_profile_transition_projection",
        "src/sunderkey/offline_esim_profile_transitions.py",
        "tests/agents/test_offline_esim_profile_transitions.py",
        "docs/offline-esim-profile-transitions.md",
    ),
    (
        "AOE-GC-D12-S02",
        "army.gc.d12.s02",
        "IW2-002",
        "linux_supplied_ebpf_helper_policy_projection",
        "src/sunderkey/offline_ebpf_helper_policy.py",
        "tests/agents/test_offline_ebpf_helper_policy.py",
        "docs/offline-ebpf-helper-policy.md",
    ),
    (
        "AOE-GC-D12-S05",
        "army.gc.d12.s05",
        "IW2-005",
        "linux_supplied_shell_tool_policy_projection",
        "src/sunderkey/offline_linux_shell_policy.py",
        "tests/agents/test_offline_linux_shell_policy.py",
        "docs/offline-linux-shell-policy.md",
    ),
    (
        "AOE-GC-D12-S08",
        "army.gc.d12.s08",
        "IW2-008",
        "linux_supplied_logging_route_policy_projection",
        "src/sunderkey/offline_linux_logging_routes.py",
        "tests/agents/test_offline_linux_logging_routes.py",
        "docs/offline-linux-logging-routes.md",
    ),
    (
        "AOE-GC-D12-S09",
        "army.gc.d12.s09",
        "IW2-009",
        "macos_supplied_privileged_item_policy_projection",
        "src/sunderkey/offline_macos_privilege_items.py",
        "tests/agents/test_offline_macos_privilege_items.py",
        "docs/offline-macos-privilege-items.md",
    ),
    (
        "AOE-GC-D12-S10",
        "army.gc.d12.s10",
        "IW2-010",
        "macos_supplied_security_control_policy_projection",
        "src/sunderkey/offline_macos_security_controls.py",
        "tests/agents/test_offline_macos_security_controls.py",
        "docs/offline-macos-security-controls.md",
    ),
    (
        "AOE-GC-D12-S11",
        "army.gc.d12.s11",
        "IW2-011",
        "macos_supplied_launch_job_policy_projection",
        "src/sunderkey/offline_macos_launch_policy.py",
        "tests/agents/test_offline_macos_launch_policy.py",
        "docs/offline-macos-launch-policy.md",
    ),
    (
        "AOE-GC-D12-S12",
        "army.gc.d12.s12",
        "IW2-012",
        "macos_supplied_store_access_policy_projection",
        "src/sunderkey/offline_macos_store_access.py",
        "tests/agents/test_offline_macos_store_access.py",
        "docs/offline-macos-store-access.md",
    ),
    (
        "AOE-GC-D12-S13",
        "army.gc.d12.s13",
        "IW2-013",
        "macos_supplied_ipc_client_policy_projection",
        "src/sunderkey/offline_macos_ipc_clients.py",
        "tests/agents/test_offline_macos_ipc_clients.py",
        "docs/offline-macos-ipc-clients.md",
    ),
    (
        "AOE-GC-D12-S14",
        "army.gc.d12.s14",
        "IW2-014",
        "unix_supplied_privileged_ipc_permission_projection",
        "src/sunderkey/offline_unix_ipc_permissions.py",
        "tests/agents/test_offline_unix_ipc_permissions.py",
        "docs/offline-unix-ipc-permissions.md",
    ),
    (
        "AOE-GC-D11-S08",
        "army.gc.d11.s08",
        "IW2-008",
        "windows_supplied_privilege_artifact_projection",
        "src/sunderkey/offline_windows_privilege_artifacts.py",
        "tests/agents/test_offline_windows_privilege_artifacts.py",
        "docs/offline-windows-privilege-artifacts.md",
    ),
    (
        "AOE-GC-D11-S09",
        "army.gc.d11.s09",
        "IW2-009",
        "windows_supplied_autostart_policy_projection",
        "src/sunderkey/offline_windows_autostart_policy.py",
        "tests/agents/test_offline_windows_autostart_policy.py",
        "docs/offline-windows-autostart-policy.md",
    ),
    (
        "AOE-GC-D11-S10",
        "army.gc.d11.s10",
        "IW2-010",
        "windows_supplied_admin_invocation_policy_projection",
        "src/sunderkey/offline_windows_admin_invocations.py",
        "tests/agents/test_offline_windows_admin_invocations.py",
        "docs/offline-windows-admin-invocations.md",
    ),
    (
        "AOE-GC-D11-S11",
        "army.gc.d11.s11",
        "IW2-011",
        "windows_supplied_protected_material_access_projection",
        "src/sunderkey/offline_windows_material_access.py",
        "tests/agents/test_offline_windows_material_access.py",
        "docs/offline-windows-material-access.md",
    ),
    (
        "AOE-GC-D11-S12",
        "army.gc.d11.s12",
        "IW2-012",
        "windows_supplied_remote_route_policy_projection",
        "src/sunderkey/offline_windows_remote_routes.py",
        "tests/agents/test_offline_windows_remote_routes.py",
        "docs/offline-windows-remote-routes.md",
    ),
    (
        "AOE-GC-D11-S13",
        "army.gc.d11.s13",
        "IW2-013",
        "windows_supplied_security_control_state_projection",
        "src/sunderkey/offline_windows_control_state.py",
        "tests/agents/test_offline_windows_control_state.py",
        "docs/offline-windows-control-state.md",
    ),
    (
        "AOE-GC-D11-S18",
        "army.gc.d11.s18",
        "IW2-018",
        "windows_supplied_endpoint_assignment_policy_projection",
        "src/sunderkey/offline_endpoint_assignment_policy.py",
        "tests/agents/test_offline_endpoint_assignment_policy.py",
        "docs/offline-endpoint-assignment-policy.md",
    ),
    (
        "AOE-GC-D11-S16",
        "army.gc.d11.s16",
        "IW2-016",
        "windows_supplied_collaboration_sharing_policy_projection",
        "src/sunderkey/offline_collaboration_sharing_policy.py",
        "tests/agents/test_offline_collaboration_sharing_policy.py",
        "docs/offline-collaboration-sharing-policy.md",
    ),
    (
        "AOE-GC-D11-S15",
        "army.gc.d11.s15",
        "IW2-015",
        "windows_supplied_mailbox_forwarding_policy_projection",
        "src/sunderkey/offline_mailbox_forwarding_policy.py",
        "tests/agents/test_offline_mailbox_forwarding_policy.py",
        "docs/offline-mailbox-forwarding-policy.md",
    ),
    (
        "AOE-GC-D12-S04",
        "army.gc.d12.s04",
        "IW2-004",
        "linux_supplied_scheduled_artifact_policy_projection",
        "src/sunderkey/offline_scheduled_artifact_policy.py",
        "tests/agents/test_offline_scheduled_artifact_policy.py",
        "docs/offline-scheduled-artifact-policy.md",
    ),
    (
        "AOE-GC-D12-S07",
        "army.gc.d12.s07",
        "IW2-007",
        "linux_supplied_namespace_cgroup_policy_projection",
        "src/sunderkey/offline_namespace_cgroup_policy.py",
        "tests/agents/test_offline_namespace_cgroup_policy.py",
        "docs/offline-namespace-cgroup-policy.md",
    ),
    (
        "AOE-GC-D12-S03",
        "army.gc.d12.s03",
        "IW2-003",
        "linux_supplied_sudo_grant_policy_projection",
        "src/sunderkey/offline_sudo_grant_policy.py",
        "tests/agents/test_offline_sudo_grant_policy.py",
        "docs/offline-sudo-grant-policy.md",
    ),
    (
        "AOE-GA-D01-S02",
        "army.ga.d01.s02",
        "IW2-002",
        "recon_supplied_scan_scope_projection",
        "src/sunderkey/offline_scan_scope_projection.py",
        "tests/agents/test_offline_scan_scope_projection.py",
        "docs/offline-scan-scope-projection.md",
    ),
    (
        "AOE-GD-D18-S13",
        "army.gd.d18.s13",
        "IW2-017",
        "hardware_supplied_smartcard_file_access_projection",
        "src/sunderkey/offline_smartcard_file_access.py",
        "tests/agents/test_offline_smartcard_file_access.py",
        "docs/offline-smartcard-file-access.md",
    ),
    (
        "AOE-GD-D18-S07",
        "army.gd.d18.s07",
        "IW2-011",
        "hardware_supplied_flash_region_map_projection",
        "src/sunderkey/offline_flash_region_map.py",
        "tests/agents/test_offline_flash_region_map.py",
        "docs/offline-flash-region-map.md",
    ),
    (
        "AOE-GD-D18-S06",
        "army.gd.d18.s06",
        "IW2-010",
        "hardware_supplied_i2c_write_frame_projection",
        "src/sunderkey/offline_i2c_write_frame.py",
        "tests/agents/test_offline_i2c_write_frame.py",
        "docs/offline-i2c-write-frame.md",
    ),
    (
        "AOE-GC-D13-S09",
        "army.gc.d13.s09",
        "IW2-012",
        "network_supplied_ble_gatt_permission_projection",
        "src/sunderkey/offline_ble_gatt_permissions.py",
        "tests/agents/test_offline_ble_gatt_permissions.py",
        "docs/offline-ble-gatt-permissions.md",
    ),
    (
        "AOE-GC-D13-S18",
        "army.gc.d13.s18",
        "IW2-021",
        "network_supplied_traffic_cadence_projection",
        "src/sunderkey/offline_traffic_cadence_projection.py",
        "tests/agents/test_offline_traffic_cadence_projection.py",
        "docs/offline-traffic-cadence-projection.md",
    ),
    (
        "AOE-GC-D13-S13",
        "army.gc.d13.s13",
        "IW2-016",
        "network_supplied_sip_dialog_sequence_projection",
        "src/sunderkey/offline_sip_dialog_sequence.py",
        "tests/agents/test_offline_sip_dialog_sequence.py",
        "docs/offline-sip-dialog-sequence.md",
    ),
    (
        "AOE-GC-D13-S16",
        "army.gc.d13.s16",
        "IW2-019",
        "network_supplied_adc_route_projection",
        "src/sunderkey/offline_adc_route_projection.py",
        "tests/agents/test_offline_adc_route_projection.py",
        "docs/offline-adc-route-projection.md",
    ),
    (
        "AOE-GB-D08-S16",
        "army.gb.d08.s16",
        "IW2-002",
        "macos_supplied_release_metadata_consistency",
        "src/sunderkey/offline_macos_release_metadata.py",
        "tests/agents/test_offline_macos_release_metadata.py",
        "docs/offline-macos-release-metadata.md",
    ),
    (
        "AOE-GB-D08-S11",
        "army.gb.d08.s11",
        "IW2-015",
        "mobile_supplied_protection_coverage_projection",
        "src/sunderkey/offline_mobile_protection_coverage.py",
        "tests/agents/test_offline_mobile_protection_coverage.py",
        "docs/offline-mobile-protection-coverage.md",
    ),
    (
        "AOE-GB-D08-S13",
        "army.gb.d08.s13",
        "IW2-017",
        "desktop_supplied_ipc_boundary_projection",
        "src/sunderkey/offline_desktop_ipc_boundary.py",
        "tests/agents/test_offline_desktop_ipc_boundary.py",
        "docs/offline-desktop-ipc-boundary.md",
    ),
    (
        "AOE-GB-D08-S10",
        "army.gb.d08.s10",
        "IW2-014",
        "mobile_supplied_storage_control_projection",
        "src/sunderkey/offline_mobile_storage_controls.py",
        "tests/agents/test_offline_mobile_storage_controls.py",
        "docs/offline-mobile-storage-controls.md",
    ),
    (
        "AOE-GB-D08-S14",
        "army.gb.d08.s14",
        "IW2-018",
        "mobile_supplied_distribution_consistency_projection",
        "src/sunderkey/offline_mobile_distribution.py",
        "tests/agents/test_offline_mobile_distribution.py",
        "docs/offline-mobile-distribution.md",
    ),
    (
        "AOE-GB-D08-S09",
        "army.gb.d08.s09",
        "IW2-013",
        "mobile_supplied_pinset_coverage_projection",
        "src/sunderkey/offline_mobile_pinset_projection.py",
        "tests/agents/test_offline_mobile_pinset_projection.py",
        "docs/offline-mobile-pinset-projection.md",
    ),
    (
        "AOE-GE-D22-S14",
        "army.ge.d22.s14",
        "IW2-027",
        "crypto_supplied_digest_vector_consistency",
        "src/sunderkey/offline_digest_vector_consistency.py",
        "tests/agents/test_offline_digest_vector_consistency.py",
        "docs/offline-digest-vector-consistency.md",
    ),
    (
        "AOE-GC-D13-S17",
        "army.gc.d13.s17",
        "IW2-020",
        "network_supplied_protocol_trace_differential",
        "src/sunderkey/offline_protocol_trace_differential.py",
        "tests/agents/test_offline_protocol_trace_differential.py",
        "docs/offline-protocol-trace-differential.md",
    ),
    (
        "AOE-GE-D22-S12",
        "army.ge.d22.s12",
        "IW2-025",
        "crypto_supplied_custom_protocol_framing",
        "src/sunderkey/offline_custom_protocol_framing.py",
        "tests/agents/test_offline_custom_protocol_framing.py",
        "docs/offline-custom-protocol-framing.md",
    ),
    (
        "AOE-GE-D22-S07",
        "army.ge.d22.s07",
        "IW2-020",
        "crypto_supplied_hybrid_kem_lineage",
        "src/sunderkey/offline_hybrid_kem_lineage.py",
        "tests/agents/test_offline_hybrid_kem_lineage.py",
        "docs/offline-hybrid-kem-lineage.md",
    ),
    (
        "AOE-GE-D22-S09",
        "army.ge.d22.s09",
        "IW2-022",
        "crypto_supplied_side_channel_timing_projection",
        "src/sunderkey/offline_side_channel_timing_projection.py",
        "tests/agents/test_offline_side_channel_timing_projection.py",
        "docs/offline-side-channel-timing-projection.md",
    ),
    (
        "AOE-GE-D22-S01",
        "army.ge.d22.s01",
        "IW2-014",
        "crypto_supplied_protocol_state_graph",
        "src/sunderkey/offline_crypto_protocol_state_graph.py",
        "tests/agents/test_offline_crypto_protocol_state_graph.py",
        "docs/offline-crypto-protocol-state-graph.md",
    ),
    (
        "AOE-GE-D22-S13",
        "army.ge.d22.s13",
        "IW2-026",
        "crypto_supplied_e2ee_epoch_membership",
        "src/sunderkey/offline_e2ee_epoch_membership.py",
        "tests/agents/test_offline_e2ee_epoch_membership.py",
        "docs/offline-e2ee-epoch-membership.md",
    ),
    (
        "AOE-GA-D04-S01",
        "campaign.threat-scenario-design",
        "IW2-002",
        "campaign_supplied_threat_scenario_graph",
        "src/sunderkey/offline_threat_scenario_graph.py",
        "tests/agents/test_offline_threat_scenario_graph.py",
        "docs/offline-threat-scenario-graph.md",
    ),
    (
        "AOE-GE-D22-S08",
        "army.ge.d22.s08",
        "IW2-021",
        "crypto_supplied_rng_sample_consistency",
        "src/sunderkey/offline_rng_sample_consistency.py",
        "tests/agents/test_offline_rng_sample_consistency.py",
        "docs/offline-rng-sample-consistency.md",
    ),
    (
        "AOE-GB-D06-S02",
        "army.gb.d06.s02",
        "IW2-009",
        "graphql_query_structure",
        "src/sunderkey/offline_graphql_analysis.py",
        "tests/agents/test_offline_graphql_analysis.py",
        "docs/offline-graphql-analysis.md",
    ),
    (
        "AOE-GC-D15-S04",
        "container.kubernetes.rbac-service-account",
        "IW2-006",
        "kubernetes_rbac_supplied_model",
        "src/sunderkey/kubernetes_rbac_analysis.py",
        "tests/agents/test_kubernetes_rbac_analysis.py",
        "docs/kubernetes-rbac-offline-analysis.md",
    ),
    (
        "AOE-GC-D14-S01",
        "army.gc.d14.s01",
        "IW2-004",
        "aws_organizations_supplied_scp_path",
        "src/sunderkey/aws_scp_analysis.py",
        "tests/agents/test_aws_scp_analysis.py",
        "docs/aws-scp-offline-analysis.md",
    ),
    (
        "AOE-GB-D06-S03",
        "army.gb.d06.s03",
        "IW2-010",
        "protobuf_schema_evolution",
        "src/sunderkey/offline_protobuf_analysis.py",
        "tests/agents/test_offline_protobuf_analysis.py",
        "docs/offline-protobuf-analysis.md",
    ),
    (
        "AOE-GE-D22-S03",
        "crypto.pki-x509-validation",
        "IW2-016",
        "supplied_x509_chain_structure",
        "src/sunderkey/offline_x509_chain_analysis.py",
        "tests/agents/test_offline_x509_chain_analysis.py",
        "docs/offline-x509-chain-analysis.md",
    ),
    (
        "AOE-GB-D05-S03",
        "army.gb.d05.s03",
        "IW2-003",
        "supplied_http_request_framing",
        "src/sunderkey/offline_http_request_framing.py",
        "tests/agents/test_offline_http_request_framing.py",
        "docs/offline-http-request-framing.md",
    ),
    (
        "AOE-GC-D14-S04",
        "army.gc.d14.s04",
        "IW2-007",
        "azure_rbac_supplied_model",
        "src/sunderkey/azure_rbac_analysis.py",
        "tests/agents/test_azure_rbac_analysis.py",
        "docs/azure-rbac-offline-analysis.md",
    ),
    (
        "AOE-GB-D06-S04",
        "army.gb.d06.s04",
        "IW2-011",
        "soap_document_literal_contract_instance",
        "src/sunderkey/offline_soap_analysis.py",
        "tests/agents/test_offline_soap_analysis.py",
        "docs/offline-soap-analysis.md",
    ),
    (
        "AOE-GC-D14-S06",
        "army.gc.d14.s06",
        "IW2-009",
        "gcp_iam_supplied_allow_model",
        "src/sunderkey/gcp_iam_analysis.py",
        "tests/agents/test_gcp_iam_analysis.py",
        "docs/gcp-iam-offline-analysis.md",
    ),
    (
        "AOE-GA-D03-S05",
        "army.ga.d03.s05",
        "IW2-006",
        "supplied_jose_signature_and_claims",
        "src/sunderkey/offline_jose_analysis.py",
        "tests/agents/test_offline_jose_analysis.py",
        "docs/offline-jose-analysis.md",
    ),
    (
        "AOE-GB-D06-S01",
        "army.gb.d06.s01",
        "IW2-008",
        "openapi_security_declaration_evolution",
        "src/sunderkey/offline_openapi_security_evolution.py",
        "tests/agents/test_offline_openapi_security_evolution.py",
        "docs/offline-openapi-security-evolution.md",
    ),
    (
        "AOE-GC-D11-S05",
        "army.gc.d11.s05",
        "IW2-005",
        "windows_supplied_dacl_arithmetic",
        "src/sunderkey/offline_windows_dacl_analysis.py",
        "tests/agents/test_offline_windows_dacl_analysis.py",
        "docs/offline-windows-dacl-analysis.md",
    ),
    (
        "AOE-GC-D14-S01",
        "army.gc.d14.s01",
        "IW2-004",
        "aws-identity-policy-set-v1",
        "src/sunderkey/offline_aws_identity_policy_analysis.py",
        "tests/agents/test_offline_aws_identity_policy_analysis.py",
        "docs/offline-aws-identity-policy-analysis.md",
    ),
    (
        "AOE-GC-D15-S07",
        "army.gc.d15.s07",
        "IW2-009",
        "kubernetes_supplied_network_policy_flows",
        "src/sunderkey/kubernetes_network_policy_analysis.py",
        "tests/agents/test_kubernetes_network_policy_analysis.py",
        "docs/kubernetes-network-policy-offline-analysis.md",
    ),
    (
        "AOE-GC-D12-S01",
        "host.linux.local-privilege-escalation",
        "IW2-001",
        "linux_supplied_posix_acl_arithmetic",
        "src/sunderkey/offline_posix_acl_analysis.py",
        "tests/agents/test_offline_posix_acl_analysis.py",
        "docs/offline-posix-acl-analysis.md",
    ),
    (
        "AOE-GC-D14-S03",
        "army.gc.d14.s03",
        "IW2-006",
        "aws_supplied_vpc_flow_predicates",
        "src/sunderkey/aws_vpc_flow_analysis.py",
        "tests/agents/test_aws_vpc_flow_analysis.py",
        "docs/aws-vpc-flow-offline-analysis.md",
    ),
    (
        "AOE-GB-D07-S14",
        "army.gb.d07.s14",
        "IW2-014",
        "postgresql_supplied_select_rls",
        "src/sunderkey/offline_postgresql_rls_analysis.py",
        "tests/agents/test_offline_postgresql_rls_analysis.py",
        "docs/offline-postgresql-rls-analysis.md",
    ),
    (
        "AOE-GB-D06-S05",
        "army.gb.d06.s05",
        "IW2-012",
        "websocket_supplied_frame_state",
        "src/sunderkey/offline_websocket_frame_analysis.py",
        "tests/agents/test_offline_websocket_frame_analysis.py",
        "docs/offline-websocket-frame-analysis.md",
    ),
    (
        "AOE-GC-D15-S05",
        "army.gc.d15.s05",
        "IW2-007",
        "kubernetes_supplied_linux_pod_security_controls",
        "src/sunderkey/kubernetes_pod_security_analysis.py",
        "tests/agents/test_kubernetes_pod_security_analysis.py",
        "docs/kubernetes-pod-security-offline-analysis.md",
    ),
    (
        "AOE-GB-D07-S05",
        "army.gb.d07.s05",
        "IW2-005",
        "redis_supplied_acl_key_selectors",
        "src/sunderkey/offline_redis_acl_analysis.py",
        "tests/agents/test_offline_redis_acl_analysis.py",
        "docs/offline-redis-acl-analysis.md",
    ),
    (
        "AOE-GA-D01-S03",
        "army.ga.d01.s03",
        "IW2-003",
        "dns_supplied_zone_lookup",
        "src/sunderkey/offline_dns_zone_analysis.py",
        "tests/agents/test_offline_dns_zone_analysis.py",
        "docs/offline-dns-zone-analysis.md",
    ),
    (
        "AOE-GC-D13-S03",
        "army.gc.d13.s03",
        "IW2-006",
        "dns_supplied_wire_structure",
        "src/sunderkey/offline_dns_message_analysis.py",
        "tests/agents/test_offline_dns_message_analysis.py",
        "docs/offline-dns-message-analysis.md",
    ),
    (
        "AOE-GB-D05-S14",
        "army.gb.d05.s14",
        "IW2-014",
        "cors_supplied_negotiation_and_exposure",
        "src/sunderkey/offline_cors_analysis.py",
        "tests/agents/test_offline_cors_analysis.py",
        "docs/offline-cors-analysis.md",
    ),
    (
        "AOE-GC-D17-S10",
        "army.gc.d17.s10",
        "IW2-022",
        "oci_supplied_blob_graph_integrity",
        "src/sunderkey/offline_oci_blob_integrity.py",
        "tests/agents/test_offline_oci_blob_integrity.py",
        "docs/offline-oci-blob-integrity.md",
    ),
    (
        "AOE-GE-D22-S02",
        "army.ge.d22.s02",
        "IW2-015",
        "tls13_supplied_hello_offer_selection",
        "src/sunderkey/offline_tls_hello_analysis.py",
        "tests/agents/test_offline_tls_hello_analysis.py",
        "docs/offline-tls-hello-analysis.md",
    ),
    (
        "AOE-GB-D05-S11",
        "web.browser-auth-session",
        "IW2-011",
        "retained_cookie_candidate_predicates",
        "src/sunderkey/offline_cookie_selection.py",
        "tests/agents/test_offline_cookie_selection.py",
        "docs/offline-cookie-selection.md",
    ),
    (
        "AOE-GC-D17-S04",
        "army.gc.d17.s04",
        "IW2-016",
        "javascript_supplied_semver_interval_arithmetic",
        "src/sunderkey/offline_semver_interval_analysis.py",
        "tests/agents/test_offline_semver_interval_analysis.py",
        "docs/offline-semver-interval-analysis.md",
    ),
    (
        "AOE-GB-D05-S02",
        "army.gb.d05.s02",
        "IW2-002",
        "http_supplied_cache_freshness_arithmetic",
        "src/sunderkey/offline_http_cache_freshness.py",
        "tests/agents/test_offline_http_cache_freshness.py",
        "docs/offline-http-cache-freshness.md",
    ),
    (
        "AOE-GC-D14-S05",
        "army.gc.d14.s05",
        "IW2-008",
        "azure_supplied_nsg_directional_predicates",
        "src/sunderkey/offline_azure_nsg_analysis.py",
        "tests/agents/test_offline_azure_nsg_analysis.py",
        "docs/offline-azure-nsg-analysis.md",
    ),
    (
        "AOE-GB-D08-S03",
        "army.gb.d08.s03",
        "IW2-007",
        "android_supplied_component_declarations",
        "src/sunderkey/offline_android_component_analysis.py",
        "tests/agents/test_offline_android_component_analysis.py",
        "docs/offline-android-component-analysis.md",
    ),
    (
        "AOE-GC-D15-S07",
        "army.gc.d15.s07",
        "IW2-009",
        "kubernetes_supplied_service_endpoint_consistency",
        "src/sunderkey/offline_kubernetes_service_analysis.py",
        "tests/agents/test_offline_kubernetes_service_analysis.py",
        "docs/offline-kubernetes-service-analysis.md",
    ),
    (
        "AOE-GC-D14-S07",
        "army.gc.d14.s07",
        "IW2-010",
        "gcp_supplied_vpc_firewall_new_flow_predicates",
        "src/sunderkey/offline_gcp_firewall_analysis.py",
        "tests/agents/test_offline_gcp_firewall_analysis.py",
        "docs/offline-gcp-firewall-analysis.md",
    ),
    (
        "AOE-GB-D08-S07",
        "army.gb.d08.s07",
        "IW2-011",
        "ios_supplied_entitlement_declaration_consistency",
        "src/sunderkey/offline_ios_entitlement_analysis.py",
        "tests/agents/test_offline_ios_entitlement_analysis.py",
        "docs/offline-ios-entitlement-analysis.md",
    ),
    (
        "AOE-GD-D18-S15",
        "army.gd.d18.s15",
        "IW2-019",
        "mqtt_supplied_topic_filter_arithmetic",
        "src/sunderkey/offline_mqtt_topic_analysis.py",
        "tests/agents/test_offline_mqtt_topic_analysis.py",
        "docs/offline-mqtt-topic-analysis.md",
    ),
    (
        "AOE-GD-D19-S06",
        "army.gd.d19.s06",
        "IW2-016",
        "modbus_supplied_tcp_read_exchange_structure",
        "src/sunderkey/offline_modbus_tcp_analysis.py",
        "tests/agents/test_offline_modbus_tcp_analysis.py",
        "docs/offline-modbus-tcp-analysis.md",
    ),
    (
        "AOE-GB-D08-S01",
        "army.gb.d08.s01",
        "IW2-005",
        "android_supplied_dex035_structure",
        "src/sunderkey/offline_android_dex_analysis.py",
        "tests/agents/test_offline_android_dex_analysis.py",
        "docs/offline-android-dex-analysis.md",
    ),
    (
        "AOE-GB-D05-S14",
        "army.gb.d05.s14",
        "IW2-014",
        "csp_supplied_external_fetch_predicates",
        "src/sunderkey/offline_csp_fetch_analysis.py",
        "tests/agents/test_offline_csp_fetch_analysis.py",
        "docs/offline-csp-fetch-analysis.md",
    ),
    (
        "AOE-GB-D08-S05",
        "army.gb.d08.s05",
        "IW2-009",
        "ios_supplied_macho64_layout",
        "src/sunderkey/offline_macho_analysis.py",
        "tests/agents/test_offline_macho_analysis.py",
        "docs/offline-macho-analysis.md",
    ),
    (
        "AOE-GB-D06-S03",
        "army.gb.d06.s03",
        "IW2-010",
        "protobuf_supplied_wire_occurrences",
        "src/sunderkey/offline_protobuf_wire_analysis.py",
        "tests/agents/test_offline_protobuf_wire_analysis.py",
        "docs/offline-protobuf-wire-analysis.md",
    ),
    (
        "AOE-GD-D18-S15",
        "army.gd.d18.s15",
        "IW2-019",
        "coap_supplied_get_piggyback_structure",
        "src/sunderkey/offline_coap_analysis.py",
        "tests/agents/test_offline_coap_analysis.py",
        "docs/offline-coap-analysis.md",
    ),
    (
        "AOE-GB-D08-S17",
        "army.gb.d08.s17",
        "IW2-003",
        "linux_supplied_elf64_layout",
        "src/sunderkey/offline_elf64_layout_analysis.py",
        "tests/agents/test_offline_elf64_layout_analysis.py",
        "docs/offline-elf64-layout-analysis.md",
    ),
    (
        "AOE-GB-D08-S15",
        "army.gb.d08.s15",
        "IW2-001",
        "windows_supplied_pe32plus_layout",
        "src/sunderkey/offline_pe32_layout_analysis.py",
        "tests/agents/test_offline_pe32_layout_analysis.py",
        "docs/offline-pe32-layout-analysis.md",
    ),
    (
        "AOE-GC-D13-S03",
        "army.gc.d13.s03",
        "IW2-006",
        "dhcpv4_supplied_offer_ack_structure",
        "src/sunderkey/offline_dhcpv4_analysis.py",
        "tests/agents/test_offline_dhcpv4_analysis.py",
        "docs/offline-dhcpv4-analysis.md",
    ),
    (
        "AOE-GA-D03-S08",
        "army.ga.d03.s08",
        "IW2-009",
        "webauthn_supplied_assertion_context_arithmetic",
        "src/sunderkey/offline_webauthn_assertion_analysis.py",
        "tests/agents/test_offline_webauthn_assertion_analysis.py",
        "docs/offline-webauthn-assertion-analysis.md",
    ),
    (
        "AOE-GC-D13-S14",
        "army.gc.d13.s14",
        "IW2-017",
        "dkim_supplied_canonicalization_and_body_hash",
        "src/sunderkey/offline_dkim_canonicalization.py",
        "tests/agents/test_offline_dkim_canonicalization.py",
        "docs/offline-dkim-canonicalization.md",
    ),
    (
        "AOE-GC-D17-S01",
        "army.gc.d17.s01",
        "IW2-013",
        "git_supplied_pack_ofs_delta_reconstruction",
        "src/sunderkey/offline_git_pack_analysis.py",
        "tests/agents/test_offline_git_pack_analysis.py",
        "docs/offline-git-pack-analysis.md",
    ),
    (
        "AOE-GE-D21-S19",
        "army.ge.d21.s19",
        "IW2-001",
        "wasm_supplied_numeric_stack_and_interfaces",
        "src/sunderkey/offline_wasm_numeric_stack_analysis.py",
        "tests/agents/test_offline_wasm_numeric_stack_analysis.py",
        "docs/offline-wasm-numeric-stack-analysis.md",
    ),
    (
        "AOE-GE-D21-S13",
        "army.ge.d21.s13",
        "IW2-025",
        "exploit_supplied_coverage_seed_selection",
        "src/sunderkey/offline_coverage_seed_selection.py",
        "tests/agents/test_offline_coverage_seed_selection.py",
        "docs/offline-coverage-seed-selection.md",
    ),
    (
        "AOE-GE-D21-S14",
        "army.ge.d21.s14",
        "IW2-026",
        "exploit_supplied_finite_grammar_plan",
        "src/sunderkey/offline_grammar_plan.py",
        "tests/agents/test_offline_grammar_plan.py",
        "docs/offline-finite-grammar-plan.md",
    ),
    (
        "AOE-GE-D21-S15",
        "army.ge.d21.s15",
        "IW2-027",
        "exploit_supplied_path_constraint_feasibility",
        "src/sunderkey/offline_path_constraint_feasibility.py",
        "tests/agents/test_offline_path_constraint_feasibility.py",
        "docs/offline-path-constraint-feasibility.md",
    ),
    (
        "AOE-GE-D21-S16",
        "army.ge.d21.s16",
        "IW2-028",
        "exploit_supplied_binary_reference_graph",
        "src/sunderkey/offline_binary_reference_graph.py",
        "tests/agents/test_offline_binary_reference_graph.py",
        "docs/offline-binary-reference-graph.md",
    ),
    (
        "AOE-GE-D21-S17",
        "army.ge.d21.s17",
        "IW2-029",
        "exploit_supplied_source_variant_tokens",
        "src/sunderkey/offline_source_variant_tokens.py",
        "tests/agents/test_offline_source_variant_tokens.py",
        "docs/offline-source-variant-tokens.md",
    ),
    (
        "AOE-GE-D21-S11",
        "army.ge.d21.s11",
        "IW2-023",
        "exploit_supplied_happens_before_conflicts",
        "src/sunderkey/offline_happens_before_conflicts.py",
        "tests/agents/test_offline_happens_before_conflicts.py",
        "docs/offline-happens-before-conflicts.md",
    ),
    (
        "AOE-GE-D21-S12",
        "army.ge.d21.s12",
        "IW2-024",
        "exploit_supplied_integer_width_arithmetic",
        "src/sunderkey/offline_integer_width_arithmetic.py",
        "tests/agents/test_offline_integer_width_arithmetic.py",
        "docs/offline-integer-width-arithmetic.md",
    ),
    (
        "AOE-GE-D21-S09",
        "army.ge.d21.s09",
        "IW2-021",
        "exploit_supplied_heap_trace_consistency",
        "src/sunderkey/offline_heap_trace_consistency.py",
        "tests/agents/test_offline_heap_trace_consistency.py",
        "docs/offline-heap-trace-consistency.md",
    ),
    (
        "AOE-GE-D21-S18",
        "army.ge.d21.s18",
        "IW2-030",
        "exploit_supplied_chain_trial_accounting",
        "src/sunderkey/offline_chain_trial_accounting.py",
        "tests/agents/test_offline_chain_trial_accounting.py",
        "docs/offline-chain-trial-accounting.md",
    ),
    (
        "AOE-GC-D12-S06",
        "army.gc.d12.s06",
        "IW2-006",
        "ssh_supplied_kexinit_selection_arithmetic",
        "src/sunderkey/offline_ssh_kexinit_analysis.py",
        "tests/agents/test_offline_ssh_kexinit_analysis.py",
        "docs/offline-ssh-kexinit-analysis.md",
    ),
    (
        "AOE-GC-D13-S01",
        "army.gc.d13.s01",
        "IW2-004",
        "ipv4_supplied_fragment_relations_and_header_checksums",
        "src/sunderkey/offline_ipv4_fragment_analysis.py",
        "tests/agents/test_offline_ipv4_fragment_analysis.py",
        "docs/offline-ipv4-fragment-analysis.md",
    ),
    (
        "AOE-GC-D13-S02",
        "army.gc.d13.s02",
        "IW2-005",
        "bgp_supplied_update_structure",
        "src/sunderkey/offline_bgp_update_analysis.py",
        "tests/agents/test_offline_bgp_update_analysis.py",
        "docs/offline-bgp-update-analysis.md",
    ),
    (
        "AOE-GC-D17-S05",
        "army.gc.d17.s05",
        "IW2-017",
        "wheel_supplied_zip_record_integrity",
        "src/sunderkey/offline_wheel_record_analysis.py",
        "tests/agents/test_offline_wheel_record_analysis.py",
        "docs/offline-wheel-record-analysis.md",
    ),
    (
        "AOE-GB-D07-S07",
        "army.gb.d07.s07",
        "IW2-007",
        "amqp091_supplied_publish_content_assembly",
        "src/sunderkey/offline_amqp091_content_analysis.py",
        "tests/agents/test_offline_amqp091_content_analysis.py",
        "docs/offline-amqp091-content-analysis.md",
    ),
    (
        "AOE-GB-D05-S01",
        "army.gb.d05.s01",
        "IW2-001",
        "http_supplied_byte_range_arithmetic",
        "src/sunderkey/offline_http_byte_range_analysis.py",
        "tests/agents/test_offline_http_byte_range_analysis.py",
        "docs/offline-http-byte-range-analysis.md",
    ),
    (
        "AOE-GB-D05-S01",
        "army.gb.d05.s01",
        "IW2-001",
        "http_supplied_etag_precondition_order",
        "src/sunderkey/offline_http_etag_preconditions.py",
        "tests/agents/test_offline_http_etag_preconditions.py",
        "docs/offline-http-etag-preconditions.md",
    ),
    (
        "AOE-GE-D22-S03",
        "crypto.pki-x509-validation",
        "IW2-016",
        "x509_supplied_san_reference_match",
        "src/sunderkey/offline_x509_san_analysis.py",
        "tests/agents/test_offline_x509_san_analysis.py",
        "docs/offline-x509-san-analysis.md",
    ),
    (
        "AOE-GA-D03-S03",
        "army.ga.d03.s03",
        "IW2-004",
        "saml_supplied_conditions_audience_restrictions",
        "src/sunderkey/offline_saml_conditions_analysis.py",
        "tests/agents/test_offline_saml_conditions_analysis.py",
        "docs/offline-saml-conditions-analysis.md",
    ),
    (
        "AOE-GD-D25-S12",
        "army.gd.d25.s12",
        "IW2-012",
        "dicom_supplied_pdata_pdv_structure",
        "src/sunderkey/offline_dicom_pdv_analysis.py",
        "tests/agents/test_offline_dicom_pdv_analysis.py",
        "docs/offline-dicom-pdv-analysis.md",
    ),
    (
        "AOE-GC-D14-S01",
        "army.gc.d14.s01",
        "IW2-004",
        "aws-supplied-identity-scp-pair-v1",
        "src/sunderkey/offline_aws_policy_scp_join.py",
        "tests/agents/test_offline_aws_policy_scp_join.py",
        "docs/offline-aws-policy-scp-join.md",
    ),
    (
        "AOE-GA-D03-S04",
        "identity.oauth-oidc",
        "IW2-005",
        "oauth_supplied_code_pkce_transcript",
        "src/sunderkey/offline_oauth_pkce_transcript.py",
        "tests/agents/test_offline_oauth_pkce_transcript.py",
        "docs/offline-oauth-pkce-transcript.md",
    ),
    (
        "AOE-GB-D06-S11",
        "army.gb.d06.s11",
        "IW2-003",
        "api_supplied_property_authorization",
        "src/sunderkey/offline_property_authorization.py",
        "tests/agents/test_offline_property_authorization.py",
        "docs/offline-property-authorization.md",
    ),
    (
        "AOE-GB-D05-S04",
        "army.gb.d05.s04",
        "IW2-004",
        "http_supplied_cache_key_differential",
        "src/sunderkey/offline_cache_key_differential.py",
        "tests/agents/test_offline_cache_key_differential.py",
        "docs/offline-cache-key-differential.md",
    ),
    (
        "AOE-GB-D06-S12",
        "army.gb.d06.s12",
        "IW2-016",
        "api_supplied_content_type_differential",
        "src/sunderkey/offline_content_type_differential.py",
        "tests/agents/test_offline_content_type_differential.py",
        "docs/offline-content-type-differential.md",
    ),
    (
        "AOE-GB-D06-S13",
        "army.gb.d06.s13",
        "IW2-004",
        "api_supplied_rate_limit_projection",
        "src/sunderkey/offline_api_rate_limit.py",
        "tests/agents/test_offline_api_rate_limit.py",
        "docs/offline-api-rate-limit.md",
    ),
    (
        "AOE-GB-D05-S05",
        "army.gb.d05.s05",
        "IW2-005",
        "https_supplied_url_navigation_projection",
        "src/sunderkey/offline_url_navigation.py",
        "tests/agents/test_offline_url_navigation.py",
        "docs/offline-url-navigation.md",
    ),
    (
        "AOE-GB-D06-S07",
        "army.gb.d06.s07",
        "IW2-014",
        "api_supplied_gateway_route_selection",
        "src/sunderkey/offline_api_gateway_routes.py",
        "tests/agents/test_offline_api_gateway_routes.py",
        "docs/offline-api-gateway-routes.md",
    ),
    (
        "AOE-GC-D14-S10",
        "cloud.workload-identity-metadata",
        "IW2-013",
        "workload_identity_supplied_trust_projection",
        "src/sunderkey/offline_workload_identity_trust.py",
        "tests/agents/test_offline_workload_identity_trust.py",
        "docs/offline-workload-identity-trust.md",
    ),
    (
        "AOE-GC-D17-S02",
        "supply-chain.ci-runner-workflow",
        "IW2-014",
        "ci_supplied_workflow_trust_flow",
        "src/sunderkey/offline_ci_workflow_trust.py",
        "tests/agents/test_offline_ci_workflow_trust.py",
        "docs/offline-ci-workflow-trust.md",
    ),
    (
        "AOE-GA-D03-S15",
        "army.ga.d03.s15",
        "IW2-016",
        "directory_supplied_lifecycle_projection",
        "src/sunderkey/offline_scim_lifecycle.py",
        "tests/agents/test_offline_scim_lifecycle.py",
        "docs/offline-scim-lifecycle.md",
    ),
    (
        "AOE-GC-D17-S08",
        "army.gc.d17.s08",
        "IW2-020",
        "dependency_supplied_resolution_collision",
        "src/sunderkey/offline_dependency_resolution.py",
        "tests/agents/test_offline_dependency_resolution.py",
        "docs/offline-dependency-resolution.md",
    ),
    (
        "AOE-GB-D06-S09",
        "api.authorization.object-level",
        "IW2-001",
        "api_supplied_object_authorization",
        "src/sunderkey/offline_api_object_authorization.py",
        "tests/agents/test_offline_api_object_authorization.py",
        "docs/offline-api-object-authorization.md",
    ),
    (
        "AOE-GB-D06-S10",
        "api.authorization.function-level",
        "IW2-002",
        "api_supplied_function_authorization_differential",
        "src/sunderkey/offline_api_function_authorization.py",
        "tests/agents/test_offline_api_function_authorization.py",
        "docs/offline-api-function-authorization.md",
    ),
    (
        "AOE-GB-D06-S14",
        "army.gb.d06.s14",
        "IW2-005",
        "api_supplied_inventory_drift",
        "src/sunderkey/offline_api_inventory_drift.py",
        "tests/agents/test_offline_api_inventory_drift.py",
        "docs/offline-api-inventory-drift.md",
    ),
    (
        "AOE-GB-D06-S15",
        "army.gb.d06.s15",
        "IW2-006",
        "api_supplied_downstream_trust_flow",
        "src/sunderkey/offline_api_downstream_trust.py",
        "tests/agents/test_offline_api_downstream_trust.py",
        "docs/offline-api-downstream-trust.md",
    ),
    (
        "AOE-GB-D05-S13",
        "army.gb.d05.s13",
        "IW2-013",
        "dom_supplied_dataflow_projection",
        "src/sunderkey/offline_dom_dataflow.py",
        "tests/agents/test_offline_dom_dataflow.py",
        "docs/offline-dom-dataflow.md",
    ),
    (
        "AOE-GA-D01-S11",
        "attack-path.graph-modeling",
        "IW2-011",
        "supplied_attack_graph_model",
        "src/sunderkey/offline_attack_graph_model.py",
        "tests/agents/test_offline_attack_graph_model.py",
        "docs/offline-attack-graph-model.md",
    ),
    (
        "AOE-GB-D05-S12",
        "web.access-control.multitenancy",
        "IW2-012",
        "web_supplied_route_authorization",
        "src/sunderkey/offline_web_route_authorization.py",
        "tests/agents/test_offline_web_route_authorization.py",
        "docs/offline-web-route-authorization.md",
    ),
    (
        "AOE-GB-D05-S15",
        "army.gb.d05.s15",
        "IW2-015",
        "browser_supplied_message_boundary_projection",
        "src/sunderkey/offline_browser_message_boundary.py",
        "tests/agents/test_offline_browser_message_boundary.py",
        "docs/offline-browser-message-boundary.md",
    ),
    (
        "AOE-GB-D05-S10",
        "army.gb.d05.s10",
        "IW2-010",
        "supplied_web_content_handling",
        "src/sunderkey/offline_web_content_handling.py",
        "tests/agents/test_offline_web_content_handling.py",
        "docs/offline-web-content-handling.md",
    ),
    (
        "AOE-GB-D06-S06",
        "army.gb.d06.s06",
        "IW2-013",
        "api_supplied_webhook_callback_trust",
        "src/sunderkey/offline_webhook_callback_trust.py",
        "tests/agents/test_offline_webhook_callback_trust.py",
        "docs/offline-webhook-callback-trust.md",
    ),
    (
        "AOE-GB-D06-S08",
        "army.gb.d06.s08",
        "IW2-015",
        "api_supplied_service_mesh_trust_projection",
        "src/sunderkey/offline_service_mesh_trust.py",
        "tests/agents/test_offline_service_mesh_trust.py",
        "docs/offline-service-mesh-trust.md",
    ),
    (
        "AOE-GB-D05-S09",
        "army.gb.d05.s09",
        "IW2-009",
        "supplied_template_context",
        "src/sunderkey/offline_template_context.py",
        "tests/agents/test_offline_template_context.py",
        "docs/offline-template-context.md",
    ),
    (
        "AOE-GB-D06-S16",
        "army.gb.d06.s16",
        "IW2-007",
        "api_supplied_partner_connector_trust_projection",
        "src/sunderkey/offline_partner_connector_trust.py",
        "tests/agents/test_offline_partner_connector_trust.py",
        "docs/offline-partner-connector-trust.md",
    ),
    (
        "AOE-GB-D05-S16",
        "army.gb.d05.s16",
        "IW2-016",
        "web_supplied_service_worker_scope",
        "src/sunderkey/offline_service_worker_scope.py",
        "tests/agents/test_offline_service_worker_scope.py",
        "docs/offline-service-worker-scope.md",
    ),
    (
        "AOE-GD-D20-S14",
        "army.gd.d20.s14",
        "IW2-004",
        "agent_supplied_tool_authority_projection",
        "src/sunderkey/offline_agent_tool_authority.py",
        "tests/agents/test_offline_agent_tool_authority.py",
        "docs/offline-agent-tool-authority.md",
    ),
    (
        "AOE-GD-D20-S13",
        "army.gd.d20.s13",
        "IW2-017",
        "agent_supplied_output_handling_boundary",
        "src/sunderkey/offline_agent_output_handling.py",
        "tests/agents/test_offline_agent_output_handling.py",
        "docs/offline-agent-output-handling.md",
    ),
    (
        "AOE-GD-D20-S10",
        "ai.indirect-prompt-injection",
        "IW2-014",
        "agent_supplied_indirect_prompt_boundary",
        "src/sunderkey/offline_indirect_prompt_boundary.py",
        "tests/agents/test_offline_indirect_prompt_boundary.py",
        "docs/offline-indirect-prompt-boundary.md",
    ),
    (
        "AOE-GD-D20-S11",
        "army.gd.d20.s11",
        "IW2-015",
        "rag_supplied_index_provenance",
        "src/sunderkey/offline_rag_provenance.py",
        "tests/agents/test_offline_rag_provenance.py",
        "docs/offline-rag-provenance.md",
    ),
    (
        "AOE-GD-D20-S16",
        "army.gd.d20.s16",
        "IW2-018",
        "agent_supplied_memory_provenance",
        "src/sunderkey/offline_agent_memory_provenance.py",
        "tests/agents/test_offline_agent_memory_provenance.py",
        "docs/offline-agent-memory-provenance.md",
    ),
    (
        "AOE-GD-D20-S07",
        "army.gd.d20.s07",
        "IW2-012",
        "model_supplied_pickle_opcode_safety",
        "src/sunderkey/offline_pickle_opcode_safety.py",
        "tests/agents/test_offline_pickle_opcode_safety.py",
        "docs/offline-pickle-opcode-safety.md",
    ),
    (
        "AOE-GD-D20-S08",
        "army.gd.d20.s08",
        "IW2-003",
        "model_supplied_artifact_integrity",
        "src/sunderkey/offline_model_artifact_integrity.py",
        "tests/agents/test_offline_model_artifact_integrity.py",
        "docs/offline-model-artifact-integrity.md",
    ),
    (
        "AOE-GD-D20-S04",
        "army.gd.d20.s04",
        "IW2-009",
        "model_supplied_evasion_delta_measurement",
        "src/sunderkey/offline_evasion_delta_measurement.py",
        "tests/agents/test_offline_evasion_delta_measurement.py",
        "docs/offline-evasion-delta-measurement.md",
    ),
    (
        "AOE-GD-D20-S15",
        "army.gd.d20.s15",
        "IW2-005",
        "agent_supplied_credential_boundary",
        "src/sunderkey/offline_agent_credential_boundary.py",
        "tests/agents/test_offline_agent_credential_boundary.py",
        "docs/offline-agent-credential-boundary.md",
    ),
    (
        "AOE-GD-D20-S01",
        "army.gd.d20.s01",
        "IW2-006",
        "mlops_supplied_release_lineage",
        "src/sunderkey/offline_mlops_lineage.py",
        "tests/agents/test_offline_mlops_lineage.py",
        "docs/offline-mlops-lineage.md",
    ),
    (
        "AOE-GD-D20-S02",
        "army.gd.d20.s02",
        "IW2-007",
        "training_supplied_label_share_drift",
        "src/sunderkey/offline_training_label_drift.py",
        "tests/agents/test_offline_training_label_drift.py",
        "docs/offline-training-label-drift.md",
    ),
    (
        "AOE-GD-D20-S03",
        "army.gd.d20.s03",
        "IW2-008",
        "model_supplied_trigger_selectivity",
        "src/sunderkey/offline_model_trigger_selectivity.py",
        "tests/agents/test_offline_model_trigger_selectivity.py",
        "docs/offline-model-trigger-selectivity.md",
    ),
    (
        "AOE-GD-D20-S05",
        "army.gd.d20.s05",
        "IW2-010",
        "model_supplied_output_similarity",
        "src/sunderkey/offline_model_output_similarity.py",
        "tests/agents/test_offline_model_output_similarity.py",
        "docs/offline-model-output-similarity.md",
    ),
    (
        "AOE-GD-D20-S06",
        "army.gd.d20.s06",
        "IW2-011",
        "model_supplied_membership_score_separation",
        "src/sunderkey/offline_membership_score_separation.py",
        "tests/agents/test_offline_membership_score_separation.py",
        "docs/offline-membership-score-separation.md",
    ),
    (
        "AOE-GD-D20-S12",
        "army.gd.d20.s12",
        "IW2-016",
        "model_supplied_prompt_canary_exposure",
        "src/sunderkey/offline_prompt_canary_exposure.py",
        "tests/agents/test_offline_prompt_canary_exposure.py",
        "docs/offline-prompt-canary-exposure.md",
    ),
    (
        "AOE-GD-D20-S18",
        "army.gd.d20.s18",
        "IW2-020",
        "agent_supplied_resource_budget",
        "src/sunderkey/offline_agent_resource_budget.py",
        "tests/agents/test_offline_agent_resource_budget.py",
        "docs/offline-agent-resource-budget.md",
    ),
    (
        "AOE-GD-D20-S19",
        "army.gd.d20.s19",
        "IW2-001",
        "agent_supplied_plan_revision_integrity",
        "src/sunderkey/offline_agent_plan_integrity.py",
        "tests/agents/test_offline_agent_plan_integrity.py",
        "docs/offline-agent-plan-integrity.md",
    ),
    (
        "AOE-GD-D20-S20",
        "army.gd.d20.s20",
        "IW2-002",
        "multi_agent_supplied_coordination_trust",
        "src/sunderkey/offline_multi_agent_coordination.py",
        "tests/agents/test_offline_multi_agent_coordination.py",
        "docs/offline-multi-agent-coordination.md",
    ),
    (
        "AOE-GC-D17-S03",
        "army.gc.d17.s03",
        "IW2-015",
        "cd_supplied_release_provenance",
        "src/sunderkey/offline_cd_release_provenance.py",
        "tests/agents/test_offline_cd_release_provenance.py",
        "docs/offline-cd-release-provenance.md",
    ),
    (
        "AOE-GC-D16-S06",
        "army.gc.d16.s06",
        "IW2-018",
        "hypervisor_supplied_management_posture_projection",
        "src/sunderkey/offline_hypervisor_management_posture.py",
        "tests/agents/test_offline_hypervisor_management_posture.py",
        "docs/offline-hypervisor-management-posture.md",
    ),
    (
        "AOE-GC-D16-S07",
        "army.gc.d16.s07",
        "IW2-019",
        "vdi_supplied_session_posture_projection",
        "src/sunderkey/offline_vdi_session_posture.py",
        "tests/agents/test_offline_vdi_session_posture.py",
        "docs/offline-vdi-session-posture.md",
    ),
    (
        "AOE-GC-D16-S08",
        "army.gc.d16.s08",
        "IW2-020",
        "backup_supplied_recovery_posture_projection",
        "src/sunderkey/offline_backup_recovery_posture.py",
        "tests/agents/test_offline_backup_recovery_posture.py",
        "docs/offline-backup-recovery-posture.md",
    ),
    (
        "AOE-GC-D16-S09",
        "army.gc.d16.s09",
        "IW2-021",
        "storage_supplied_access_posture_projection",
        "src/sunderkey/offline_storage_access_posture.py",
        "tests/agents/test_offline_storage_access_posture.py",
        "docs/offline-storage-access-posture.md",
    ),
    (
        "AOE-GC-D16-S10",
        "army.gc.d16.s10",
        "IW2-022",
        "enterprise_server_supplied_management_projection",
        "src/sunderkey/offline_enterprise_server_management.py",
        "tests/agents/test_offline_enterprise_server_management.py",
        "docs/offline-enterprise-server-management.md",
    ),
    (
        "AOE-GC-D16-S11",
        "army.gc.d16.s11",
        "IW2-023",
        "rmm_supplied_control_posture_projection",
        "src/sunderkey/offline_rmm_control_posture.py",
        "tests/agents/test_offline_rmm_control_posture.py",
        "docs/offline-rmm-control-posture.md",
    ),
    (
        "AOE-GC-D16-S12",
        "army.gc.d16.s12",
        "IW2-024",
        "hpc_supplied_queue_posture_projection",
        "src/sunderkey/offline_hpc_queue_posture.py",
        "tests/agents/test_offline_hpc_queue_posture.py",
        "docs/offline-hpc-queue-posture.md",
    ),
    (
        "AOE-GC-D17-S06",
        "army.gc.d17.s06",
        "IW2-018",
        "managed_supplied_package_feed_projection",
        "src/sunderkey/offline_managed_package_feed.py",
        "tests/agents/test_offline_managed_package_feed.py",
        "docs/offline-managed-package-feed.md",
    ),
    (
        "AOE-GC-D17-S07",
        "army.gc.d17.s07",
        "IW2-019",
        "native_supplied_target_compatibility_projection",
        "src/sunderkey/offline_native_target_compatibility.py",
        "tests/agents/test_offline_native_target_compatibility.py",
        "docs/offline-native-target-compatibility.md",
    ),
    (
        "AOE-GC-D17-S09",
        "army.gc.d17.s09",
        "IW2-021",
        "build_supplied_reproducibility_projection",
        "src/sunderkey/offline_build_reproducibility.py",
        "tests/agents/test_offline_build_reproducibility.py",
        "docs/offline-build-reproducibility.md",
    ),
    (
        "AOE-GC-D17-S11",
        "army.gc.d17.s11",
        "IW2-023",
        "repository_supplied_secret_occurrence_projection",
        "src/sunderkey/offline_repository_secret_metadata.py",
        "tests/agents/test_offline_repository_secret_metadata.py",
        "docs/offline-repository-secret-metadata.md",
    ),
    (
        "AOE-GC-D17-S12",
        "army.gc.d17.s12",
        "IW2-024",
        "iac_supplied_change_dependency_projection",
        "src/sunderkey/offline_iac_change_graph.py",
        "tests/agents/test_offline_iac_change_graph.py",
        "docs/offline-iac-change-graph.md",
    ),
    (
        "AOE-GC-D17-S13",
        "army.gc.d17.s13",
        "IW2-025",
        "devcontainer_supplied_host_boundary_projection",
        "src/sunderkey/offline_devcontainer_boundary.py",
        "tests/agents/test_offline_devcontainer_boundary.py",
        "docs/offline-devcontainer-boundary.md",
    ),
    (
        "AOE-GC-D17-S14",
        "army.gc.d17.s14",
        "IW2-026",
        "vendor_supplied_update_lineage_projection",
        "src/sunderkey/offline_vendor_update_lineage.py",
        "tests/agents/test_offline_vendor_update_lineage.py",
        "docs/offline-vendor-update-lineage.md",
    ),
    (
        "AOE-GC-D15-S08",
        "army.gc.d15.s08",
        "IW2-010",
        "kubernetes_supplied_admission_policy_projection",
        "src/sunderkey/offline_kubernetes_admission_boundary.py",
        "tests/agents/test_offline_kubernetes_admission_boundary.py",
        "docs/offline-kubernetes-admission-boundary.md",
    ),
    (
        "AOE-GC-D14-S09",
        "army.gc.d14.s09",
        "IW2-012",
        "cloud_supplied_multicloud_federation_projection",
        "src/sunderkey/offline_multicloud_federation.py",
        "tests/agents/test_offline_multicloud_federation.py",
        "docs/offline-multicloud-federation.md",
    ),
    (
        "AOE-GB-D05-S06",
        "army.gb.d05.s06",
        "IW2-006",
        "java_supplied_filter_mapping_boundary",
        "src/sunderkey/offline_java_filter_boundary.py",
        "tests/agents/test_offline_java_filter_boundary.py",
        "docs/offline-java-filter-boundary.md",
    ),
    (
        "AOE-GB-D05-S07",
        "army.gb.d05.s07",
        "IW2-007",
        "dotnet_supplied_middleware_order_boundary",
        "src/sunderkey/offline_dotnet_middleware_boundary.py",
        "tests/agents/test_offline_dotnet_middleware_boundary.py",
        "docs/offline-dotnet-middleware-boundary.md",
    ),
    (
        "AOE-GB-D05-S08",
        "army.gb.d05.s08",
        "IW2-008",
        "web_supplied_framework_stack_projection",
        "src/sunderkey/offline_web_framework_stack.py",
        "tests/agents/test_offline_web_framework_stack.py",
        "docs/offline-web-framework-stack.md",
    ),
    (
        "AOE-GB-D05-S17",
        "army.gb.d05.s17",
        "IW2-017",
        "web_supplied_cms_permission_graph_projection",
        "src/sunderkey/offline_cms_permission_graph.py",
        "tests/agents/test_offline_cms_permission_graph.py",
        "docs/offline-cms-permission-graph.md",
    ),
    (
        "AOE-GB-D05-S18",
        "army.gb.d05.s18",
        "IW2-018",
        "browser_supplied_webrtc_signaling_projection",
        "src/sunderkey/offline_webrtc_signaling.py",
        "tests/agents/test_offline_webrtc_signaling.py",
        "docs/offline-webrtc-signaling.md",
    ),
    (
        "AOE-GB-D07-S02",
        "army.gb.d07.s02",
        "IW2-002",
        "data_supplied_nosql_access_grants_projection",
        "src/sunderkey/offline_nosql_access_grants.py",
        "tests/agents/test_offline_nosql_access_grants.py",
        "docs/offline-nosql-access-grants.md",
    ),
    (
        "AOE-GB-D07-S04",
        "army.gb.d07.s04",
        "IW2-004",
        "data_supplied_vector_tenant_boundary_projection",
        "src/sunderkey/offline_vector_tenant_boundary.py",
        "tests/agents/test_offline_vector_tenant_boundary.py",
        "docs/offline-vector-tenant-boundary.md",
    ),
    (
        "AOE-GA-D03-S14",
        "army.ga.d03.s14",
        "IW2-015",
        "identity_supplied_entitlement_toxic_combination",
        "src/sunderkey/offline_entitlement_toxic_combination.py",
        "tests/agents/test_offline_entitlement_toxic_combination.py",
        "docs/offline-entitlement-toxic-combination.md",
    ),
    (
        "AOE-GA-D03-S16",
        "army.ga.d03.s16",
        "IW2-017",
        "identity_supplied_session_binding_timeline",
        "src/sunderkey/offline_session_binding_timeline.py",
        "tests/agents/test_offline_session_binding_timeline.py",
        "docs/offline-session-binding-timeline.md",
    ),
    (
        "AOE-GB-D08-S12",
        "army.gb.d08.s12",
        "IW2-016",
        "browser_supplied_webview_bridge_origin_projection",
        "src/sunderkey/offline_webview_bridge_origin.py",
        "tests/agents/test_offline_webview_bridge_origin.py",
        "docs/offline-webview-bridge-origin.md",
    ),
    (
        "AOE-GB-D08-S18",
        "army.gb.d08.s18",
        "IW2-004",
        "desktop_supplied_electron_bridge_origin_projection",
        "src/sunderkey/offline_electron_bridge_origin.py",
        "tests/agents/test_offline_electron_bridge_origin.py",
        "docs/offline-electron-bridge-origin.md",
    ),
    (
        "AOE-GA-D01-S04",
        "army.ga.d01.s04",
        "IW2-004",
        "supplied_prefix_origin_mapping",
        "src/sunderkey/offline_prefix_origin_mapping.py",
        "tests/agents/test_offline_prefix_origin_mapping.py",
        "docs/offline-prefix-origin-mapping.md",
    ),
    (
        "AOE-GA-D01-S05",
        "army.ga.d01.s05",
        "IW2-005",
        "supplied_cloud_inventory_drift",
        "src/sunderkey/offline_cloud_inventory_drift.py",
        "tests/agents/test_offline_cloud_inventory_drift.py",
        "docs/offline-cloud-inventory-drift.md",
    ),
    (
        "AOE-GA-D01-S06",
        "army.ga.d01.s06",
        "IW2-006",
        "supplied_saas_signal_correlation",
        "src/sunderkey/offline_saas_signal_correlation.py",
        "tests/agents/test_offline_saas_signal_correlation.py",
        "docs/offline-saas-signal-correlation.md",
    ),
    (
        "AOE-GA-D01-S08",
        "army.ga.d01.s08",
        "IW2-008",
        "supplied_credential_exposure_review",
        "src/sunderkey/offline_credential_exposure_review.py",
        "tests/agents/test_offline_credential_exposure_review.py",
        "docs/offline-credential-exposure-review.md",
    ),
    (
        "AOE-GA-D01-S07",
        "army.ga.d01.s07",
        "IW2-007",
        "supplied_repository_reference_graph",
        "src/sunderkey/offline_repository_reference_graph.py",
        "tests/agents/test_offline_repository_reference_graph.py",
        "docs/offline-repository-reference-graph.md",
    ),
    (
        "AOE-GA-D01-S10",
        "army.ga.d01.s10",
        "IW2-010",
        "supplied_technology_evidence_reconciliation",
        "src/sunderkey/offline_technology_evidence.py",
        "tests/agents/test_offline_technology_evidence.py",
        "docs/offline-technology-evidence.md",
    ),
    (
        "AOE-GA-D01-S12",
        "army.ga.d01.s12",
        "IW2-012",
        "supplied_deception_cue_reconciliation",
        "src/sunderkey/offline_deception_evidence.py",
        "tests/agents/test_offline_deception_evidence.py",
        "docs/offline-deception-evidence.md",
    ),
    (
        "AOE-GB-D09-S01",
        "business-logic.workflow-state-machine",
        "IW2-001",
        "supplied_workflow_state_replay",
        "src/sunderkey/offline_workflow_state_replay.py",
        "tests/agents/test_offline_workflow_state_replay.py",
        "docs/offline-workflow-state-replay.md",
    ),
    (
        "AOE-GB-D09-S02",
        "army.gb.d09.s02",
        "IW2-002",
        "supplied_price_rounding_arithmetic",
        "src/sunderkey/offline_price_rounding_analysis.py",
        "tests/agents/test_offline_price_rounding_analysis.py",
        "docs/offline-price-rounding-analysis.md",
    ),
    (
        "AOE-GB-D09-S03",
        "army.gb.d09.s03",
        "IW2-003",
        "supplied_debit_idempotency_timeline",
        "src/sunderkey/offline_debit_idempotency_timeline.py",
        "tests/agents/test_offline_debit_idempotency_timeline.py",
        "docs/offline-debit-idempotency-timeline.md",
    ),
    (
        "AOE-GB-D09-S07",
        "army.gb.d09.s07",
        "IW2-007",
        "supplied_coupon_redemption_timeline",
        "src/sunderkey/offline_coupon_redemption_timeline.py",
        "tests/agents/test_offline_coupon_redemption_timeline.py",
        "docs/offline-coupon-redemption-timeline.md",
    ),
    (
        "AOE-GB-D09-S11",
        "army.gb.d09.s11",
        "IW2-011",
        "supplied_consent_purpose_timeline",
        "src/sunderkey/offline_consent_purpose_timeline.py",
        "tests/agents/test_offline_consent_purpose_timeline.py",
        "docs/offline-consent-purpose-timeline.md",
    ),
    (
        "AOE-GB-D09-S05",
        "army.gb.d09.s05",
        "IW2-005",
        "supplied_account_recovery_threshold",
        "src/sunderkey/offline_account_recovery_threshold.py",
        "tests/agents/test_offline_account_recovery_threshold.py",
        "docs/offline-account-recovery-threshold.md",
    ),
    (
        "AOE-GB-D09-S06",
        "army.gb.d09.s06",
        "IW2-006",
        "supplied_tenant_ownership_reconciliation",
        "src/sunderkey/offline_tenant_ownership_reconciliation.py",
        "tests/agents/test_offline_tenant_ownership_reconciliation.py",
        "docs/offline-tenant-ownership-reconciliation.md",
    ),
    (
        "AOE-GB-D09-S08",
        "army.gb.d09.s08",
        "IW2-008",
        "supplied_auction_bid_timeline",
        "src/sunderkey/offline_auction_bid_timeline.py",
        "tests/agents/test_offline_auction_bid_timeline.py",
        "docs/offline-auction-bid-timeline.md",
    ),
    (
        "AOE-GB-D09-S04",
        "army.gb.d09.s04",
        "IW2-004",
        "supplied_payment_reversal_ledger",
        "src/sunderkey/offline_payment_reversal_ledger.py",
        "tests/agents/test_offline_payment_reversal_ledger.py",
        "docs/offline-payment-reversal-ledger.md",
    ),
    (
        "AOE-GB-D09-S12",
        "army.gb.d09.s12",
        "IW2-012",
        "supplied_cross_channel_balance",
        "src/sunderkey/offline_cross_channel_balance.py",
        "tests/agents/test_offline_cross_channel_balance.py",
        "docs/offline-cross-channel-balance.md",
    ),
    (
        "AOE-GB-D09-S09",
        "army.gb.d09.s09",
        "IW2-009",
        "supplied_scalping_window_review",
        "src/sunderkey/offline_scalping_window_review.py",
        "tests/agents/test_offline_scalping_window_review.py",
        "docs/offline-scalping-window-review.md",
    ),
    (
        "AOE-GB-D09-S10",
        "army.gb.d09.s10",
        "IW2-010",
        "supplied_fraud_decision_review",
        "src/sunderkey/offline_fraud_decision_review.py",
        "tests/agents/test_offline_fraud_decision_review.py",
        "docs/offline-fraud-decision-review.md",
    ),
    (
        "AOE-GC-D11-S01",
        "enterprise.active-directory.path-analysis",
        "IW2-001",
        "supplied_directory_entitlement_path",
        "src/sunderkey/offline_directory_entitlement_path.py",
        "tests/agents/test_offline_directory_entitlement_path.py",
        "docs/offline-directory-entitlement-path.md",
    ),
    (
        "AOE-GC-D11-S06",
        "army.gc.d11.s06",
        "IW2-006",
        "supplied_directory_trust_paths",
        "src/sunderkey/offline_directory_trust_paths.py",
        "tests/agents/test_offline_directory_trust_paths.py",
        "docs/offline-directory-trust-paths.md",
    ),
    (
        "AOE-GC-D11-S14",
        "enterprise.entra-id",
        "IW2-014",
        "supplied_entra_role_claim_review",
        "src/sunderkey/offline_entra_role_claim_review.py",
        "tests/agents/test_offline_entra_role_claim_review.py",
        "docs/offline-entra-role-claim-review.md",
    ),
    (
        "AOE-GB-D07-S01",
        "data.relational-database",
        "IW2-001",
        "supplied_relational_grant_path",
        "src/sunderkey/offline_relational_grant_path.py",
        "tests/agents/test_offline_relational_grant_path.py",
        "docs/offline-relational-grant-path.md",
    ),
    (
        "AOE-GB-D07-S03",
        "army.gb.d07.s03",
        "IW2-003",
        "supplied_graph_tenant_routes",
        "src/sunderkey/offline_graph_tenant_routes.py",
        "tests/agents/test_offline_graph_tenant_routes.py",
        "docs/offline-graph-tenant-routes.md",
    ),
    (
        "AOE-GB-D07-S06",
        "army.gb.d07.s06",
        "IW2-006",
        "supplied_search_alias_projection",
        "src/sunderkey/offline_search_alias_projection.py",
        "tests/agents/test_offline_search_alias_projection.py",
        "docs/offline-search-alias-projection.md",
    ),
    (
        "AOE-GB-D07-S13",
        "army.gb.d07.s13",
        "IW2-013",
        "supplied_backup_chain_projection",
        "src/sunderkey/offline_backup_chain_projection.py",
        "tests/agents/test_offline_backup_chain_projection.py",
        "docs/offline-backup-chain-projection.md",
    ),
    (
        "AOE-GB-D07-S08",
        "army.gb.d07.s08",
        "IW2-008",
        "supplied_stream_offset_projection",
        "src/sunderkey/offline_stream_offset_projection.py",
        "tests/agents/test_offline_stream_offset_projection.py",
        "docs/offline-stream-offset-projection.md",
    ),
    (
        "AOE-GB-D07-S09",
        "army.gb.d07.s09",
        "IW2-009",
        "supplied_warehouse_lineage",
        "src/sunderkey/offline_warehouse_lineage.py",
        "tests/agents/test_offline_warehouse_lineage.py",
        "docs/offline-warehouse-lineage.md",
    ),
    (
        "AOE-GB-D07-S10",
        "army.gb.d07.s10",
        "IW2-010",
        "supplied_spark_job_plan",
        "src/sunderkey/offline_spark_job_plan.py",
        "tests/agents/test_offline_spark_job_plan.py",
        "docs/offline-spark-job-plan.md",
    ),
    (
        "AOE-GB-D07-S12",
        "army.gb.d07.s12",
        "IW2-012",
        "supplied_analytics_sharing",
        "src/sunderkey/offline_analytics_sharing.py",
        "tests/agents/test_offline_analytics_sharing.py",
        "docs/offline-analytics-sharing.md",
    ),
    (
        "AOE-GE-D23-S05",
        "army.ge.d23.s05",
        "IW2-019",
        "supplied_archive_member_paths",
        "src/sunderkey/offline_archive_member_paths.py",
        "tests/agents/test_offline_archive_member_paths.py",
        "docs/offline-archive-member-paths.md",
    ),
    (
        "AOE-GE-D23-S06",
        "army.ge.d23.s06",
        "IW2-020",
        "supplied_dns_scope_timeline",
        "src/sunderkey/offline_dns_scope_timeline.py",
        "tests/agents/test_offline_dns_scope_timeline.py",
        "docs/offline-dns-scope-timeline.md",
    ),
    (
        "AOE-GB-D07-S11",
        "army.gb.d07.s11",
        "IW2-011",
        "supplied_etl_watermark_projection",
        "src/sunderkey/offline_etl_watermark_projection.py",
        "tests/agents/test_offline_etl_watermark_projection.py",
        "docs/offline-etl-watermark-projection.md",
    ),
    (
        "AOE-GE-D23-S04",
        "army.ge.d23.s04",
        "IW2-018",
        "supplied_json_key_policy_differential",
        "src/sunderkey/offline_json_key_policy_differential.py",
        "tests/agents/test_offline_json_key_policy_differential.py",
        "docs/offline-json-key-policy-differential.md",
    ),
    (
        "AOE-GE-D23-S03",
        "army.ge.d23.s03",
        "IW2-017",
        "supplied_pickle_opcode_inventory",
        "src/sunderkey/offline_pickle_opcode_inventory.py",
        "tests/agents/test_offline_pickle_opcode_inventory.py",
        "docs/offline-pickle-opcode-inventory.md",
    ),
    (
        "AOE-GE-D23-S07",
        "army.ge.d23.s07",
        "IW2-021",
        "supplied_cross_surface_authorization",
        "src/sunderkey/offline_cross_surface_authorization.py",
        "tests/agents/test_offline_cross_surface_authorization.py",
        "docs/offline-cross-surface-authorization.md",
    ),
    (
        "AOE-GE-D23-S08",
        "army.ge.d23.s08",
        "IW2-022",
        "supplied_cross_channel_session",
        "src/sunderkey/offline_cross_channel_session.py",
        "tests/agents/test_offline_cross_channel_session.py",
        "docs/offline-cross-channel-session.md",
    ),
    (
        "AOE-GE-D23-S09",
        "army.ge.d23.s09",
        "IW2-023",
        "supplied_request_origin_trust",
        "src/sunderkey/offline_request_origin_trust.py",
        "tests/agents/test_offline_request_origin_trust.py",
        "docs/offline-request-origin-trust.md",
    ),
    (
        "AOE-GE-D23-S10",
        "army.ge.d23.s10",
        "IW2-024",
        "supplied_toctou_state_schedule",
        "src/sunderkey/offline_toctou_state_schedule.py",
        "tests/agents/test_offline_toctou_state_schedule.py",
        "docs/offline-toctou-state-schedule.md",
    ),
    (
        "AOE-GE-D23-S11",
        "army.ge.d23.s11",
        "IW2-025",
        "supplied_resource_expansion_budget",
        "src/sunderkey/offline_resource_expansion_budget.py",
        "tests/agents/test_offline_resource_expansion_budget.py",
        "docs/offline-resource-expansion-budget.md",
    ),
    (
        "AOE-GE-D23-S12",
        "army.ge.d23.s12",
        "IW2-026",
        "supplied_dependency_fail_closed",
        "src/sunderkey/offline_dependency_fail_closed.py",
        "tests/agents/test_offline_dependency_fail_closed.py",
        "docs/offline-dependency-fail-closed.md",
    ),
    (
        "AOE-GE-D23-S13",
        "army.ge.d23.s13",
        "IW2-027",
        "supplied_configuration_defaults",
        "src/sunderkey/offline_configuration_defaults.py",
        "tests/agents/test_offline_configuration_defaults.py",
        "docs/offline-configuration-defaults.md",
    ),
    (
        "AOE-GE-D23-S14",
        "pattern.confused-deputy-trust-boundary",
        "IW2-028",
        "supplied_confused_deputy_boundary",
        "src/sunderkey/offline_confused_deputy_boundary.py",
        "tests/agents/test_offline_confused_deputy_boundary.py",
        "docs/offline-confused-deputy-boundary.md",
    ),
    (
        "AOE-GE-D23-S15",
        "army.ge.d23.s15",
        "IW2-029",
        "supplied_integrity_poisoning",
        "src/sunderkey/offline_integrity_poisoning.py",
        "tests/agents/test_offline_integrity_poisoning.py",
        "docs/offline-integrity-poisoning.md",
    ),
    (
        "AOE-GE-D23-S01",
        "army.ge.d23.s01",
        "IW2-015",
        "supplied_query_input_boundary",
        "src/sunderkey/offline_query_input_boundary.py",
        "tests/agents/test_offline_query_input_boundary.py",
        "docs/offline-query-input-boundary.md",
    ),
    (
        "AOE-GE-D23-S02",
        "army.ge.d23.s02",
        "IW2-016",
        "supplied_interpreter_input_boundary",
        "src/sunderkey/offline_interpreter_input_boundary.py",
        "tests/agents/test_offline_interpreter_input_boundary.py",
        "docs/offline-interpreter-input-boundary.md",
    ),
    (
        "AOE-GE-D23-S16",
        "army.ge.d23.s16",
        "IW2-030",
        "supplied_observable_discrepancy",
        "src/sunderkey/offline_observable_discrepancy.py",
        "tests/agents/test_offline_observable_discrepancy.py",
        "docs/offline-observable-discrepancy.md",
    ),
    (
        "AOE-GC-D14-S11",
        "army.gc.d14.s11",
        "IW2-014",
        "s3_supplied_public_grant_controls",
        "src/sunderkey/offline_s3_public_grant_controls.py",
        "tests/agents/test_offline_s3_public_grant_controls.py",
        "docs/offline-s3-public-grant-controls.md",
    ),
    (
        "AOE-GB-D10-S07",
        "army.gb.d10.s07",
        "IW2-007",
        "evm_supplied_proxy_storage_layout",
        "src/sunderkey/offline_proxy_storage_layout.py",
        "tests/agents/test_offline_proxy_storage_layout.py",
        "docs/offline-proxy-storage-layout.md",
    ),
    (
        "AOE-GB-D10-S08",
        "army.gb.d10.s08",
        "IW2-008",
        "evm_supplied_callback_state_order",
        "src/sunderkey/offline_reentrancy_state_order.py",
        "tests/agents/test_offline_reentrancy_state_order.py",
        "docs/offline-reentrancy-state-order.md",
    ),
    (
        "AOE-GB-D10-S03",
        "army.gb.d10.s03",
        "IW2-003",
        "defi_supplied_spot_twap_deviation",
        "src/sunderkey/offline_oracle_twap_deviation.py",
        "tests/agents/test_offline_oracle_twap_deviation.py",
        "docs/offline-oracle-twap-deviation.md",
    ),
    (
        "AOE-GB-D10-S04",
        "army.gb.d10.s04",
        "IW2-004",
        "bridge_supplied_duplicate_accepted_claims",
        "src/sunderkey/offline_bridge_claim_replay.py",
        "tests/agents/test_offline_bridge_claim_replay.py",
        "docs/offline-bridge-claim-replay.md",
    ),
    (
        "AOE-GB-D10-S11",
        "army.gb.d10.s11",
        "IW2-011",
        "governance_supplied_quorum_reconciliation",
        "src/sunderkey/offline_governance_quorum_reconciliation.py",
        "tests/agents/test_offline_governance_quorum_reconciliation.py",
        "docs/offline-governance-quorum-reconciliation.md",
    ),
    (
        "AOE-GB-D10-S05",
        "army.gb.d10.s05",
        "IW2-005",
        "consensus_supplied_conflicting_validator_votes",
        "src/sunderkey/offline_consensus_vote_equivocation.py",
        "tests/agents/test_offline_consensus_vote_equivocation.py",
        "docs/offline-consensus-vote-equivocation.md",
    ),
    (
        "AOE-GB-D10-S06",
        "army.gb.d10.s06",
        "IW2-006",
        "wallet_supplied_signer_threshold_authorization",
        "src/sunderkey/offline_wallet_threshold_authorization.py",
        "tests/agents/test_offline_wallet_threshold_authorization.py",
        "docs/offline-wallet-threshold-authorization.md",
    ),
    (
        "AOE-GB-D10-S12",
        "army.gb.d10.s12",
        "IW2-012",
        "rpc_supplied_cross_endpoint_response_discrepancy",
        "src/sunderkey/offline_rpc_response_discrepancy.py",
        "tests/agents/test_offline_rpc_response_discrepancy.py",
        "docs/offline-rpc-response-discrepancy.md",
    ),
    (
        "AOE-GB-D10-S01",
        "army.gb.d10.s01",
        "IW2-001",
        "evm_supplied_origin_authorization_boundary",
        "src/sunderkey/offline_evm_origin_authorization.py",
        "tests/agents/test_offline_evm_origin_authorization.py",
        "docs/offline-evm-origin-authorization.md",
    ),
    (
        "AOE-GB-D10-S02",
        "army.gb.d10.s02",
        "IW2-002",
        "wasm_supplied_host_import_allowlist",
        "src/sunderkey/offline_wasm_host_import_boundary.py",
        "tests/agents/test_offline_wasm_host_import_boundary.py",
        "docs/offline-wasm-host-import-boundary.md",
    ),
    (
        "AOE-GB-D10-S09",
        "army.gb.d10.s09",
        "IW2-009",
        "token_supplied_zero_fee_transfer_arithmetic",
        "src/sunderkey/offline_token_transfer_arithmetic.py",
        "tests/agents/test_offline_token_transfer_arithmetic.py",
        "docs/offline-token-transfer-arithmetic.md",
    ),
    (
        "AOE-GB-D10-S10",
        "army.gb.d10.s10",
        "IW2-010",
        "mev_supplied_outer_trade_order_pattern",
        "src/sunderkey/offline_mev_trade_order_pattern.py",
        "tests/agents/test_offline_mev_trade_order_pattern.py",
        "docs/offline-mev-trade-order-pattern.md",
    ),
    (
        "AOE-GC-D14-S12",
        "army.gc.d14.s12",
        "IW2-015",
        "cloud_supplied_private_endpoint_path_scope",
        "src/sunderkey/offline_private_endpoint_path.py",
        "tests/agents/test_offline_private_endpoint_path.py",
        "docs/offline-private-endpoint-path.md",
    ),
    (
        "AOE-GC-D14-S13",
        "army.gc.d14.s13",
        "IW2-016",
        "cloud_supplied_kms_grant_separation",
        "src/sunderkey/offline_kms_grant_separation.py",
        "tests/agents/test_offline_kms_grant_separation.py",
        "docs/offline-kms-grant-separation.md",
    ),
    (
        "AOE-GC-D14-S14",
        "army.gc.d14.s14",
        "IW2-017",
        "cloud_supplied_unalerted_logging_disable",
        "src/sunderkey/offline_cloud_logging_guardrail_timeline.py",
        "tests/agents/test_offline_cloud_logging_guardrail_timeline.py",
        "docs/offline-cloud-logging-guardrail-timeline.md",
    ),
    (
        "AOE-GC-D14-S19",
        "army.gc.d14.s19",
        "IW2-001",
        "workspace_supplied_external_sharing_policy",
        "src/sunderkey/offline_workspace_external_sharing.py",
        "tests/agents/test_offline_workspace_external_sharing.py",
        "docs/offline-workspace-external-sharing.md",
    ),
    (
        "AOE-GC-D14-S02",
        "army.gc.d14.s02",
        "IW2-005",
        "compute_supplied_private_ingress_scope",
        "src/sunderkey/offline_compute_ingress_scope.py",
        "tests/agents/test_offline_compute_ingress_scope.py",
        "docs/offline-compute-ingress-scope.md",
    ),
    (
        "AOE-GC-D14-S16",
        "army.gc.d14.s16",
        "IW2-019",
        "managed_paas_supplied_grant_scope",
        "src/sunderkey/offline_managed_paas_grant_scope.py",
        "tests/agents/test_offline_managed_paas_grant_scope.py",
        "docs/offline-managed-paas-grant-scope.md",
    ),
    (
        "AOE-GC-D14-S20",
        "army.gc.d14.s20",
        "IW2-002",
        "idp_supplied_privileged_mfa_path_policy",
        "src/sunderkey/offline_workforce_idp_mfa_paths.py",
        "tests/agents/test_offline_workforce_idp_mfa_paths.py",
        "docs/offline-workforce-idp-mfa-paths.md",
    ),
    (
        "AOE-GC-D14-S21",
        "army.gc.d14.s21",
        "IW2-003",
        "data_cloud_supplied_grant_scope_policy",
        "src/sunderkey/offline_data_cloud_grant_scope.py",
        "tests/agents/test_offline_data_cloud_grant_scope.py",
        "docs/offline-data-cloud-grant-scope.md",
    ),
    (
        "AOE-GD-D19-S17",
        "army.gd.d19.s17",
        "IW2-001",
        "bacnet_supplied_device_identifier_collision",
        "src/sunderkey/offline_bacnet_device_identity.py",
        "tests/agents/test_offline_bacnet_device_identity.py",
        "docs/offline-bacnet-device-identity.md",
    ),
    (
        "AOE-GD-D19-S18",
        "army.gd.d19.s18",
        "IW2-002",
        "ros2_supplied_security_declaration_gap",
        "src/sunderkey/offline_ros2_security_declaration.py",
        "tests/agents/test_offline_ros2_security_declaration.py",
        "docs/offline-ros2-security-declaration.md",
    ),
    (
        "AOE-GD-D19-S19",
        "army.gd.d19.s19",
        "IW2-003",
        "iec61850_supplied_subscription_reference_consistency",
        "src/sunderkey/offline_iec61850_subscription_refs.py",
        "tests/agents/test_offline_iec61850_subscription_refs.py",
        "docs/offline-iec61850-subscription-refs.md",
    ),
    (
        "AOE-GD-D19-S20",
        "army.gd.d19.s20",
        "IW2-004",
        "cip_supplied_security_property_gap",
        "src/sunderkey/offline_cip_security_declaration.py",
        "tests/agents/test_offline_cip_security_declaration.py",
        "docs/offline-cip-security-declaration.md",
    ),
    (
        "AOE-GD-D24-S01",
        "army.gd.d24.s01",
        "IW2-001",
        "acpi_supplied_table_integrity",
        "src/sunderkey/offline_acpi_table_integrity.py",
        "tests/agents/test_offline_acpi_table_integrity.py",
        "docs/offline-acpi-table-integrity.md",
    ),
    (
        "AOE-GD-D24-S02",
        "army.gd.d24.s02",
        "IW2-002",
        "redfish_supplied_role_privilege_ceiling",
        "src/sunderkey/offline_redfish_role_privileges.py",
        "tests/agents/test_offline_redfish_role_privileges.py",
        "docs/offline-redfish-role-privileges.md",
    ),
    (
        "AOE-GD-D24-S03",
        "army.gd.d24.s03",
        "IW2-003",
        "usb_supplied_descriptor_framing",
        "src/sunderkey/offline_usb_descriptor_framing.py",
        "tests/agents/test_offline_usb_descriptor_framing.py",
        "docs/offline-usb-descriptor-framing.md",
    ),
    (
        "AOE-GD-D24-S04",
        "army.gd.d24.s04",
        "IW2-004",
        "iommu_supplied_group_separation",
        "src/sunderkey/offline_iommu_group_separation.py",
        "tests/agents/test_offline_iommu_group_separation.py",
        "docs/offline-iommu-group-separation.md",
    ),
    (
        "AOE-GD-D19-S01",
        "army.gd.d19.s01",
        "IW2-011",
        "ot_supplied_zone_conduit_flow_projection",
        "src/sunderkey/offline_ot_zone_conduit_projection.py",
        "tests/agents/test_offline_ot_zone_conduit_projection.py",
        "docs/offline-ot-zone-conduit-projection.md",
    ),
    (
        "AOE-GD-D24-S06",
        "army.gd.d24.s06",
        "IW2-006",
        "gpu_supplied_instance_tenant_boundary",
        "src/sunderkey/offline_gpu_instance_tenant_boundary.py",
        "tests/agents/test_offline_gpu_instance_tenant_boundary.py",
        "docs/offline-gpu-instance-tenant-boundary.md",
    ),
    (
        "AOE-GD-D24-S07",
        "army.gd.d24.s07",
        "IW2-007",
        "riscv_supplied_pmp_interval_projection",
        "src/sunderkey/offline_riscv_pmp_projection.py",
        "tests/agents/test_offline_riscv_pmp_projection.py",
        "docs/offline-riscv-pmp-projection.md",
    ),
    (
        "AOE-GD-D24-S08",
        "army.gd.d24.s08",
        "IW2-008",
        "tpm_supplied_sha256_pcr_replay",
        "src/sunderkey/offline_tpm_pcr_replay.py",
        "tests/agents/test_offline_tpm_pcr_replay.py",
        "docs/offline-tpm-pcr-replay.md",
    ),
    (
        "AOE-GD-D24-S05",
        "army.gd.d24.s05",
        "IW2-005",
        "gpu_supplied_management_node_permissions",
        "src/sunderkey/offline_gpu_management_node_permissions.py",
        "tests/agents/test_offline_gpu_management_node_permissions.py",
        "docs/offline-gpu-management-node-permissions.md",
    ),
    (
        "AOE-GD-D24-S09",
        "army.gd.d24.s09",
        "IW2-009",
        "esrt_supplied_device_firmware_version_projection",
        "src/sunderkey/offline_firmware_update_metadata.py",
        "tests/agents/test_offline_firmware_update_metadata.py",
        "docs/offline-firmware-update-metadata.md",
    ),
    (
        "AOE-GD-D24-S10",
        "army.gd.d24.s10",
        "IW2-010",
        "amt_supplied_control_state_policy",
        "src/sunderkey/offline_management_engine_state.py",
        "tests/agents/test_offline_management_engine_state.py",
        "docs/offline-management-engine-state.md",
    ),
    (
        "AOE-GD-D19-S15",
        "army.gd.d19.s15",
        "IW2-025",
        "ot_supplied_remote_access_policy_projection",
        "src/sunderkey/offline_ot_remote_access_policy.py",
        "tests/agents/test_offline_ot_remote_access_policy.py",
        "docs/offline-ot-remote-access-policy.md",
    ),
    (
        "AOE-GD-D18-S01",
        "army.gd.d18.s01",
        "IW2-005",
        "firmware_supplied_inventory_sbom_claim_reconciliation",
        "src/sunderkey/offline_firmware_inventory_sbom.py",
        "tests/agents/test_offline_firmware_inventory_sbom.py",
        "docs/offline-firmware-inventory-sbom.md",
    ),
    (
        "AOE-GD-D18-S03",
        "army.gd.d18.s03",
        "IW2-007",
        "secure_boot_supplied_update_chain_projection",
        "src/sunderkey/offline_secure_boot_update_chain.py",
        "tests/agents/test_offline_secure_boot_update_chain.py",
        "docs/offline-secure-boot-update-chain.md",
    ),
    (
        "AOE-GC-D15-S01",
        "army.gc.d15.s01",
        "IW2-003",
        "oci_supplied_image_layer_metadata",
        "src/sunderkey/offline_oci_image_layers.py",
        "tests/agents/test_offline_oci_image_layers.py",
        "docs/offline-oci-image-layers.md",
    ),
    (
        "AOE-GA-D04-S17",
        "army.ga.d04.s17",
        "IW2-001",
        "supplied_third_party_trust_path_projection",
        "src/sunderkey/offline_third_party_trust_paths.py",
        "tests/agents/test_offline_third_party_trust_paths.py",
        "docs/offline-third-party-trust-paths.md",
    ),
    (
        "AOE-GC-D11-S04",
        "army.gc.d11.s04",
        "IW2-004",
        "adcs_supplied_template_rights_projection",
        "src/sunderkey/offline_adcs_template_rights.py",
        "tests/agents/test_offline_adcs_template_rights.py",
        "docs/offline-adcs-template-rights.md",
    ),
    (
        "AOE-GD-D25-S01",
        "army.gd.d25.s01",
        "IW2-001",
        "vehicle_supplied_gateway_flow_projection",
        "src/sunderkey/offline_vehicle_gateway_graph.py",
        "tests/agents/test_offline_vehicle_gateway_graph.py",
        "docs/offline-vehicle-gateway-graph.md",
    ),
    (
        "AOE-GD-D25-S02",
        "army.gd.d25.s02",
        "IW2-002",
        "vehicle_supplied_diagnostic_policy_projection",
        "src/sunderkey/offline_vehicle_diagnostic_policy.py",
        "tests/agents/test_offline_vehicle_diagnostic_policy.py",
        "docs/offline-vehicle-diagnostic-policy.md",
    ),
    (
        "AOE-GD-D25-S03",
        "army.gd.d25.s03",
        "IW2-003",
        "vehicle_supplied_service_zone_declarations",
        "src/sunderkey/offline_vehicle_service_declarations.py",
        "tests/agents/test_offline_vehicle_service_declarations.py",
        "docs/offline-vehicle-service-declarations.md",
    ),
    (
        "AOE-GC-D15-S03",
        "army.gc.d15.s03",
        "IW2-005",
        "kubernetes_supplied_api_authentication_context",
        "src/sunderkey/offline_kubernetes_api_authentication.py",
        "tests/agents/test_offline_kubernetes_api_authentication.py",
        "docs/offline-kubernetes-api-authentication.md",
    ),
    (
        "AOE-GC-D15-S09",
        "army.gc.d15.s09",
        "IW2-011",
        "kubernetes_supplied_secret_configmap_references",
        "src/sunderkey/offline_kubernetes_secret_references.py",
        "tests/agents/test_offline_kubernetes_secret_references.py",
        "docs/offline-kubernetes-secret-references.md",
    ),
    (
        "AOE-GC-D15-S11",
        "army.gc.d15.s11",
        "IW2-013",
        "oci_supplied_registry_signature_bindings",
        "src/sunderkey/offline_oci_registry_signature_bindings.py",
        "tests/agents/test_offline_oci_registry_signature_bindings.py",
        "docs/offline-oci-registry-signature-bindings.md",
    ),
    (
        "AOE-GC-D15-S12",
        "army.gc.d15.s12",
        "IW2-014",
        "kubernetes_supplied_runtime_reconciliation",
        "src/sunderkey/offline_kubernetes_runtime_reconciliation.py",
        "tests/agents/test_offline_kubernetes_runtime_reconciliation.py",
        "docs/offline-kubernetes-runtime-reconciliation.md",
    ),
    (
        "AOE-GC-D15-S02",
        "army.gc.d15.s02",
        "IW2-004",
        "container_supplied_runtime_declarations",
        "src/sunderkey/offline_container_runtime_declarations.py",
        "tests/agents/test_offline_container_runtime_declarations.py",
        "docs/offline-container-runtime-declarations.md",
    ),
    (
        "AOE-GC-D15-S06",
        "army.gc.d15.s06",
        "IW2-008",
        "kubernetes_supplied_control_plane_declarations",
        "src/sunderkey/offline_kubernetes_control_plane_declarations.py",
        "tests/agents/test_offline_kubernetes_control_plane_declarations.py",
        "docs/offline-kubernetes-control-plane-declarations.md",
    ),
    (
        "AOE-GC-D15-S10",
        "army.gc.d15.s10",
        "IW2-012",
        "supplied_container_boundary_path_projection",
        "src/sunderkey/offline_container_boundary_path_declarations.py",
        "tests/agents/test_offline_container_boundary_path_declarations.py",
        "docs/offline-container-boundary-path-declarations.md",
    ),
    (
        "AOE-GC-D15-S13",
        "army.gc.d15.s13",
        "IW2-015",
        "serverless_supplied_function_event_bindings",
        "src/sunderkey/offline_serverless_event_declarations.py",
        "tests/agents/test_offline_serverless_event_declarations.py",
        "docs/offline-serverless-event-declarations.md",
    ),
    (
        "AOE-GC-D15-S14",
        "army.gc.d15.s14",
        "IW2-016",
        "multicluster_supplied_tenant_declarations",
        "src/sunderkey/offline_multicluster_tenant_declarations.py",
        "tests/agents/test_offline_multicluster_tenant_declarations.py",
        "docs/offline-multicluster-tenant-declarations.md",
    ),
    (
        "AOE-GC-D11-S02",
        "army.gc.d11.s02",
        "IW2-002",
        "supplied_kerberos_ad_declarations",
        "src/sunderkey/offline_kerberos_ad_declarations.py",
        "tests/agents/test_offline_kerberos_ad_declarations.py",
        "docs/offline-kerberos-ad-declarations.md",
    ),
    (
        "AOE-GC-D11-S03",
        "army.gc.d11.s03",
        "IW2-003",
        "supplied_ntlm_control_pairs",
        "src/sunderkey/offline_ntlm_control_pairs.py",
        "tests/agents/test_offline_ntlm_control_pairs.py",
        "docs/offline-ntlm-control-pairs.md",
    ),
    (
        "AOE-GC-D11-S07",
        "army.gc.d11.s07",
        "IW2-007",
        "supplied_dc_topology_declarations",
        "src/sunderkey/offline_dc_topology_declarations.py",
        "tests/agents/test_offline_dc_topology_declarations.py",
        "docs/offline-dc-topology-declarations.md",
    ),
    (
        "AOE-GC-D11-S17",
        "army.gc.d11.s17",
        "IW2-017",
        "supplied_hybrid_identity_mappings",
        "src/sunderkey/offline_hybrid_identity_mappings.py",
        "tests/agents/test_offline_hybrid_identity_mappings.py",
        "docs/offline-hybrid-identity-mappings.md",
    ),
    (
        "AOE-GC-D14-S08",
        "army.gc.d14.s08",
        "IW2-011",
        "secondary_cloud_supplied_control_declarations",
        "src/sunderkey/offline_secondary_cloud_control_declarations.py",
        "tests/agents/test_offline_secondary_cloud_control_declarations.py",
        "docs/offline-secondary-cloud-control-declarations.md",
    ),
    (
        "AOE-GC-D14-S15",
        "army.gc.d14.s15",
        "IW2-018",
        "cloud_org_supplied_support_billing_boundary",
        "src/sunderkey/offline_cloud_org_support_billing_boundary.py",
        "tests/agents/test_offline_cloud_org_support_billing_boundary.py",
        "docs/offline-cloud-org-support-billing-boundary.md",
    ),
    (
        "AOE-GC-D14-S17",
        "army.gc.d14.s17",
        "IW2-020",
        "saas_supplied_tenant_admin_delegation",
        "src/sunderkey/offline_enterprise_saas_admin_delegation.py",
        "tests/agents/test_offline_enterprise_saas_admin_delegation.py",
        "docs/offline-enterprise-saas-admin-delegation.md",
    ),
    (
        "AOE-GC-D14-S18",
        "army.gc.d14.s18",
        "IW2-021",
        "cloud_supplied_post_compromise_control_timeline",
        "src/sunderkey/offline_cloud_post_compromise_timeline.py",
        "tests/agents/test_offline_cloud_post_compromise_timeline.py",
        "docs/offline-cloud-post-compromise-timeline.md",
    ),
    (
        "AOE-GD-D19-S02",
        "army.gd.d19.s02",
        "IW2-012",
        "ot_supplied_controller_configuration",
        "src/sunderkey/offline_ot_controller_configuration.py",
        "tests/agents/test_offline_ot_controller_configuration.py",
        "docs/offline-ot-controller-configuration.md",
    ),
    (
        "AOE-GD-D19-S03",
        "army.gd.d19.s03",
        "IW2-013",
        "ot_supplied_hmi_tag_mapping",
        "src/sunderkey/offline_ot_hmi_tag_mapping.py",
        "tests/agents/test_offline_ot_hmi_tag_mapping.py",
        "docs/offline-ot-hmi-tag-mapping.md",
    ),
    (
        "AOE-GD-D19-S04",
        "army.gd.d19.s04",
        "IW2-014",
        "ot_supplied_engineering_project_provenance",
        "src/sunderkey/offline_ot_engineering_project_provenance.py",
        "tests/agents/test_offline_ot_engineering_project_provenance.py",
        "docs/offline-ot-engineering-project-provenance.md",
    ),
    (
        "AOE-GD-D18-S02",
        "army.gd.d18.s02",
        "IW2-006",
        "firmware_supplied_emulation_trace_projection",
        "src/sunderkey/offline_firmware_emulation_trace.py",
        "tests/agents/test_offline_firmware_emulation_trace.py",
        "docs/offline-firmware-emulation-trace.md",
    ),
    (
        "AOE-GD-D18-S04",
        "army.gd.d18.s04",
        "IW2-008",
        "firmware_supplied_rtos_task_policy_projection",
        "src/sunderkey/offline_firmware_rtos_task_policy.py",
        "tests/agents/test_offline_firmware_rtos_task_policy.py",
        "docs/offline-firmware-rtos-task-policy.md",
    ),
    (
        "AOE-GD-D18-S05",
        "army.gd.d18.s05",
        "IW2-009",
        "firmware_supplied_debug_interface_inventory_projection",
        "src/sunderkey/offline_firmware_debug_interface_inventory.py",
        "tests/agents/test_offline_firmware_debug_interface_inventory.py",
        "docs/offline-firmware-debug-interface-inventory.md",
    ),
    (
        "AOE-GD-D18-S10",
        "army.gd.d18.s10",
        "IW2-014",
        "firmware_supplied_secure_element_assertions_projection",
        "src/sunderkey/offline_firmware_secure_element_assertions.py",
        "tests/agents/test_offline_firmware_secure_element_assertions.py",
        "docs/offline-firmware-secure-element-assertions.md",
    ),
    (
        "AOE-GD-D18-S16",
        "army.gd.d18.s16",
        "IW2-020",
        "firmware_supplied_tamper_provenance_projection",
        "src/sunderkey/offline_firmware_tamper_provenance.py",
        "tests/agents/test_offline_firmware_tamper_provenance.py",
        "docs/offline-firmware-tamper-provenance.md",
    ),
    (
        "AOE-GA-D03-S13",
        "identity.authorization.rbac-abac-rebac",
        "IW2-014",
        "identity_supplied_authorization_model_projection",
        "src/sunderkey/offline_authorization_model_projection.py",
        "tests/agents/test_offline_authorization_model_projection.py",
        "docs/offline-authorization-model-projection.md",
    ),
    (
        "AOE-GA-D03-S12",
        "army.ga.d03.s12",
        "IW2-013",
        "identity_supplied_jit_privilege_windows",
        "src/sunderkey/offline_jit_privilege_windows.py",
        "tests/agents/test_offline_jit_privilege_windows.py",
        "docs/offline-jit-privilege-windows.md",
    ),
    (
        "AOE-GA-D03-S11",
        "army.ga.d03.s11",
        "IW2-012",
        "identity_supplied_service_secret_lifecycle",
        "src/sunderkey/offline_service_secret_lifecycle.py",
        "tests/agents/test_offline_service_secret_lifecycle.py",
        "docs/offline-service-secret-lifecycle.md",
    ),
    (
        "AOE-GA-D03-S10",
        "army.ga.d03.s10",
        "IW2-011",
        "identity_supplied_spiffe_id_trust_projection",
        "src/sunderkey/offline_spiffe_id_trust_projection.py",
        "tests/agents/test_offline_spiffe_id_trust_projection.py",
        "docs/offline-spiffe-id-trust-projection.md",
    ),
    (
        "AOE-GA-D03-S09",
        "army.ga.d03.s09",
        "IW2-010",
        "identity_supplied_guest_trust_projection",
        "src/sunderkey/offline_guest_trust_projection.py",
        "tests/agents/test_offline_guest_trust_projection.py",
        "docs/offline-guest-trust-projection.md",
    ),
    (
        "AOE-GA-D03-S07",
        "army.ga.d03.s07",
        "IW2-008",
        "identity_supplied_certificate_auth_metadata",
        "src/sunderkey/offline_certificate_auth_metadata.py",
        "tests/agents/test_offline_certificate_auth_metadata.py",
        "docs/offline-certificate-auth-metadata.md",
    ),
    (
        "AOE-GA-D03-S06",
        "army.ga.d03.s06",
        "IW2-007",
        "identity_supplied_kerberos_realm_path",
        "src/sunderkey/offline_kerberos_realm_path.py",
        "tests/agents/test_offline_kerberos_realm_path.py",
        "docs/offline-kerberos-realm-path.md",
    ),
    (
        "AOE-GA-D03-S01",
        "army.ga.d03.s01",
        "IW2-002",
        "identity_supplied_password_lockout_timeline",
        "src/sunderkey/offline_password_lockout_timeline.py",
        "tests/agents/test_offline_password_lockout_timeline.py",
        "docs/offline-password-lockout-timeline.md",
    ),
    (
        "AOE-GA-D03-S02",
        "army.ga.d03.s02",
        "IW2-003",
        "identity_supplied_mfa_factor_rebind",
        "src/sunderkey/offline_mfa_factor_rebind.py",
        "tests/agents/test_offline_mfa_factor_rebind.py",
        "docs/offline-mfa-factor-rebind.md",
    ),
    (
        "AOE-GA-D03-S17",
        "army.ga.d03.s17",
        "IW2-001",
        "identity_supplied_biometric_assurance_projection",
        "src/sunderkey/offline_biometric_assurance_projection.py",
        "tests/agents/test_offline_biometric_assurance_projection.py",
        "docs/offline-biometric-assurance-projection.md",
    ),
    (
        "AOE-GA-D01-S01",
        "army.ga.d01.s01",
        "IW2-001",
        "recon_supplied_passive_source_freshness",
        "src/sunderkey/offline_passive_source_freshness.py",
        "tests/agents/test_offline_passive_source_freshness.py",
        "docs/offline-passive-source-freshness.md",
    ),
    (
        "AOE-GA-D01-S09",
        "army.ga.d01.s09",
        "IW2-009",
        "recon_supplied_organization_relationship_provenance",
        "src/sunderkey/offline_organization_relationship_provenance.py",
        "tests/agents/test_offline_organization_relationship_provenance.py",
        "docs/offline-organization-relationship-provenance.md",
    ),
    (
        "AOE-GE-D22-S04",
        "army.ge.d22.s04",
        "IW2-017",
        "crypto_supplied_kdf_policy_comparison",
        "src/sunderkey/offline_kdf_policy_comparison.py",
        "tests/agents/test_offline_kdf_policy_comparison.py",
        "docs/offline-kdf-policy-comparison.md",
    ),
    (
        "AOE-GE-D22-S05",
        "army.ge.d22.s05",
        "IW2-018",
        "crypto_supplied_symmetric_nonce_reuse",
        "src/sunderkey/offline_symmetric_nonce_reuse.py",
        "tests/agents/test_offline_symmetric_nonce_reuse.py",
        "docs/offline-symmetric-nonce-reuse.md",
    ),
    (
        "AOE-GE-D22-S06",
        "army.ge.d22.s06",
        "IW2-019",
        "crypto_supplied_public_key_policy",
        "src/sunderkey/offline_public_key_policy.py",
        "tests/agents/test_offline_public_key_policy.py",
        "docs/offline-public-key-policy.md",
    ),
    (
        "AOE-GE-D22-S10",
        "army.ge.d22.s10",
        "IW2-023",
        "crypto_supplied_key_lifecycle_posture",
        "src/sunderkey/offline_key_lifecycle_posture.py",
        "tests/agents/test_offline_key_lifecycle_posture.py",
        "docs/offline-key-lifecycle-posture.md",
    ),
    (
        "AOE-GE-D22-S11",
        "army.ge.d22.s11",
        "IW2-024",
        "crypto_supplied_token_payload_views",
        "src/sunderkey/offline_token_payload_views.py",
        "tests/agents/test_offline_token_payload_views.py",
        "docs/offline-token-payload-views.md",
    ),
    (
        "AOE-GC-D13-S04",
        "army.gc.d13.s04",
        "IW2-007",
        "network_supplied_switch_vlan_projection",
        "src/sunderkey/offline_switch_vlan_projection.py",
        "tests/agents/test_offline_switch_vlan_projection.py",
        "docs/offline-switch-vlan-projection.md",
    ),
    (
        "AOE-GC-D13-S05",
        "network.boundary.firewall-proxy-vpn",
        "IW2-008",
        "network_supplied_firewall_rule_order",
        "src/sunderkey/offline_firewall_rule_order_projection.py",
        "tests/agents/test_offline_firewall_rule_order_projection.py",
        "docs/offline-firewall-rule-order-projection.md",
    ),
    (
        "AOE-GC-D13-S07",
        "army.gc.d13.s07",
        "IW2-010",
        "network_supplied_nac_admission_consistency",
        "src/sunderkey/offline_nac_admission_projection.py",
        "tests/agents/test_offline_nac_admission_projection.py",
        "docs/offline-nac-admission-projection.md",
    ),
    (
        "AOE-GC-D13-S08",
        "army.gc.d13.s08",
        "IW2-011",
        "network_supplied_wifi_policy_projection",
        "src/sunderkey/offline_wifi_policy_projection.py",
        "tests/agents/test_offline_wifi_policy_projection.py",
        "docs/offline-wifi-policy-projection.md",
    ),
    (
        "AOE-GC-D13-S15",
        "army.gc.d13.s15",
        "IW2-018",
        "network_supplied_snmp_view_projection",
        "src/sunderkey/offline_snmp_view_projection.py",
        "tests/agents/test_offline_snmp_view_projection.py",
        "docs/offline-snmp-view-projection.md",
    ),
    (
        "AOE-GC-D13-S21",
        "army.gc.d13.s21",
        "IW2-003",
        "network_supplied_sdwan_overlay_projection",
        "src/sunderkey/offline_sdwan_overlay_projection.py",
        "tests/agents/test_offline_sdwan_overlay_projection.py",
        "docs/offline-sdwan-overlay-projection.md",
    ),
)
PROFILE_DEFAULT_COMPONENTS = {
    "AOE-GE-D21-S08": "exploit_supplied_seccomp_bpf_subset_projection",
    "AOE-GD-D25-S11": "clinical_supplied_fhir_device_association_review",
    "AOE-GA-D02-S02": "social_supplied_passport_claim_review",
    "AOE-GD-D19-S07": "industrial_supplied_ot_vendor_support_map",
    "AOE-GA-D02-S04": "social_supplied_activitystreams_create_review",
    "AOE-GD-D19-S09": "industrial_supplied_power_recovery_cadence_review",
    "AOE-GA-D02-S13": "social_supplied_operator_offboarding_review",
    "AOE-GA-D02-S05": "social_supplied_mfa_registration_audit_review",
    "AOE-GA-D02-S09": "social_supplied_visitor_escort_record_review",
    "AOE-GA-D02-S10": "social_supplied_osdp_poll_frame_review",
    "AOE-GA-D02-S11": "social_supplied_windows_device_event_review",
    "AOE-GA-D02-S01": "social_supplied_email_auth_results_review",
    "AOE-GA-D02-S03": "social_supplied_sms_uri_review",
    "AOE-GA-D02-S06": "social_supplied_oauth_consent_uri_review",
    "AOE-GA-D02-S08": "social_supplied_ooxml_relationship_review",
    "AOE-GE-D21-S20": "exploit_supplied_pe_packing_triage",
    "AOE-GD-D19-S05": "industrial_supplied_sis_bpcs_resource_projection",
    "AOE-GE-D21-S07": "exploit_supplied_browser_minidump_directory",
    "AOE-GD-D25-S04": "transport_supplied_ocpp16_data_transfer_projection",
    "AOE-GD-D25-S07": "transport_supplied_ais_position_report_projection",
    "AOE-GD-D25-S08": "transport_supplied_ccsds_space_packet_projection",
    "AOE-GD-D25-S09": "transport_supplied_rinex_observation_header_projection",
    "AOE-GD-D25-S10": "transport_supplied_mavlink2_packet_envelope",
    "AOE-GD-D19-S12": "industrial_supplied_socketcan_classical_frame_projection",
    "AOE-GD-D18-S11": "hardware_supplied_cache_set_mapping_projection",
    "AOE-GE-D21-S06": "exploit_engineering_supplied_hexagon_elf32_layout",
    "AOE-GE-D21-S05": "exploit_engineering_supplied_apple_kernel_macho_markers",
    "AOE-GD-D18-S12": "hardware_supplied_yosys_netlist_structural_delta",
    "AOE-GE-D21-S04": "exploit_engineering_supplied_linux_module_info_projection",
    "AOE-GE-D21-S03": "exploit_engineering_supplied_windows_driver_pe_marker_projection",
    "AOE-GA-D04-S07": "campaign_supplied_privilege_transition_controls",
    "AOE-GD-D18-S14": "hardware_supplied_thread_mac_frame_control_projection",
    "AOE-GA-D04-S09": "campaign_supplied_path_review_checkpoint_projection",
    "AOE-GD-D18-S08": "hardware_supplied_trace_difference_projection",
    "AOE-GA-D04-S02": "campaign_supplied_initial_access_chain_controls",
    "AOE-GE-D21-S02": "exploit_engineering_supplied_aarch64_elf_section_permission_projection",
    "AOE-GE-D21-S01": "exploit_engineering_supplied_pe_section_permission_projection",
    "AOE-GB-D08-S02": "mobile_supplied_android_instrumentation_trace_projection",
    "AOE-GB-D08-S04": "mobile_supplied_android_device_trust_trace_projection",
    "AOE-GB-D08-S06": "mobile_supplied_ios_instrumentation_trace_projection",
    "AOE-GB-D08-S08": "mobile_supplied_ios_device_trust_trace_projection",
    "AOE-GD-D20-S09": "model_supplied_direct_instruction_boundary_projection",
    "AOE-GD-D20-S17": "model_supplied_multimodal_provenance_claim_projection",
    "AOE-GC-D16-S01": "legacy_supplied_zos_grant_policy_projection",
    "AOE-GC-D16-S02": "legacy_supplied_ibmi_grant_policy_projection",
    "AOE-GC-D16-S03": "legacy_supplied_unix_grant_policy_projection",
    "AOE-GC-D16-S04": "legacy_supplied_sap_grant_policy_projection",
    "AOE-GC-D16-S05": "legacy_supplied_oracle_grant_policy_projection",
    "AOE-GC-D13-S06": "telecom_supplied_appliance_management_relation_projection",
    "AOE-GC-D13-S10": "telecom_supplied_rf_receive_policy_projection",
    "AOE-GC-D13-S11": "telecom_supplied_mobile_core_relation_projection",
    "AOE-GC-D13-S12": "telecom_supplied_signaling_route_projection",
    "AOE-GC-D13-S19": "telecom_supplied_oran_policy_target_projection",
    "AOE-GC-D13-S20": "telecom_supplied_esim_profile_transition_projection",
    "AOE-GC-D12-S02": "linux_supplied_ebpf_helper_policy_projection",
    "AOE-GC-D12-S05": "linux_supplied_shell_tool_policy_projection",
    "AOE-GC-D12-S08": "linux_supplied_logging_route_policy_projection",
    "AOE-GC-D12-S09": "macos_supplied_privileged_item_policy_projection",
    "AOE-GC-D12-S10": "macos_supplied_security_control_policy_projection",
    "AOE-GC-D12-S11": "macos_supplied_launch_job_policy_projection",
    "AOE-GC-D12-S12": "macos_supplied_store_access_policy_projection",
    "AOE-GC-D12-S13": "macos_supplied_ipc_client_policy_projection",
    "AOE-GC-D12-S14": "unix_supplied_privileged_ipc_permission_projection",
    "AOE-GC-D11-S08": "windows_supplied_privilege_artifact_projection",
    "AOE-GC-D11-S09": "windows_supplied_autostart_policy_projection",
    "AOE-GC-D11-S10": "windows_supplied_admin_invocation_policy_projection",
    "AOE-GC-D11-S11": "windows_supplied_protected_material_access_projection",
    "AOE-GC-D11-S12": "windows_supplied_remote_route_policy_projection",
    "AOE-GC-D11-S13": "windows_supplied_security_control_state_projection",
    "AOE-GC-D11-S18": "windows_supplied_endpoint_assignment_policy_projection",
    "AOE-GC-D11-S16": "windows_supplied_collaboration_sharing_policy_projection",
    "AOE-GC-D11-S15": "windows_supplied_mailbox_forwarding_policy_projection",
    "AOE-GC-D12-S04": "linux_supplied_scheduled_artifact_policy_projection",
    "AOE-GC-D12-S07": "linux_supplied_namespace_cgroup_policy_projection",
    "AOE-GC-D12-S03": "linux_supplied_sudo_grant_policy_projection",
    "AOE-GA-D01-S02": "recon_supplied_scan_scope_projection",
    "AOE-GD-D18-S13": "hardware_supplied_smartcard_file_access_projection",
    "AOE-GD-D18-S07": "hardware_supplied_flash_region_map_projection",
    "AOE-GD-D18-S06": "hardware_supplied_i2c_write_frame_projection",
    "AOE-GC-D13-S09": "network_supplied_ble_gatt_permission_projection",
    "AOE-GC-D13-S18": "network_supplied_traffic_cadence_projection",
    "AOE-GC-D13-S13": "network_supplied_sip_dialog_sequence_projection",
    "AOE-GC-D13-S16": "network_supplied_adc_route_projection",
    "AOE-GB-D08-S16": "macos_supplied_release_metadata_consistency",
    "AOE-GB-D08-S11": "mobile_supplied_protection_coverage_projection",
    "AOE-GB-D08-S13": "desktop_supplied_ipc_boundary_projection",
    "AOE-GB-D08-S10": "mobile_supplied_storage_control_projection",
    "AOE-GB-D08-S14": "mobile_supplied_distribution_consistency_projection",
    "AOE-GB-D08-S09": "mobile_supplied_pinset_coverage_projection",
    "AOE-GE-D22-S14": "crypto_supplied_digest_vector_consistency",
    "AOE-GC-D13-S17": "network_supplied_protocol_trace_differential",
    "AOE-GE-D22-S12": "crypto_supplied_custom_protocol_framing",
    "AOE-GE-D22-S07": "crypto_supplied_hybrid_kem_lineage",
    "AOE-GE-D22-S09": "crypto_supplied_side_channel_timing_projection",
    "AOE-GE-D22-S01": "crypto_supplied_protocol_state_graph",
    "AOE-GE-D22-S13": "crypto_supplied_e2ee_epoch_membership",
    "AOE-GA-D04-S01": "campaign_supplied_threat_scenario_graph",
    "AOE-GE-D22-S08": "crypto_supplied_rng_sample_consistency",
    "AOE-GB-D06-S02": "graphql_query_structure",
    "AOE-GC-D15-S04": "kubernetes_rbac_supplied_model",
    "AOE-GC-D14-S01": "aws_organizations_supplied_scp_path",
    "AOE-GB-D06-S03": "protobuf_schema_evolution",
    "AOE-GE-D22-S03": "supplied_x509_chain_structure",
    "AOE-GB-D05-S03": "supplied_http_request_framing",
    "AOE-GC-D14-S04": "azure_rbac_supplied_model",
    "AOE-GB-D06-S04": "soap_document_literal_contract_instance",
    "AOE-GC-D14-S06": "gcp_iam_supplied_allow_model",
    "AOE-GA-D03-S05": "supplied_jose_signature_and_claims",
    "AOE-GB-D06-S01": "openapi_security_declaration_evolution",
    "AOE-GC-D11-S05": "windows_supplied_dacl_arithmetic",
    "AOE-GC-D15-S07": "kubernetes_supplied_network_policy_flows",
    "AOE-GC-D12-S01": "linux_supplied_posix_acl_arithmetic",
    "AOE-GC-D14-S03": "aws_supplied_vpc_flow_predicates",
    "AOE-GB-D07-S14": "postgresql_supplied_select_rls",
    "AOE-GB-D06-S05": "websocket_supplied_frame_state",
    "AOE-GC-D15-S05": "kubernetes_supplied_linux_pod_security_controls",
    "AOE-GB-D07-S05": "redis_supplied_acl_key_selectors",
    "AOE-GA-D01-S03": "dns_supplied_zone_lookup",
    "AOE-GC-D13-S03": "dns_supplied_wire_structure",
    "AOE-GB-D05-S14": "cors_supplied_negotiation_and_exposure",
    "AOE-GC-D17-S10": "oci_supplied_blob_graph_integrity",
    "AOE-GE-D22-S02": "tls13_supplied_hello_offer_selection",
    "AOE-GB-D05-S11": "retained_cookie_candidate_predicates",
    "AOE-GC-D17-S04": "javascript_supplied_semver_interval_arithmetic",
    "AOE-GB-D05-S02": "http_supplied_cache_freshness_arithmetic",
    "AOE-GC-D14-S05": "azure_supplied_nsg_directional_predicates",
    "AOE-GB-D08-S03": "android_supplied_component_declarations",
    "AOE-GC-D14-S07": "gcp_supplied_vpc_firewall_new_flow_predicates",
    "AOE-GB-D08-S07": "ios_supplied_entitlement_declaration_consistency",
    "AOE-GD-D18-S15": "mqtt_supplied_topic_filter_arithmetic",
    "AOE-GD-D19-S06": "modbus_supplied_tcp_read_exchange_structure",
    "AOE-GB-D08-S01": "android_supplied_dex035_structure",
    "AOE-GB-D08-S05": "ios_supplied_macho64_layout",
    "AOE-GB-D08-S17": "linux_supplied_elf64_layout",
    "AOE-GB-D08-S15": "windows_supplied_pe32plus_layout",
    "AOE-GA-D03-S08": "webauthn_supplied_assertion_context_arithmetic",
    "AOE-GC-D13-S14": "dkim_supplied_canonicalization_and_body_hash",
    "AOE-GC-D17-S01": "git_supplied_pack_ofs_delta_reconstruction",
    "AOE-GE-D21-S19": "wasm_supplied_numeric_stack_and_interfaces",
    "AOE-GE-D21-S13": "exploit_supplied_coverage_seed_selection",
    "AOE-GE-D21-S14": "exploit_supplied_finite_grammar_plan",
    "AOE-GE-D21-S15": "exploit_supplied_path_constraint_feasibility",
    "AOE-GE-D21-S16": "exploit_supplied_binary_reference_graph",
    "AOE-GE-D21-S17": "exploit_supplied_source_variant_tokens",
    "AOE-GE-D21-S11": "exploit_supplied_happens_before_conflicts",
    "AOE-GE-D21-S12": "exploit_supplied_integer_width_arithmetic",
    "AOE-GE-D21-S09": "exploit_supplied_heap_trace_consistency",
    "AOE-GE-D21-S18": "exploit_supplied_chain_trial_accounting",
    "AOE-GC-D12-S06": "ssh_supplied_kexinit_selection_arithmetic",
    "AOE-GC-D13-S01": "ipv4_supplied_fragment_relations_and_header_checksums",
    "AOE-GC-D13-S02": "bgp_supplied_update_structure",
    "AOE-GC-D17-S05": "wheel_supplied_zip_record_integrity",
    "AOE-GB-D07-S07": "amqp091_supplied_publish_content_assembly",
    "AOE-GB-D05-S01": "http_supplied_byte_range_arithmetic",
    "AOE-GA-D03-S03": "saml_supplied_conditions_audience_restrictions",
    "AOE-GD-D25-S12": "dicom_supplied_pdata_pdv_structure",
    "AOE-GA-D03-S04": "oauth_supplied_code_pkce_transcript",
    "AOE-GB-D06-S11": "api_supplied_property_authorization",
    "AOE-GB-D05-S04": "http_supplied_cache_key_differential",
    "AOE-GB-D06-S12": "api_supplied_content_type_differential",
    "AOE-GB-D06-S13": "api_supplied_rate_limit_projection",
    "AOE-GB-D05-S05": "https_supplied_url_navigation_projection",
    "AOE-GB-D06-S07": "api_supplied_gateway_route_selection",
    "AOE-GC-D14-S10": "workload_identity_supplied_trust_projection",
    "AOE-GC-D17-S02": "ci_supplied_workflow_trust_flow",
    "AOE-GA-D03-S15": "directory_supplied_lifecycle_projection",
    "AOE-GC-D17-S08": "dependency_supplied_resolution_collision",
    "AOE-GB-D06-S09": "api_supplied_object_authorization",
    "AOE-GB-D06-S10": "api_supplied_function_authorization_differential",
    "AOE-GB-D06-S14": "api_supplied_inventory_drift",
    "AOE-GB-D06-S15": "api_supplied_downstream_trust_flow",
    "AOE-GB-D05-S13": "dom_supplied_dataflow_projection",
    "AOE-GA-D01-S11": "supplied_attack_graph_model",
    "AOE-GB-D05-S12": "web_supplied_route_authorization",
    "AOE-GB-D05-S15": "browser_supplied_message_boundary_projection",
    "AOE-GB-D05-S10": "supplied_web_content_handling",
    "AOE-GB-D06-S06": "api_supplied_webhook_callback_trust",
    "AOE-GB-D06-S08": "api_supplied_service_mesh_trust_projection",
    "AOE-GB-D05-S09": "supplied_template_context",
    "AOE-GB-D06-S16": "api_supplied_partner_connector_trust_projection",
    "AOE-GB-D05-S16": "web_supplied_service_worker_scope",
    "AOE-GD-D20-S14": "agent_supplied_tool_authority_projection",
    "AOE-GD-D20-S13": "agent_supplied_output_handling_boundary",
    "AOE-GD-D20-S10": "agent_supplied_indirect_prompt_boundary",
    "AOE-GD-D20-S11": "rag_supplied_index_provenance",
    "AOE-GD-D20-S16": "agent_supplied_memory_provenance",
    "AOE-GD-D20-S07": "model_supplied_pickle_opcode_safety",
    "AOE-GD-D20-S08": "model_supplied_artifact_integrity",
    "AOE-GD-D20-S04": "model_supplied_evasion_delta_measurement",
    "AOE-GD-D20-S15": "agent_supplied_credential_boundary",
    "AOE-GD-D20-S01": "mlops_supplied_release_lineage",
    "AOE-GD-D20-S02": "training_supplied_label_share_drift",
    "AOE-GD-D20-S03": "model_supplied_trigger_selectivity",
    "AOE-GD-D20-S05": "model_supplied_output_similarity",
    "AOE-GD-D20-S06": "model_supplied_membership_score_separation",
    "AOE-GD-D20-S12": "model_supplied_prompt_canary_exposure",
    "AOE-GD-D20-S18": "agent_supplied_resource_budget",
    "AOE-GD-D20-S19": "agent_supplied_plan_revision_integrity",
    "AOE-GD-D20-S20": "multi_agent_supplied_coordination_trust",
    "AOE-GC-D17-S03": "cd_supplied_release_provenance",
    "AOE-GC-D16-S06": "hypervisor_supplied_management_posture_projection",
    "AOE-GC-D16-S07": "vdi_supplied_session_posture_projection",
    "AOE-GC-D16-S08": "backup_supplied_recovery_posture_projection",
    "AOE-GC-D16-S09": "storage_supplied_access_posture_projection",
    "AOE-GC-D16-S10": "enterprise_server_supplied_management_projection",
    "AOE-GC-D16-S11": "rmm_supplied_control_posture_projection",
    "AOE-GC-D16-S12": "hpc_supplied_queue_posture_projection",
    "AOE-GC-D17-S06": "managed_supplied_package_feed_projection",
    "AOE-GC-D17-S07": "native_supplied_target_compatibility_projection",
    "AOE-GC-D17-S09": "build_supplied_reproducibility_projection",
    "AOE-GC-D17-S11": "repository_supplied_secret_occurrence_projection",
    "AOE-GC-D17-S12": "iac_supplied_change_dependency_projection",
    "AOE-GC-D17-S13": "devcontainer_supplied_host_boundary_projection",
    "AOE-GC-D17-S14": "vendor_supplied_update_lineage_projection",
    "AOE-GC-D15-S08": "kubernetes_supplied_admission_policy_projection",
    "AOE-GC-D14-S09": "cloud_supplied_multicloud_federation_projection",
    "AOE-GB-D05-S06": "java_supplied_filter_mapping_boundary",
    "AOE-GB-D05-S07": "dotnet_supplied_middleware_order_boundary",
    "AOE-GB-D05-S08": "web_supplied_framework_stack_projection",
    "AOE-GB-D05-S17": "web_supplied_cms_permission_graph_projection",
    "AOE-GB-D05-S18": "browser_supplied_webrtc_signaling_projection",
    "AOE-GB-D07-S02": "data_supplied_nosql_access_grants_projection",
    "AOE-GB-D07-S04": "data_supplied_vector_tenant_boundary_projection",
    "AOE-GA-D03-S14": "identity_supplied_entitlement_toxic_combination",
    "AOE-GA-D03-S16": "identity_supplied_session_binding_timeline",
    "AOE-GB-D08-S12": "browser_supplied_webview_bridge_origin_projection",
    "AOE-GB-D08-S18": "desktop_supplied_electron_bridge_origin_projection",
    "AOE-GA-D01-S04": "supplied_prefix_origin_mapping",
    "AOE-GA-D01-S05": "supplied_cloud_inventory_drift",
    "AOE-GA-D01-S06": "supplied_saas_signal_correlation",
    "AOE-GA-D01-S08": "supplied_credential_exposure_review",
    "AOE-GA-D01-S07": "supplied_repository_reference_graph",
    "AOE-GA-D01-S10": "supplied_technology_evidence_reconciliation",
    "AOE-GA-D01-S12": "supplied_deception_cue_reconciliation",
    "AOE-GB-D09-S02": "supplied_price_rounding_arithmetic",
    "AOE-GB-D09-S03": "supplied_debit_idempotency_timeline",
    "AOE-GB-D09-S01": "supplied_workflow_state_replay",
    "AOE-GB-D09-S07": "supplied_coupon_redemption_timeline",
    "AOE-GB-D09-S11": "supplied_consent_purpose_timeline",
    "AOE-GB-D09-S05": "supplied_account_recovery_threshold",
    "AOE-GB-D09-S06": "supplied_tenant_ownership_reconciliation",
    "AOE-GB-D09-S08": "supplied_auction_bid_timeline",
    "AOE-GB-D09-S04": "supplied_payment_reversal_ledger",
    "AOE-GB-D09-S12": "supplied_cross_channel_balance",
    "AOE-GB-D09-S09": "supplied_scalping_window_review",
    "AOE-GB-D09-S10": "supplied_fraud_decision_review",
    "AOE-GC-D11-S01": "supplied_directory_entitlement_path",
    "AOE-GC-D11-S06": "supplied_directory_trust_paths",
    "AOE-GC-D11-S14": "supplied_entra_role_claim_review",
    "AOE-GC-D11-S02": "supplied_kerberos_ad_declarations",
    "AOE-GC-D11-S03": "supplied_ntlm_control_pairs",
    "AOE-GC-D11-S07": "supplied_dc_topology_declarations",
    "AOE-GC-D11-S17": "supplied_hybrid_identity_mappings",
    "AOE-GB-D07-S01": "supplied_relational_grant_path",
    "AOE-GB-D07-S03": "supplied_graph_tenant_routes",
    "AOE-GB-D07-S06": "supplied_search_alias_projection",
    "AOE-GB-D07-S13": "supplied_backup_chain_projection",
    "AOE-GB-D07-S08": "supplied_stream_offset_projection",
    "AOE-GB-D07-S09": "supplied_warehouse_lineage",
    "AOE-GB-D07-S10": "supplied_spark_job_plan",
    "AOE-GB-D07-S12": "supplied_analytics_sharing",
    "AOE-GE-D23-S05": "supplied_archive_member_paths",
    "AOE-GE-D23-S06": "supplied_dns_scope_timeline",
    "AOE-GB-D07-S11": "supplied_etl_watermark_projection",
    "AOE-GE-D23-S04": "supplied_json_key_policy_differential",
    "AOE-GE-D23-S03": "supplied_pickle_opcode_inventory",
    "AOE-GE-D23-S07": "supplied_cross_surface_authorization",
    "AOE-GE-D23-S08": "supplied_cross_channel_session",
    "AOE-GE-D23-S09": "supplied_request_origin_trust",
    "AOE-GE-D23-S10": "supplied_toctou_state_schedule",
    "AOE-GE-D23-S11": "supplied_resource_expansion_budget",
    "AOE-GE-D23-S12": "supplied_dependency_fail_closed",
    "AOE-GE-D23-S13": "supplied_configuration_defaults",
    "AOE-GE-D23-S14": "supplied_confused_deputy_boundary",
    "AOE-GE-D23-S15": "supplied_integrity_poisoning",
    "AOE-GE-D23-S01": "supplied_query_input_boundary",
    "AOE-GE-D23-S02": "supplied_interpreter_input_boundary",
    "AOE-GE-D23-S16": "supplied_observable_discrepancy",
    "AOE-GC-D14-S11": "s3_supplied_public_grant_controls",
    "AOE-GB-D10-S07": "evm_supplied_proxy_storage_layout",
    "AOE-GB-D10-S08": "evm_supplied_callback_state_order",
    "AOE-GB-D10-S03": "defi_supplied_spot_twap_deviation",
    "AOE-GB-D10-S04": "bridge_supplied_duplicate_accepted_claims",
    "AOE-GB-D10-S11": "governance_supplied_quorum_reconciliation",
    "AOE-GB-D10-S05": "consensus_supplied_conflicting_validator_votes",
    "AOE-GB-D10-S06": "wallet_supplied_signer_threshold_authorization",
    "AOE-GB-D10-S12": "rpc_supplied_cross_endpoint_response_discrepancy",
    "AOE-GB-D10-S01": "evm_supplied_origin_authorization_boundary",
    "AOE-GB-D10-S02": "wasm_supplied_host_import_allowlist",
    "AOE-GB-D10-S09": "token_supplied_zero_fee_transfer_arithmetic",
    "AOE-GB-D10-S10": "mev_supplied_outer_trade_order_pattern",
    "AOE-GC-D14-S12": "cloud_supplied_private_endpoint_path_scope",
    "AOE-GC-D14-S13": "cloud_supplied_kms_grant_separation",
    "AOE-GC-D14-S14": "cloud_supplied_unalerted_logging_disable",
    "AOE-GC-D14-S19": "workspace_supplied_external_sharing_policy",
    "AOE-GC-D14-S02": "compute_supplied_private_ingress_scope",
    "AOE-GC-D14-S16": "managed_paas_supplied_grant_scope",
    "AOE-GC-D14-S20": "idp_supplied_privileged_mfa_path_policy",
    "AOE-GC-D14-S21": "data_cloud_supplied_grant_scope_policy",
    "AOE-GC-D14-S08": "secondary_cloud_supplied_control_declarations",
    "AOE-GC-D14-S15": "cloud_org_supplied_support_billing_boundary",
    "AOE-GC-D14-S17": "saas_supplied_tenant_admin_delegation",
    "AOE-GC-D14-S18": "cloud_supplied_post_compromise_control_timeline",
    "AOE-GD-D19-S02": "ot_supplied_controller_configuration",
    "AOE-GD-D19-S03": "ot_supplied_hmi_tag_mapping",
    "AOE-GD-D19-S04": "ot_supplied_engineering_project_provenance",
    "AOE-GD-D18-S02": "firmware_supplied_emulation_trace_projection",
    "AOE-GD-D18-S04": "firmware_supplied_rtos_task_policy_projection",
    "AOE-GD-D18-S05": "firmware_supplied_debug_interface_inventory_projection",
    "AOE-GD-D18-S10": "firmware_supplied_secure_element_assertions_projection",
    "AOE-GD-D18-S16": "firmware_supplied_tamper_provenance_projection",
    "AOE-GD-D19-S17": "bacnet_supplied_device_identifier_collision",
    "AOE-GD-D19-S18": "ros2_supplied_security_declaration_gap",
    "AOE-GD-D19-S19": "iec61850_supplied_subscription_reference_consistency",
    "AOE-GD-D19-S20": "cip_supplied_security_property_gap",
    "AOE-GD-D24-S01": "acpi_supplied_table_integrity",
    "AOE-GD-D24-S02": "redfish_supplied_role_privilege_ceiling",
    "AOE-GD-D24-S03": "usb_supplied_descriptor_framing",
    "AOE-GD-D24-S04": "iommu_supplied_group_separation",
    "AOE-GD-D19-S01": "ot_supplied_zone_conduit_flow_projection",
    "AOE-GD-D24-S06": "gpu_supplied_instance_tenant_boundary",
    "AOE-GD-D24-S07": "riscv_supplied_pmp_interval_projection",
    "AOE-GD-D24-S08": "tpm_supplied_sha256_pcr_replay",
    "AOE-GD-D24-S05": "gpu_supplied_management_node_permissions",
    "AOE-GD-D24-S09": "esrt_supplied_device_firmware_version_projection",
    "AOE-GD-D24-S10": "amt_supplied_control_state_policy",
    "AOE-GD-D19-S15": "ot_supplied_remote_access_policy_projection",
    "AOE-GD-D18-S01": "firmware_supplied_inventory_sbom_claim_reconciliation",
    "AOE-GD-D18-S03": "secure_boot_supplied_update_chain_projection",
    "AOE-GC-D15-S01": "oci_supplied_image_layer_metadata",
    "AOE-GA-D04-S17": "supplied_third_party_trust_path_projection",
    "AOE-GC-D11-S04": "adcs_supplied_template_rights_projection",
    "AOE-GD-D25-S01": "vehicle_supplied_gateway_flow_projection",
    "AOE-GD-D25-S02": "vehicle_supplied_diagnostic_policy_projection",
    "AOE-GD-D25-S03": "vehicle_supplied_service_zone_declarations",
    "AOE-GC-D15-S03": "kubernetes_supplied_api_authentication_context",
    "AOE-GC-D15-S09": "kubernetes_supplied_secret_configmap_references",
    "AOE-GC-D15-S11": "oci_supplied_registry_signature_bindings",
    "AOE-GC-D15-S12": "kubernetes_supplied_runtime_reconciliation",
    "AOE-GC-D15-S02": "container_supplied_runtime_declarations",
    "AOE-GC-D15-S06": "kubernetes_supplied_control_plane_declarations",
    "AOE-GC-D15-S10": "supplied_container_boundary_path_projection",
    "AOE-GC-D15-S13": "serverless_supplied_function_event_bindings",
    "AOE-GC-D15-S14": "multicluster_supplied_tenant_declarations",
    "AOE-GA-D03-S13": "identity_supplied_authorization_model_projection",
    "AOE-GA-D03-S12": "identity_supplied_jit_privilege_windows",
    "AOE-GA-D03-S11": "identity_supplied_service_secret_lifecycle",
    "AOE-GA-D03-S10": "identity_supplied_spiffe_id_trust_projection",
    "AOE-GA-D03-S09": "identity_supplied_guest_trust_projection",
    "AOE-GA-D03-S07": "identity_supplied_certificate_auth_metadata",
    "AOE-GA-D03-S06": "identity_supplied_kerberos_realm_path",
    "AOE-GA-D03-S01": "identity_supplied_password_lockout_timeline",
    "AOE-GA-D03-S02": "identity_supplied_mfa_factor_rebind",
    "AOE-GA-D03-S17": "identity_supplied_biometric_assurance_projection",
    "AOE-GA-D01-S01": "recon_supplied_passive_source_freshness",
    "AOE-GA-D01-S09": "recon_supplied_organization_relationship_provenance",
    "AOE-GE-D22-S04": "crypto_supplied_kdf_policy_comparison",
    "AOE-GE-D22-S05": "crypto_supplied_symmetric_nonce_reuse",
    "AOE-GE-D22-S06": "crypto_supplied_public_key_policy",
    "AOE-GE-D22-S10": "crypto_supplied_key_lifecycle_posture",
    "AOE-GE-D22-S11": "crypto_supplied_token_payload_views",
    "AOE-GC-D13-S04": "network_supplied_switch_vlan_projection",
    "AOE-GC-D13-S05": "network_supplied_firewall_rule_order",
    "AOE-GC-D13-S07": "network_supplied_nac_admission_consistency",
    "AOE-GC-D13-S08": "network_supplied_wifi_policy_projection",
    "AOE-GC-D13-S15": "network_supplied_snmp_view_projection",
    "AOE-GC-D13-S21": "network_supplied_sdwan_overlay_projection",
}
INTEGRATION_PATHS = (
    "tests/agents/test_offline_seccomp_fhir_common_task_integration.py",
    "docs/offline-seccomp-fhir-common-task.md",
    "examples/offline-seccomp-bpf-subset-component.json",
    "examples/offline-fhir-device-association-component.json",
    "tests/agents/test_offline_voice_vendor_review_task_integration.py",
    "docs/offline-voice-vendor-review-task.md",
    "examples/offline-passport-claim-component.json",
    "examples/offline-ot-vendor-support-map-component.json",
    "tests/agents/test_offline_cross_domain_record_review_task_integration.py",
    "docs/offline-cross-domain-record-review-task.md",
    "examples/offline-activitystreams-create-component.json",
    "examples/offline-power-recovery-cadence-component.json",
    "examples/offline-operator-offboarding-component.json",
    "tests/agents/test_offline_social_record_review_task_integration.py",
    "docs/offline-social-record-review-task.md",
    "examples/offline-mfa-registration-audit-component.json",
    "examples/offline-visitor-escort-record-component.json",
    "examples/offline-osdp-poll-frame-component.json",
    "examples/offline-windows-device-event-component.json",
    "examples/offline-email-auth-results-component.json",
    "examples/offline-sms-uri-component.json",
    "tests/agents/test_offline_social_artifact_review_task_integration.py",
    "docs/offline-social-artifact-review-task.md",
    "examples/offline-oauth-consent-uri-component.json",
    "examples/offline-ooxml-relationship-component.json",
    "examples/offline-pe-packing-triage-component.json",
    "examples/offline-sis-bpcs-resource-component.json",
    "examples/offline-browser-minidump-directory-component.json",
    "examples/offline-ocpp16-data-transfer-component.json",
    "examples/offline-ais-position-report-component.json",
    "examples/offline-ccsds-space-packet-component.json",
    "examples/offline-rinex-observation-header-component.json",
    "tests/agents/test_offline_space_gnss_review_task_integration.py",
    "docs/offline-space-gnss-review-task.md",
    "examples/offline-mavlink2-packet-envelope-component.json",
    "tests/agents/test_offline_transport_packet_review_task_integration.py",
    "docs/offline-transport-packet-review-task.md",
    "examples/offline-socketcan-classical-frames-component.json",
    "tests/agents/test_offline_industrial_frame_review_task_integration.py",
    "docs/offline-industrial-frame-review-task.md",
    "examples/offline-cache-set-projection-component.json",
    "tests/agents/test_offline_hardware_structure_cache_task_integration.py",
    "docs/offline-hardware-structure-cache-task.md",
    "examples/offline-hexagon-elf32-layout-component.json",
    "tests/agents/test_offline_cross_format_kernel_dsp_task_integration.py",
    "docs/offline-cross-format-kernel-dsp-task.md",
    "examples/offline-apple-kernel-macho-markers-component.json",
    "tests/agents/test_offline_apple_kernel_macho_task_integration.py",
    "docs/offline-apple-kernel-macho-task.md",
    "examples/offline-yosys-netlist-delta-component.json",
    "tests/agents/test_offline_hardware_design_trace_task_integration.py",
    "docs/offline-hardware-design-trace-task.md",
    "examples/offline-linux-module-info-component.json",
    "tests/agents/test_offline_linux_module_common_task_integration.py",
    "docs/offline-linux-module-common-task.md",
    "src/sunderkey/offline_specialist_components.py",
    "scripts/build_offline_specialist_components.py",
    "scripts/run_offline_specialist_component.py",
    "tests/agents/test_offline_specialist_components.py",
    "tests/agents/test_offline_component_json_scanning.py",
    "docs/offline-specialist-wave-components.md",
    "examples/offline-graphql-component.json",
    "examples/offline-kubernetes-rbac-component.json",
    "examples/offline-aws-scp-component.json",
    "examples/offline-protobuf-component.json",
    "examples/offline-x509-chain-component.json",
    "examples/offline-http-request-framing-component.json",
    "examples/offline-azure-rbac-component.json",
    "examples/offline-soap-component.json",
    "examples/offline-gcp-iam-component.json",
    "examples/offline-jose-component.json",
    "examples/offline-openapi-security-evolution-component.json",
    "examples/offline-windows-dacl-component.json",
    "examples/offline-aws-identity-policy-component.json",
    "examples/offline-kubernetes-network-policy-component.json",
    "examples/offline-posix-acl-component.json",
    "examples/offline-aws-vpc-flow-component.json",
    "examples/offline-postgresql-rls-component.json",
    "examples/offline-websocket-frame-component.json",
    "examples/offline-kubernetes-pod-security-component.json",
    "examples/offline-redis-acl-component.json",
    "examples/offline-dns-zone-component.json",
    "examples/offline-dns-message-component.json",
    "examples/offline-cors-component.json",
    "examples/offline-oci-blob-component.json",
    "examples/offline-tls-hello-component.json",
    "examples/offline-cookie-selection-component.json",
    "examples/offline-semver-interval-component.json",
    "examples/offline-http-cache-freshness-component.json",
    "src/sunderkey/offline_specialist_task.py",
    "tests/agents/test_offline_specialist_task.py",
    "docs/offline-specialist-task.md",
    "tests/agents/test_offline_exploit_research_task_integration.py",
    "docs/offline-exploit-research-task.md",
    "scripts/run_offline_specialist_task.py",
    "tests/agents/test_offline_specialist_task_cli.py",
    "examples/offline-specialist-task.json",
    "examples/offline-azure-nsg-component.json",
    "examples/offline-android-component.json",
    "examples/offline-kubernetes-service-component.json",
    "tests/agents/test_offline_declaration_task_integration.py",
    "examples/offline-gcp-firewall-component.json",
    "examples/offline-ios-entitlement-component.json",
    "examples/offline-mqtt-topic-component.json",
    "tests/agents/test_offline_firewall_entitlement_topic_task.py",
    "examples/offline-modbus-tcp-component.json",
    "examples/offline-android-dex-component.json",
    "examples/offline-csp-fetch-component.json",
    "tests/agents/test_offline_protocol_artifact_task_integration.py",
    "src/sunderkey/offline_specialist_task_relations.py",
    "tests/agents/test_offline_specialist_task_relations.py",
    "docs/offline-specialist-task-relations.md",
    "scripts/run_offline_specialist_task_relations.py",
    "tests/agents/test_offline_specialist_task_relations_cli.py",
    "examples/offline-specialist-task-relations.json",
    "examples/offline-specialist-task-relation-inputs.json",
    "examples/offline-macho-component.json",
    "examples/offline-protobuf-wire-component.json",
    "examples/offline-coap-component.json",
    "tests/agents/test_offline_wire_mobile_task_integration.py",
    "examples/offline-elf64-layout-component.json",
    "examples/offline-initial-access-chain-component.json",
    "tests/agents/test_offline_initial_access_common_task_integration.py",
    "docs/offline-initial-access-common-task.md",
    "examples/offline-hardware-trace-difference-component.json",
    "tests/agents/test_offline_hardware_timing_common_task_integration.py",
    "docs/offline-hardware-timing-common-task.md",
    "examples/offline-path-review-checkpoint-component.json",
    "tests/agents/test_offline_path_review_common_task_integration.py",
    "docs/offline-path-review-common-task.md",
    "examples/offline-thread-mac-frame-control-component.json",
    "tests/agents/test_offline_radio_header_common_task_integration.py",
    "docs/offline-radio-header-common-task.md",
    "examples/offline-privilege-transition-controls-component.json",
    "tests/agents/test_offline_scenario_control_triad_task_integration.py",
    "docs/offline-scenario-control-triad-task.md",
    "examples/offline-windows-driver-pe-markers-component.json",
    "tests/agents/test_offline_windows_pe_review_triad_task_integration.py",
    "docs/offline-windows-pe-review-triad-task.md",
    "examples/offline-elf-section-permissions-component.json",
    "tests/agents/test_offline_elf_permission_common_task_integration.py",
    "docs/offline-elf-permission-common-task.md",
    "examples/offline-pe32-layout-component.json",
    "examples/offline-dhcpv4-component.json",
    "tests/agents/test_offline_binary_dhcp_task_integration.py",
    "examples/offline-webauthn-assertion-component.json",
    "tests/agents/test_offline_auth_context_task_integration.py",
    "examples/offline-dkim-component.json",
    "examples/offline-git-pack-component.json",
    "tests/agents/test_offline_auth_mail_pack_task_integration.py",
    "examples/offline-wasm-numeric-stack-component.json",
    "tests/agents/test_offline_wasm_binary_task_integration.py",
    "examples/offline-ssh-kexinit-component.json",
    "tests/agents/test_offline_ssh_network_task_integration.py",
    "examples/offline-ipv4-fragment-component.json",
    "tests/agents/test_offline_ipv4_protocol_task_integration.py",
    "examples/offline-bgp-update-component.json",
    "tests/agents/test_offline_bgp_network_task_integration.py",
    "examples/offline-wheel-record-component.json",
    "tests/agents/test_offline_wheel_artifact_task_integration.py",
    "examples/offline-amqp091-content-component.json",
    "tests/agents/test_offline_amqp_messaging_task_integration.py",
    "examples/offline-http-byte-range-component.json",
    "examples/offline-http-etag-component.json",
    "examples/offline-x509-san-component.json",
    "tests/agents/test_offline_http_etag_range_san_integration.py",
    "examples/offline-saml-conditions-component.json",
    "examples/offline-dicom-pdv-component.json",
    "tests/agents/test_offline_saml_dicom_integration.py",
    "tests/agents/test_offline_saml_dicom_task_integration.py",
    "examples/offline-aws-policy-scp-pair-component.json",
    "tests/agents/test_offline_aws_policy_scp_component_integration.py",
    "examples/offline-oauth-pkce-transcript-component.json",
    "tests/agents/test_offline_policy_flow_task_integration.py",
    "examples/offline-property-authorization-component.json",
    "examples/offline-cache-key-differential-component.json",
    "examples/offline-content-type-differential-component.json",
    "tests/agents/test_offline_api_property_cache_task_integration.py",
    "examples/offline-api-rate-limit-component.json",
    "examples/offline-url-navigation-component.json",
    "examples/offline-api-gateway-routes-component.json",
    "tests/agents/test_offline_api_routing_task_integration.py",
    "examples/offline-workload-identity-trust-component.json",
    "examples/offline-ci-workflow-trust-component.json",
    "examples/offline-scim-lifecycle-component.json",
    "tests/agents/test_offline_identity_supply_task_integration.py",
    "examples/offline-dependency-resolution-component.json",
    "tests/agents/test_offline_dependency_resolution_task_integration.py",
    "examples/offline-api-object-authorization-component.json",
    "examples/offline-api-function-authorization-component.json",
    "examples/offline-api-inventory-drift-component.json",
    "examples/offline-api-downstream-trust-component.json",
    "examples/offline-dom-dataflow-component.json",
    "tests/agents/test_offline_api_authorization_flow_task_integration.py",
    "examples/offline-attack-graph-model-component.json",
    "examples/offline-web-route-authorization-component.json",
    "examples/offline-browser-message-boundary-component.json",
    "tests/agents/test_offline_graph_web_boundary_task_integration.py",
    "examples/offline-web-content-handling-component.json",
    "examples/offline-webhook-callback-trust-component.json",
    "examples/offline-service-mesh-trust-component.json",
    "examples/offline-template-context-component.json",
    "examples/offline-partner-connector-trust-component.json",
    "examples/offline-service-worker-scope-component.json",
    "tests/agents/test_offline_template_worker_partner_task_integration.py",
    "examples/offline-agent-tool-authority-component.json",
    "examples/offline-agent-plan-integrity-component.json",
    "examples/offline-multi-agent-coordination-component.json",
    "examples/offline-cd-release-provenance-component.json",
    "examples/offline-build-reproducibility-component.json",
    "examples/offline-managed-package-feed-component.json",
    "examples/offline-backup-recovery-posture-component.json",
    "examples/offline-hypervisor-management-posture-component.json",
    "examples/offline-vdi-session-posture-component.json",
    "examples/offline-enterprise-server-management-component.json",
    "examples/offline-rmm-control-posture-component.json",
    "examples/offline-hpc-queue-posture-component.json",
    "examples/offline-key-lifecycle-posture-component.json",
    "examples/offline-public-key-policy-component.json",
    "examples/offline-token-payload-views-component.json",
    "examples/offline-coverage-seed-selection-component.json",
    "examples/offline-finite-grammar-component.json",
    "examples/offline-path-constraint-component.json",
    "examples/offline-binary-reference-component.json",
    "examples/offline-source-variant-component.json",
    "examples/offline-happens-before-component.json",
    "examples/offline-integer-width-component.json",
    "examples/offline-heap-trace-component.json",
    "examples/offline-chain-trial-component.json",
    "examples/offline-threat-scenario-component.json",
    "examples/offline-rng-sample-component.json",
    "examples/offline-crypto-protocol-state-component.json",
    "examples/offline-e2ee-epoch-component.json",
    "tests/agents/test_offline_crypto_protocol_task_integration.py",
    "docs/offline-crypto-protocol-task.md",
    "examples/offline-hybrid-kem-lineage-component.json",
    "examples/offline-side-channel-timing-component.json",
    "examples/offline-custom-protocol-framing-component.json",
    "examples/offline-protocol-trace-differential-component.json",
    "examples/offline-digest-vector-component.json",
    "examples/offline-mobile-pinset-component.json",
    "examples/offline-mobile-storage-component.json",
    "examples/offline-mobile-distribution-component.json",
    "examples/offline-desktop-ipc-component.json",
    "examples/offline-mobile-protection-component.json",
    "examples/offline-macos-release-component.json",
    "examples/offline-adc-route-component.json",
    "examples/offline-sip-dialog-component.json",
    "examples/offline-traffic-cadence-component.json",
    "examples/offline-ble-gatt-component.json",
    "examples/offline-i2c-write-component.json",
    "examples/offline-flash-region-component.json",
    "examples/offline-smartcard-file-component.json",
    "examples/offline-scan-scope-component.json",
    "examples/offline-sudo-grant-component.json",
    "examples/offline-namespace-cgroup-component.json",
    "examples/offline-scheduled-artifact-component.json",
    "examples/offline-mailbox-forwarding-component.json",
    "examples/offline-collaboration-sharing-component.json",
    "examples/offline-endpoint-assignment-component.json",
    "examples/offline-windows-privilege-artifacts-component.json",
    "examples/offline-windows-autostart-component.json",
    "examples/offline-windows-admin-invocations-component.json",
    "examples/offline-windows-material-access-component.json",
    "examples/offline-windows-remote-routes-component.json",
    "examples/offline-windows-control-state-component.json",
    "examples/offline-ebpf-helper-component.json",
    "examples/offline-linux-shell-component.json",
    "examples/offline-linux-logging-component.json",
    "examples/offline-macos-privilege-items-component.json",
    "examples/offline-macos-security-controls-component.json",
    "examples/offline-macos-launch-policy-component.json",
    "examples/offline-macos-store-access-component.json",
    "examples/offline-macos-ipc-clients-component.json",
    "examples/offline-unix-ipc-permissions-component.json",
    "examples/offline-telecom-appliance-component.json",
    "examples/offline-rf-receive-component.json",
    "examples/offline-mobile-core-component.json",
    "examples/offline-signaling-routes-component.json",
    "examples/offline-oran-policy-targets-component.json",
    "examples/offline-esim-profile-transitions-component.json",
    "examples/offline-zos-grants-component.json",
    "examples/offline-ibmi-grants-component.json",
    "examples/offline-unix-enterprise-grants-component.json",
    "examples/offline-sap-grants-component.json",
    "examples/offline-oracle-enterprise-grants-component.json",
    "tests/agents/test_offline_legacy_grant_common_task_integration.py",
    "docs/offline-legacy-grant-common-task.md",
    "examples/offline-android-instrumentation-trace-component.json",
    "examples/offline-android-device-trust-trace-component.json",
    "examples/offline-ios-instrumentation-trace-component.json",
    "examples/offline-ios-device-trust-trace-component.json",
    "examples/offline-direct-instruction-boundary-component.json",
    "examples/offline-multimodal-provenance-component.json",
    "tests/agents/test_offline_mobile_model_common_task_integration.py",
    "docs/offline-mobile-model-common-task.md",
    "examples/offline-pe-section-permissions-component.json",
    "tests/agents/test_offline_pe_permission_common_task_integration.py",
    "docs/offline-pe-permission-common-task.md",
    "tests/agents/test_offline_telecom_policy_common_task_integration.py",
    "docs/offline-telecom-policy-common-task.md",
    "tests/agents/test_offline_protocol_review_task_integration.py",
    "docs/offline-protocol-review-task.md",
    "tests/agents/test_offline_advanced_crypto_task_integration.py",
    "docs/offline-advanced-crypto-task.md",
    "examples/offline-storage-access-posture-component.json",
    "tests/agents/test_offline_enterprise_recovery_task_integration.py",
    "examples/offline-native-target-compatibility-component.json",
    "examples/offline-repository-secret-metadata-component.json",
    "examples/offline-iac-change-graph-component.json",
    "examples/offline-devcontainer-boundary-component.json",
    "examples/offline-vendor-update-lineage-component.json",
    "examples/offline-kubernetes-admission-boundary-component.json",
    "examples/offline-multicloud-federation-component.json",
    "tests/agents/test_offline_agent_trust_task_integration.py",
    "tests/agents/test_offline_cloud_release_task_integration.py",
    "tests/agents/test_offline_supply_chain_task_integration.py",
    "examples/offline-java-filter-boundary-component.json",
    "src/sunderkey/offline_framework_declaration_core.py",
    "examples/offline-dotnet-middleware-boundary-component.json",
    "examples/offline-web-framework-stack-component.json",
    "examples/offline-cms-permission-graph-component.json",
    "examples/offline-webrtc-signaling-component.json",
    "tests/agents/test_offline_web_stack_task_integration.py",
    "examples/offline-nosql-access-grants-component.json",
    "examples/offline-vector-tenant-boundary-component.json",
    "examples/offline-entitlement-toxic-combination-component.json",
    "examples/offline-session-binding-timeline-component.json",
    "examples/offline-webview-bridge-origin-component.json",
    "examples/offline-electron-bridge-origin-component.json",
    "examples/offline-prefix-origin-component.json",
    "tests/agents/test_offline_prefix_origin_task_integration.py",
    "examples/offline-cloud-inventory-drift-component.json",
    "tests/agents/test_offline_cloud_inventory_task_integration.py",
    "examples/offline-saas-signal-component.json",
    "tests/agents/test_offline_saas_signal_task_integration.py",
    "examples/offline-credential-exposure-component.json",
    "tests/agents/test_offline_credential_exposure_task_integration.py",
    "examples/offline-repository-reference-component.json",
    "tests/agents/test_offline_repository_reference_task_integration.py",
    "src/sunderkey/offline_recon_evidence_core.py",
    "examples/offline-technology-evidence-component.json",
    "examples/offline-deception-evidence-component.json",
    "tests/agents/test_offline_recon_evidence_task_integration.py",
    "examples/offline-price-rounding-component.json",
    "examples/offline-debit-idempotency-component.json",
    "tests/agents/test_offline_economic_task_integration.py",
    "examples/offline-workflow-state-component.json",
    "examples/offline-coupon-redemption-component.json",
    "tests/agents/test_offline_workflow_coupon_task_integration.py",
    "examples/offline-consent-purpose-component.json",
    "tests/agents/test_offline_workflow_consent_task_integration.py",
    "examples/offline-account-recovery-component.json",
    "examples/offline-tenant-ownership-component.json",
    "tests/agents/test_offline_recovery_tenant_task_integration.py",
    "examples/offline-auction-bid-component.json",
    "tests/agents/test_offline_auction_coupon_task_integration.py",
    "examples/offline-payment-reversal-component.json",
    "examples/offline-cross-channel-balance-component.json",
    "tests/agents/test_offline_payment_channel_task_integration.py",
    "examples/offline-scalping-window-component.json",
    "examples/offline-fraud-decision-component.json",
    "tests/agents/test_offline_scalping_fraud_task_integration.py",
    "examples/offline-directory-entitlement-path-component.json",
    "examples/offline-directory-trust-paths-component.json",
    "examples/offline-entra-role-claim-component.json",
    "examples/offline-kerberos-ad-declarations-component.json",
    "examples/offline-ntlm-control-pairs-component.json",
    "examples/offline-dc-topology-declarations-component.json",
    "examples/offline-hybrid-identity-mappings-component.json",
    "examples/offline-secondary-cloud-control-declarations-component.json",
    "examples/offline-cloud-org-support-billing-boundary-component.json",
    "examples/offline-enterprise-saas-admin-delegation-component.json",
    "examples/offline-cloud-post-compromise-timeline-component.json",
    "tests/agents/test_offline_cloud_identity_task_integration.py",
    "tests/agents/test_offline_crypto_policy_task_integration.py",
    "docs/offline-crypto-policy-task.md",
    "tests/agents/test_offline_network_boundary_task_integration.py",
    "docs/offline-network-boundary-task.md",
    "tests/agents/test_offline_network_management_task_integration.py",
    "docs/offline-network-management-task.md",
    "examples/offline-ot-controller-configuration-component.json",
    "examples/offline-ot-hmi-tag-mapping-component.json",
    "examples/offline-ot-engineering-project-provenance-component.json",
    "tests/agents/test_offline_ot_foundation_task_integration.py",
    "examples/offline-relational-grant-path-component.json",
    "examples/offline-graph-tenant-routes-component.json",
    "examples/offline-search-alias-component.json",
    "examples/offline-backup-chain-component.json",
    "examples/offline-stream-offset-component.json",
    "examples/offline-warehouse-lineage-component.json",
    "examples/offline-spark-job-plan-component.json",
    "examples/offline-analytics-sharing-component.json",
    "examples/offline-archive-member-paths-component.json",
    "examples/offline-etl-watermark-component.json",
    "tests/agents/test_offline_data_declaration_task_integration.py",
    "tests/agents/test_offline_directory_dacl_task_integration.py",
    "tests/agents/test_offline_data_identity_mobile_task_integration.py",
    "src/sunderkey/offline_specialist_task_delta.py",
    "tests/agents/test_offline_specialist_task_delta.py",
    "docs/offline-specialist-task-delta.md",
    "src/sunderkey/offline_collaboration_claim_graph.py",
    "tests/agents/test_offline_collaboration_claim_graph.py",
    "docs/offline-collaboration-claim-graph.md",
    "src/sunderkey/offline_pattern_task_relations.py",
    "tests/agents/test_offline_pattern_task_relations.py",
    "docs/offline-pattern-task-relations.md",
    "examples/offline-pattern-task-relations.json",
    "scripts/run_offline_pattern_task_relations.py",
    "tests/agents/test_offline_pattern_task_relations_cli.py",
    "examples/offline-pattern-task-inputs.json",
    "examples/offline-pattern-task-relations-expanded.json",
    "examples/offline-pattern-task-relations-twelve.json",
    "examples/offline-pattern-task-relations-sixteen.json",
    "src/sunderkey/offline_pattern_claim_graph.py",
    "tests/agents/test_offline_pattern_claim_graph.py",
    "docs/offline-pattern-claim-graph.md",
    "examples/offline-pattern-claim-graph.json",
    "src/sunderkey/offline_pattern_review_handoff.py",
    "tests/agents/test_offline_pattern_review_handoff.py",
    "docs/offline-pattern-review-handoff.md",
    "src/sunderkey/offline_pattern_claim_delta.py",
    "tests/agents/test_offline_pattern_claim_delta.py",
    "docs/offline-pattern-claim-delta.md",
    "src/sunderkey/offline_collaboration_review_handoff.py",
    "tests/agents/test_offline_collaboration_review_handoff.py",
    "docs/offline-collaboration-review-handoff.md",
    "src/sunderkey/offline_claim_world_projection.py",
    "tests/agents/test_offline_claim_world_projection.py",
    "docs/offline-claim-world-projection.md",
    "src/sunderkey/offline_specialist_decision_delta.py",
    "tests/agents/test_offline_specialist_decision_delta.py",
    "docs/offline-specialist-decision-delta.md",
    "src/sunderkey/offline_collaboration_claim_delta.py",
    "tests/agents/test_offline_collaboration_claim_delta.py",
    "docs/offline-collaboration-claim-delta.md",
    "examples/offline-gpu-management-node-permissions-component.json",
    "examples/offline-firmware-update-metadata-component.json",
    "examples/offline-management-engine-state-component.json",
    "examples/offline-ot-remote-access-policy-component.json",
    "tests/agents/test_offline_ot_platform_assurance_wave_two_task_integration.py",
    "examples/offline-firmware-inventory-sbom-component.json",
    "examples/offline-firmware-emulation-trace-component.json",
    "examples/offline-firmware-rtos-task-policy-component.json",
    "examples/offline-firmware-debug-interface-inventory-component.json",
    "examples/offline-firmware-secure-element-assertions-component.json",
    "examples/offline-firmware-tamper-provenance-component.json",
    "examples/offline-secure-boot-update-chain-component.json",
    "examples/offline-oci-image-layers-component.json",
    "examples/offline-third-party-trust-paths-component.json",
    "tests/agents/test_offline_firmware_oci_trust_task_integration.py",
    "examples/offline-adcs-template-rights-component.json",
    "examples/offline-vehicle-gateway-graph-component.json",
    "examples/offline-vehicle-diagnostic-policy-component.json",
    "examples/offline-vehicle-service-declarations-component.json",
    "tests/agents/test_offline_vehicle_identity_task_integration.py",
    "examples/offline-kubernetes-api-authentication-component.json",
    "examples/offline-kubernetes-secret-references-component.json",
    "examples/offline-oci-registry-signature-bindings-component.json",
    "examples/offline-kubernetes-runtime-reconciliation-component.json",
    "tests/agents/test_offline_kubernetes_supply_task_integration.py",
    "examples/offline-container-runtime-declarations-component.json",
    "examples/offline-kubernetes-control-plane-declarations-component.json",
    "examples/offline-container-boundary-path-declarations-component.json",
    "examples/offline-serverless-event-declarations-component.json",
    "examples/offline-multicluster-tenant-declarations-component.json",
    "tests/agents/test_offline_container_serverless_task_integration.py",
    "examples/offline-acpi-table-integrity-component.json",
    "examples/offline-agent-credential-boundary-component.json",
    "examples/offline-agent-memory-provenance-component.json",
    "examples/offline-agent-output-handling-component.json",
    "examples/offline-agent-resource-budget-component.json",
    "examples/offline-bacnet-device-identity-component.json",
    "examples/offline-bridge-claim-replay-component.json",
    "examples/offline-cip-security-declaration-component.json",
    "examples/offline-cloud-logging-guardrail-timeline-component.json",
    "examples/offline-compute-ingress-scope-component.json",
    "examples/offline-configuration-defaults-component.json",
    "examples/offline-confused-deputy-boundary-component.json",
    "examples/offline-consensus-vote-equivocation-component.json",
    "examples/offline-cross-channel-session-component.json",
    "examples/offline-cross-surface-authorization-component.json",
    "examples/offline-data-cloud-grant-scope-component.json",
    "examples/offline-dependency-fail-closed-component.json",
    "examples/offline-dns-scope-timeline-component.json",
    "examples/offline-evasion-delta-measurement-component.json",
    "examples/offline-evm-origin-authorization-component.json",
    "examples/offline-governance-quorum-reconciliation-component.json",
    "examples/offline-gpu-instance-tenant-boundary-component.json",
    "examples/offline-iec61850-subscription-refs-component.json",
    "examples/offline-indirect-prompt-boundary-component.json",
    "examples/offline-integrity-poisoning-component.json",
    "examples/offline-interpreter-input-boundary-component.json",
    "examples/offline-iommu-group-separation-component.json",
    "examples/offline-json-key-policy-component.json",
    "examples/offline-kms-grant-separation-component.json",
    "examples/offline-managed-paas-grant-scope-component.json",
    "examples/offline-membership-score-separation-component.json",
    "examples/offline-mev-trade-order-pattern-component.json",
    "examples/offline-mlops-lineage-component.json",
    "examples/offline-model-artifact-integrity-component.json",
    "examples/offline-model-output-similarity-component.json",
    "examples/offline-model-trigger-selectivity-component.json",
    "examples/offline-observable-discrepancy-component.json",
    "examples/offline-oracle-twap-deviation-component.json",
    "examples/offline-ot-zone-conduit-projection-component.json",
    "examples/offline-pickle-opcode-component.json",
    "examples/offline-pickle-opcode-safety-component.json",
    "examples/offline-private-endpoint-path-component.json",
    "examples/offline-prompt-canary-exposure-component.json",
    "examples/offline-proxy-storage-layout-component.json",
    "examples/offline-query-input-boundary-component.json",
    "examples/offline-rag-provenance-component.json",
    "examples/offline-redfish-role-privileges-component.json",
    "examples/offline-reentrancy-state-order-component.json",
    "examples/offline-request-origin-trust-component.json",
    "examples/offline-resource-expansion-budget-component.json",
    "examples/offline-riscv-pmp-projection-component.json",
    "examples/offline-ros2-security-declaration-component.json",
    "examples/offline-rpc-response-discrepancy-component.json",
    "examples/offline-s3-public-grant-controls-component.json",
    "examples/offline-toctou-state-schedule-component.json",
    "examples/offline-token-transfer-arithmetic-component.json",
    "examples/offline-tpm-pcr-replay-component.json",
    "examples/offline-training-label-drift-component.json",
    "examples/offline-usb-descriptor-framing-component.json",
    "examples/offline-wallet-threshold-authorization-component.json",
    "examples/offline-wasm-host-import-boundary-component.json",
    "examples/offline-authorization-model-projection-component.json",
    "examples/offline-jit-privilege-windows-component.json",
    "examples/offline-service-secret-lifecycle-component.json",
    "examples/offline-spiffe-id-trust-projection-component.json",
    "examples/offline-guest-trust-component.json",
    "examples/offline-certificate-auth-metadata-component.json",
    "examples/offline-kerberos-realm-path-component.json",
    "examples/offline-password-lockout-timeline-component.json",
    "examples/offline-mfa-factor-rebind-component.json",
    "examples/offline-biometric-assurance-component.json",
    "examples/offline-passive-source-freshness-component.json",
    "examples/offline-organization-relationship-component.json",
    "examples/offline-kdf-policy-component.json",
    "examples/offline-symmetric-nonce-component.json",
    "examples/offline-switch-vlan-component.json",
    "examples/offline-firewall-rule-order-component.json",
    "examples/offline-nac-admission-component.json",
    "examples/offline-wifi-policy-component.json",
    "examples/offline-snmp-view-component.json",
    "examples/offline-sdwan-overlay-component.json",
    "examples/offline-workforce-idp-mfa-paths-component.json",
    "examples/offline-workspace-external-sharing-component.json",
)
EFFECTS = {
    "target_authority": "none",
    "qualification": "none",
    "routing": "none",
    "execution": "none",
    "deployment": "none",
    "provider_requests": "none",
}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_STRING_BOUNDARY = re.compile(r'["\\]')


class OfflineSpecialistComponentError(QualificationError):
    """Invalid offline input, component provenance or attempt to widen inert staging."""


def _native(value: Any, *, maximum_bytes: int) -> str:
    """Bound native JSON before serialization, rejecting subclass and numeric aliases."""

    pending = [(value, 0)]
    nodes = 0
    size = 0

    def charge_text(item: str) -> None:
        nonlocal size
        if len(item) > maximum_bytes:
            raise OfflineSpecialistComponentError("JSON text exceeds the input byte limit")
        size += len(item) + 2 + item.count('"') + item.count("\\")
        for character in _CONTROL.findall(item):
            size += 1 if character in "\b\f\n\r\t" else 5
        if not item.isascii():
            size += sum(
                5 if ord(character) <= 0xFFFF else 11 for character in item if ord(character) > 127
            )
        if size > maximum_bytes:
            raise OfflineSpecialistComponentError(
                "JSON aggregate byte budget exceeded before serialization"
            )

    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 200_000 or depth > 80:
            raise OfflineSpecialistComponentError("Native JSON structure exceeds offline limits")
        if type(item) is dict:
            if len(item) > 200_000 or any(
                type(key) is not str or len(key) > maximum_bytes for key in item
            ):
                raise OfflineSpecialistComponentError("JSON object keys must be native text")
            if nodes + len(pending) + len(item) > 200_000:
                raise OfflineSpecialistComponentError(
                    "JSON queued structure exceeds the node budget"
                )
            size += 2 + max(0, len(item) - 1) + len(item)
            for key in item:
                charge_text(key)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 200_000:
                raise OfflineSpecialistComponentError("JSON array exceeds the node budget")
            if nodes + len(pending) + len(item) > 200_000:
                raise OfflineSpecialistComponentError(
                    "JSON queued structure exceeds the node budget"
                )
            size += 2 + max(0, len(item) - 1)
            if size > maximum_bytes:
                raise OfflineSpecialistComponentError(
                    "JSON aggregate byte budget exceeded before serialization"
                )
            pending.extend((child, depth + 1) for child in item)
        elif type(item) not in (str, int, bool, type(None)):
            raise OfflineSpecialistComponentError(
                "JSON values must use supported exact native types"
            )
        elif type(item) is str:
            charge_text(item)
        elif type(item) is int:
            if item.bit_length() > 64:
                raise OfflineSpecialistComponentError("JSON integer exceeds the input range")
            size += len(str(item))
        elif type(item) is bool:
            size += 4 if item else 5
        else:
            size += 4
        if size > maximum_bytes:
            raise OfflineSpecialistComponentError(
                "JSON aggregate byte budget exceeded before serialization"
            )
    try:
        text = _canonical_json(value)
        if len(text.encode("utf-8")) > maximum_bytes:
            raise OfflineSpecialistComponentError("Canonical JSON exceeds the input byte limit")
        return text
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise OfflineSpecialistComponentError("Invalid native JSON") from exc


def _json_preflight(text: str) -> None:
    """Bound decoded value count, nesting and numeric cost before JSON allocation."""

    index = nodes = depth = 0
    text_length = len(text)
    while index < text_length:
        character = text[index]
        if character in " \t\r\n,:":
            index += 1
            continue
        if character in "[{":
            if depth > 80:
                raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
            depth += 1
            nodes += 1
            index += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise OfflineSpecialistComponentError("JSON nesting is invalid")
            index += 1
        elif character == '"':
            index += 1
            while index < text_length:
                boundary = _STRING_BOUNDARY.search(text, index)
                if boundary is None:
                    raise OfflineSpecialistComponentError("JSON string is incomplete")
                index = boundary.start()
                if text[index] == '"':
                    index += 1
                    break
                else:
                    index += 2
            else:
                raise OfflineSpecialistComponentError("JSON string is incomplete")
            after = index
            while after < text_length and text[after] in " \t\r\n":
                after += 1
            if after >= text_length or text[after] != ":":
                nodes += 1
                if depth > 80:
                    raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
        else:
            end = index
            while end < text_length and text[end] not in ' \t\r\n,:]}[{"':
                end += 1
            if end - index > 21:
                raise OfflineSpecialistComponentError("JSON scalar token exceeds the input range")
            token = text[index:end]
            if not token:
                raise OfflineSpecialistComponentError("JSON scalar token is invalid")
            if token not in {"null", "true", "false"}:
                digits = token[1:] if token.startswith("-") else token
                if len(digits) > 20 or re.fullmatch(r"[0-9]+", digits) is None:
                    raise OfflineSpecialistComponentError(
                        "JSON scalar type or magnitude is invalid"
                    )
                if int(token).bit_length() > 64:
                    raise OfflineSpecialistComponentError("JSON integer exceeds the input range")
            nodes += 1
            if depth > 80:
                raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
            index = end
        if nodes > 200_000:
            raise OfflineSpecialistComponentError("JSON node count exceeds offline limits")
    if depth:
        raise OfflineSpecialistComponentError("JSON nesting is incomplete")


def _parse(content: bytes, maximum_bytes: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum_bytes:
        raise OfflineSpecialistComponentError("JSON bytes are empty, invalid or oversized")
    try:
        text = content.decode("utf-8")
        _json_preflight(text)
        raw = loads_json_without_duplicate_keys(text)
        _native(raw, maximum_bytes=maximum_bytes)
        return raw
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise OfflineSpecialistComponentError(
            "JSON input is invalid or contains duplicate keys"
        ) from exc


def _local_path(value: str | Path) -> Path:
    if type(value) not in (str, type(Path())):
        raise OfflineSpecialistComponentError("Input path must be native local text or Path")
    text = str(value)
    if not text or len(text) > 4096 or "\x00" in text or "://" in text:
        raise OfflineSpecialistComponentError("Input path is invalid")
    if text.startswith(("\\\\", "//")):
        raise OfflineSpecialistComponentError("Remote input paths are not permitted")
    return Path(text).absolute()


def _read_local_regular_file(path: str | Path, maximum_bytes: int) -> bytes:
    """Bound development I/O and reject observed links; this is not host containment."""

    source = _local_path(path)
    try:
        for part in (*reversed(source.parents), source):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise OfflineSpecialistComponentError("Component source paths must not be linked")
        if not stat.S_ISREG(source.lstat().st_mode):
            raise OfflineSpecialistComponentError("Input must be a local regular file")
        descriptor = os.open(
            source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum_bytes:
                raise OfflineSpecialistComponentError(
                    "Component source is not a bounded regular file"
                )
            content = stream.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise OfflineSpecialistComponentError("Component source exceeds the byte limit")
        return content
    except OSError as exc:
        raise OfflineSpecialistComponentError(
            "A required local component source is unavailable"
        ) from exc


def _read_source(repository_root: str | Path, relative_path: str) -> bytes:
    root = _local_path(repository_root)
    if (
        type(relative_path) is not str
        or Path(relative_path).is_absolute()
        or ".." in Path(relative_path).parts
    ):
        raise OfflineSpecialistComponentError(
            "Component source must be a fixed relative repository path"
        )
    source = root / relative_path
    content = _read_local_regular_file(source, MAX_SOURCE_BYTES)
    if not source.resolve().is_relative_to(root.resolve()):
        raise OfflineSpecialistComponentError("Component source escapes the repository")
    return content


def _same(actual: Any, expected: Any, label: str, *, maximum_bytes: int = MAX_SOURCE_BYTES) -> None:
    if _native(actual, maximum_bytes=maximum_bytes) != _native(
        expected, maximum_bytes=maximum_bytes
    ):
        raise OfflineSpecialistComponentError(f"{label} does not match exact reconstructed content")


def _address(body: dict[str, Any], domain: str, prefix: str) -> tuple[str, str]:
    digest = _canonical_sha256({"domain": domain, "content": body})
    return prefix + digest.removeprefix("sha256:")[:32].upper(), digest


@lru_cache(maxsize=1)
def _validated_foundation_program(
    contents: tuple[bytes, ...],
) -> str:
    """Reuse pure foundation derivation only when every captured source byte matches."""

    raw = {
        path: _parse(content, MAX_SOURCE_BYTES)
        for path, content in zip(FOUNDATION_PATHS, contents, strict=True)
    }
    registry = ExpertRegistry.from_dict(raw[FOUNDATION_PATHS[0]])
    capabilities = CapabilityCatalog.from_dict(raw[FOUNDATION_PATHS[1]], registry)
    expansion = ArmyExpansionRoadmap.from_dict(raw[FOUNDATION_PATHS[2]])
    vectors = AttackVectorCatalog.from_dict(raw[FOUNDATION_PATHS[3]], registry, expansion)
    standard = QualificationStandard.from_dict(raw[FOUNDATION_PATHS[4]], registry, capabilities)
    plans = QualificationPlanCatalogV2.from_dict(
        raw[FOUNDATION_PATHS[5]], registry, capabilities, vectors, standard
    )
    blueprints = CandidateBlueprintCatalogV2.from_dict(
        raw[FOUNDATION_PATHS[6]], registry, capabilities, vectors, standard, plans
    )
    for path, parsed in zip(
        FOUNDATION_PATHS[:7],
        (registry, capabilities, expansion, vectors, standard, plans, blueprints),
        strict=True,
    ):
        _same(raw[path], parsed.to_dict(), "Foundation native round-trip")
    packages, roadmap = build_implementation_program_v2(
        registry, capabilities, expansion, vectors, plans, blueprints
    )
    _same(raw[FOUNDATION_PATHS[7]], packages, "Implementation packages")
    _same(raw[FOUNDATION_PATHS[8]], roadmap, "Implementation roadmap")
    return _native(packages, maximum_bytes=MAX_SOURCE_BYTES)


def _catalog_document(repository_root: str | Path) -> dict[str, Any]:
    paths = (
        *FOUNDATION_PATHS,
        STRATEGY_PATH,
        *INTEGRATION_PATHS,
        *(path for item in COMPONENTS for path in item[4:]),
    )
    captured = {path: _read_source(repository_root, path) for path in paths}
    strategy = CandidateImplementationStrategy.from_dict(
        _parse(captured[STRATEGY_PATH], MAX_SOURCE_BYTES)
    )
    package_json = _validated_foundation_program(tuple(captured[path] for path in FOUNDATION_PATHS))
    packages = _parse(package_json.encode("utf-8"), MAX_SOURCE_BYTES)
    by_profile = {item["profile_id"]: item for item in packages["packages"]}
    descriptors = []
    for profile_id, capability, wave, algorithm, module_path, test_path, guide_path in COMPONENTS:
        package = by_profile[profile_id]
        if (
            capability not in package["primary_capability_ids"]
            or package["scheduled_wave_id"] != wave
        ):
            raise OfflineSpecialistComponentError(
                "Component ownership differs from reviewed work packages"
            )
        descriptors.append(
            {
                "component_id": algorithm,
                "profile_id": profile_id,
                "profile_name": package["profile_name"],
                "package_id": package["package_id"],
                "scheduled_wave_id": wave,
                "priority_sequence": package["priority_sequence"],
                "commander_profile_id": package["commander_profile_id"],
                "independent_validator_id": package["independent_validator_id"],
                "vector_id": package["vector_id"],
                "primary_capability_id": capability,
                "blueprint_sha256": package["blueprint_sha256"],
                "implementation_path": module_path,
                "test_path": test_path,
                "guide_path": guide_path,
                "implementation_boundary": "offline_algorithm_component",
                "full_candidate_assembled": False,
                "qualified": False,
                "routable": False,
                "deployed": False,
                "phase158_entry_approved": False,
            }
        )
    component_ids = {item["component_id"] for item in descriptors}
    profile_ids = {item["profile_id"] for item in descriptors}
    if len(component_ids) != len(descriptors) or set(PROFILE_DEFAULT_COMPONENTS) != profile_ids:
        raise OfflineSpecialistComponentError("Component identities or fixed defaults are invalid")
    for profile_id, default_id in PROFILE_DEFAULT_COMPONENTS.items():
        if not any(
            item["profile_id"] == profile_id and item["component_id"] == default_id
            for item in descriptors
        ):
            raise OfflineSpecialistComponentError("Fixed default does not belong to its profile")
    body = {
        "schema_version": 1,
        "catalog_version": "1.0.0",
        "development_mode": "additional_inert_offline_staging",
        "strategy_id": strategy.strategy_id,
        "strategy_sha256": strategy.strategy_sha256,
        "source_hash_profile": "sha256_crlf_normalized_to_lf",
        "sources": [
            {
                "path": path,
                "sha256": "sha256:"
                + hashlib.sha256(captured[path].replace(b"\r\n", b"\n")).hexdigest(),
            }
            for path in sorted(captured)
        ],
        "components": descriptors,
        "coverage_summary": {
            "offline_algorithm_component_count": len(descriptors),
            "partial_specialist_profile_count": len(profile_ids),
            "full_candidate_count": 0,
            "qualified_candidate_count": 0,
            "routable_candidate_count": 0,
            "phase158_ready_candidate_count": 0,
        },
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Partial algorithms do not implement all ten components or eight package stages.",
            "The original six-reference SDK slice and all six Phase 158 gates remain unchanged.",
            "Wave identifiers identify existing planning ownership, not a scheduling reordering.",
            "Inputs are supplied inert data, not authenticated targets or live observations.",
            "Source digests prove local consistency, not owner authentication or source safety.",
            "No network, process, credential, provider or operational dispatch is used.",
        ],
    }
    identifier, digest = _address(body, CATALOG_DOMAIN, "OSC-")
    return {**body, "catalog_id": identifier, "catalog_sha256": digest}


@dataclass(frozen=True, slots=True)
class OfflineSpecialistComponentCatalog:
    """Owned catalog content; every dispatch separately reconstructs current source bindings."""

    document_json: str

    @classmethod
    def from_dict(
        cls, raw: dict[str, Any], *, repository_root: str | Path
    ) -> OfflineSpecialistComponentCatalog:
        expected = _catalog_document(repository_root)
        _same(raw, expected, "Offline component catalog", maximum_bytes=MAX_CATALOG_BYTES)
        return cls(_native(expected, maximum_bytes=MAX_CATALOG_BYTES))

    def to_dict(self) -> dict[str, Any]:
        text = getattr(self, "document_json", None)
        if (
            type(self) is not OfflineSpecialistComponentCatalog
            or type(text) is not str
            or len(text) > MAX_CATALOG_BYTES
        ):
            raise OfflineSpecialistComponentError(
                "Catalog wrapper family or native content is invalid"
            )
        try:
            raw = _parse(text.encode("utf-8"), MAX_CATALOG_BYTES)
        except UnicodeError as exc:
            raise OfflineSpecialistComponentError("Catalog wrapper text is invalid") from exc
        if type(raw) is not dict or _native(raw, maximum_bytes=MAX_CATALOG_BYTES) != text:
            raise OfflineSpecialistComponentError("Catalog wrapper content is not canonical")
        return raw


def build_offline_specialist_component_catalog(
    *, repository_root: str | Path
) -> OfflineSpecialistComponentCatalog:
    return OfflineSpecialistComponentCatalog(
        _native(_catalog_document(repository_root), maximum_bytes=MAX_CATALOG_BYTES)
    )


def load_offline_specialist_component_catalog(
    *, repository_root: str | Path
) -> OfflineSpecialistComponentCatalog:
    raw = _parse(_read_source(repository_root, CATALOG_PATH), MAX_CATALOG_BYTES)
    return OfflineSpecialistComponentCatalog.from_dict(raw, repository_root=repository_root)


def parse_offline_specialist_component_request(content: bytes) -> dict[str, Any]:
    raw = _parse(content, MAX_REQUEST_BYTES)
    if type(raw) is not dict:
        raise OfflineSpecialistComponentError("Component request must be a native object")
    return raw


def load_offline_specialist_component_request(path: str | Path) -> dict[str, Any]:
    """Read one explicitly supplied local regular inert fixture, without runtime grants."""

    return parse_offline_specialist_component_request(
        _read_local_regular_file(path, MAX_REQUEST_BYTES)
    )


def _prepare_component_request(
    request: dict[str, Any],
    *,
    catalog: OfflineSpecialistComponentCatalog,
    repository_root: str | Path,
) -> tuple[dict[str, Any], dict[str, Any], OfflineSpecialistComponentCatalog]:
    """Snapshot the current catalog and shared inert envelope without running an algorithm."""

    if type(catalog) is not OfflineSpecialistComponentCatalog:
        raise OfflineSpecialistComponentError("Dispatch needs the exact offline catalog family")
    verified = OfflineSpecialistComponentCatalog.from_dict(
        catalog.to_dict(), repository_root=repository_root
    )
    request_json = _native(request, maximum_bytes=MAX_REQUEST_BYTES)
    owned = _parse(request_json.encode("utf-8"), MAX_REQUEST_BYTES)
    fields = {
        "schema_version",
        "profile_id",
        "environment",
        "action_tier",
        "dry_run",
        "credential_refs",
        "resources",
        "payload",
    }
    if type(owned) is not dict or (
        owned.keys() != fields and owned.keys() != fields | {"component_id"}
    ):
        raise OfflineSpecialistComponentError("Component request fields are invalid")
    _same(
        {
            key: owned[key]
            for key in ("schema_version", "action_tier", "dry_run", "credential_refs", "resources")
        },
        {
            "schema_version": 1,
            "action_tier": "R0",
            "dry_run": True,
            "credential_refs": [],
            "resources": {"network": [], "filesystem": [], "process": [], "credential": []},
        },
        "Inert staging boundary",
    )
    if owned["environment"] not in ("synthetic", "supplied_inert_data"):
        raise OfflineSpecialistComponentError(
            "Only declared synthetic or supplied inert inputs are allowed"
        )
    profile_id = owned["profile_id"]
    if type(profile_id) is not str or profile_id not in PROFILE_DEFAULT_COMPONENTS:
        raise OfflineSpecialistComponentError("Profile has no fixed offline component default")
    component_id = (
        owned["component_id"] if "component_id" in owned else PROFILE_DEFAULT_COMPONENTS[profile_id]
    )
    if type(component_id) is not str or not component_id:
        raise OfflineSpecialistComponentError("Component selector must be exact registered text")
    descriptor = next(
        (
            item
            for item in verified.to_dict()["components"]
            if item["profile_id"] == profile_id and item["component_id"] == component_id
        ),
        None,
    )
    if descriptor is None:
        raise OfflineSpecialistComponentError(
            "Component selector does not identify an algorithm owned by this profile"
        )
    payload = owned["payload"]
    if type(payload) is not dict:
        raise OfflineSpecialistComponentError("Component payload must be a native object")
    payload_fields = {
        "graphql_query_structure": {
            "schema_content",
            "query_content",
            "schema_source_id",
            "query_source_id",
            "operation_name",
            "limits",
        },
        "kubernetes_rbac_supplied_model": {"snapshot", "queries"},
        "aws_organizations_supplied_scp_path": {"snapshot", "queries"},
        "azure_rbac_supplied_model": {"snapshot", "queries"},
        "gcp_iam_supplied_allow_model": {"snapshot", "queries"},
        "protobuf_schema_evolution": {
            "previous_content",
            "current_content",
            "previous_source_id",
            "current_source_id",
            "limits",
        },
        "soap_document_literal_contract_instance": {
            "wsdl_content",
            "envelope_content",
            "wsdl_source_id",
            "envelope_source_id",
            "selection",
            "limits",
        },
    }.get(component_id, {"model"})
    if payload.keys() != payload_fields:
        raise OfflineSpecialistComponentError("Component payload fields are invalid")
    return owned, descriptor, verified


def prepare_offline_specialist_component_request(
    request: dict[str, Any],
    *,
    catalog: OfflineSpecialistComponentCatalog,
    repository_root: str | Path,
) -> dict[str, Any]:
    """Detach a current-source, deny-all envelope before common-task analysis.

    This checks shared resource, selector and top-level payload boundaries only.
    Leaf algorithms still validate their complete premises when explicitly run.
    No analysis, assignment, authorization or positive-use admission occurs.
    """

    owned, _descriptor, _verified = _prepare_component_request(
        request, catalog=catalog, repository_root=repository_root
    )
    return owned


def run_offline_specialist_component(
    request: dict[str, Any],
    *,
    catalog: OfflineSpecialistComponentCatalog,
    repository_root: str | Path,
) -> dict[str, Any]:
    """Analyze caller-owned inert inputs using one of the statically imported closed algorithms."""

    owned, descriptor, verified = _prepare_component_request(
        request, catalog=catalog, repository_root=repository_root
    )
    component_id = descriptor["component_id"]
    payload = owned["payload"]
    if component_id == "graphql_query_structure":
        if payload.keys() != {
            "schema_content",
            "query_content",
            "schema_source_id",
            "query_source_id",
            "operation_name",
            "limits",
        }:
            raise OfflineSpecialistComponentError("GraphQL payload fields are invalid")
        if any(
            type(payload[key]) is not str
            for key in ("schema_content", "query_content", "schema_source_id", "query_source_id")
        ):
            raise OfflineSpecialistComponentError("GraphQL source fields must be native text")
        limit_fields = {
            "max_schema_bytes",
            "max_query_bytes",
            "max_depth",
            "max_tokens",
            "max_nodes",
            "max_expanded_selections",
        }
        if type(payload["limits"]) is not dict or payload["limits"].keys() != limit_fields:
            raise OfflineSpecialistComponentError("GraphQL requires all six explicit bound fields")
        analysis = analyze_graphql_operation(
            schema_content=payload["schema_content"].encode("utf-8"),
            query_content=payload["query_content"].encode("utf-8"),
            schema_source_id=payload["schema_source_id"],
            query_source_id=payload["query_source_id"],
            operation_name=payload["operation_name"],
            limits=GraphQLAnalysisLimits(**payload["limits"]),
        )
    elif component_id == "kubernetes_rbac_supplied_model":
        if payload.keys() != {"snapshot", "queries"}:
            raise OfflineSpecialistComponentError("Kubernetes RBAC payload fields are invalid")
        analysis = analyze_kubernetes_rbac(payload["snapshot"], payload["queries"])
    elif component_id == "aws_organizations_supplied_scp_path":
        if payload.keys() != {"snapshot", "queries"}:
            raise OfflineSpecialistComponentError("AWS SCP payload fields are invalid")
        analysis = analyze_aws_scp(payload["snapshot"], payload["queries"])
    elif component_id == "protobuf_schema_evolution":
        if payload.keys() != {
            "previous_content",
            "current_content",
            "previous_source_id",
            "current_source_id",
            "limits",
        }:
            raise OfflineSpecialistComponentError("Protobuf payload fields are invalid")
        if any(
            type(payload[key]) is not str
            for key in (
                "previous_content",
                "current_content",
                "previous_source_id",
                "current_source_id",
            )
        ):
            raise OfflineSpecialistComponentError("Protobuf source fields must be native text")
        limit_fields = {
            "max_previous_bytes",
            "max_current_bytes",
            "max_tokens",
            "max_nodes",
            "max_observations",
        }
        if type(payload["limits"]) is not dict or payload["limits"].keys() != limit_fields:
            raise OfflineSpecialistComponentError(
                "Protobuf requires all five explicit bound fields"
            )
        analysis = analyze_protobuf_schema_evolution(
            previous_content=payload["previous_content"].encode("utf-8"),
            current_content=payload["current_content"].encode("utf-8"),
            previous_source_id=payload["previous_source_id"],
            current_source_id=payload["current_source_id"],
            limits=ProtobufAnalysisLimits(**payload["limits"]),
        )
    elif component_id == "supplied_http_request_framing":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("HTTP request framing payload fields are invalid")
        analysis = analyze_supplied_http_request_framing(payload["model"])
    elif component_id == "azure_rbac_supplied_model":
        if payload.keys() != {"snapshot", "queries"}:
            raise OfflineSpecialistComponentError("Azure RBAC payload fields are invalid")
        analysis = analyze_azure_rbac(payload["snapshot"], payload["queries"])
    elif component_id == "soap_document_literal_contract_instance":
        if payload.keys() != {
            "wsdl_content",
            "envelope_content",
            "wsdl_source_id",
            "envelope_source_id",
            "selection",
            "limits",
        }:
            raise OfflineSpecialistComponentError("SOAP payload fields are invalid")
        if any(
            type(payload[key]) is not str
            for key in ("wsdl_content", "envelope_content", "wsdl_source_id", "envelope_source_id")
        ):
            raise OfflineSpecialistComponentError("SOAP source fields must be native text")
        limit_fields = {
            "max_wsdl_bytes",
            "max_envelope_bytes",
            "max_xml_tokens",
            "max_xml_nodes",
            "max_xml_depth",
            "max_observations",
        }
        if type(payload["limits"]) is not dict or payload["limits"].keys() != limit_fields:
            raise OfflineSpecialistComponentError("SOAP requires all six explicit bound fields")
        analysis = analyze_soap_contract_instance(
            wsdl_content=payload["wsdl_content"].encode("utf-8"),
            envelope_content=payload["envelope_content"].encode("utf-8"),
            wsdl_source_id=payload["wsdl_source_id"],
            envelope_source_id=payload["envelope_source_id"],
            selection=payload["selection"],
            limits=SoapAnalysisLimits(**payload["limits"]),
        )
    elif component_id == "gcp_iam_supplied_allow_model":
        if payload.keys() != {"snapshot", "queries"}:
            raise OfflineSpecialistComponentError("GCP IAM payload fields are invalid")
        analysis = analyze_gcp_iam(payload["snapshot"], payload["queries"])
    elif component_id == "supplied_jose_signature_and_claims":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("JOSE payload fields are invalid")
        analysis = analyze_supplied_jose(payload["model"])
    elif component_id == "openapi_security_declaration_evolution":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OpenAPI evolution payload fields are invalid")
        analysis = analyze_openapi_security_evolution(payload["model"])
    elif component_id == "supplied_x509_chain_structure":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("X.509 payload fields are invalid")
        analysis = analyze_supplied_x509_chain(payload["model"])
    elif component_id == "windows_supplied_dacl_arithmetic":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Windows DACL payload fields are invalid")
        analysis = analyze_supplied_windows_dacl(payload["model"])
    elif component_id == "aws-identity-policy-set-v1":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("AWS identity policy payload fields are invalid")
        analysis = analyze_aws_identity_policy_set(payload["model"])
    elif component_id == "kubernetes_supplied_network_policy_flows":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError(
                "Kubernetes network policy payload fields are invalid"
            )
        analysis = analyze_supplied_kubernetes_network_policy(payload["model"])
    elif component_id == "linux_supplied_posix_acl_arithmetic":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("POSIX ACL payload fields are invalid")
        analysis = analyze_supplied_posix_acl(payload["model"])
    elif component_id == "aws_supplied_vpc_flow_predicates":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("AWS VPC flow payload fields are invalid")
        analysis = analyze_supplied_aws_vpc_flow(payload["model"])
    elif component_id == "postgresql_supplied_select_rls":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("PostgreSQL RLS payload fields are invalid")
        analysis = analyze_supplied_postgresql_rls(payload["model"])
    elif component_id == "websocket_supplied_frame_state":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("WebSocket frame payload fields are invalid")
        analysis = analyze_supplied_websocket_frames(payload["model"])
    elif component_id == "kubernetes_supplied_linux_pod_security_controls":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError(
                "Kubernetes Pod control payload fields are invalid"
            )
        analysis = analyze_supplied_kubernetes_pod_security(payload["model"])
    elif component_id == "redis_supplied_acl_key_selectors":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Redis ACL payload fields are invalid")
        analysis = analyze_supplied_redis_acl(payload["model"])
    elif component_id == "dns_supplied_zone_lookup":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("DNS zone payload fields are invalid")
        analysis = analyze_supplied_dns_zone(payload["model"])
    elif component_id == "dns_supplied_wire_structure":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("DNS message payload fields are invalid")
        analysis = analyze_supplied_dns_message(payload["model"])
    elif component_id == "cors_supplied_negotiation_and_exposure":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("CORS payload fields are invalid")
        analysis = analyze_supplied_cors(payload["model"])
    elif component_id == "oci_supplied_blob_graph_integrity":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OCI blob graph payload fields are invalid")
        analysis = analyze_supplied_oci_blob_graph(payload["model"])
    elif component_id == "tls13_supplied_hello_offer_selection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("TLS Hello payload fields are invalid")
        analysis = analyze_supplied_tls_hello_pair(payload["model"])
    elif component_id == "retained_cookie_candidate_predicates":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cookie selection payload fields are invalid")
        analysis = analyze_supplied_cookie_selection(payload["model"])
    elif component_id == "javascript_supplied_semver_interval_arithmetic":
        analysis = analyze_supplied_semver_intervals(payload["model"])
    elif component_id == "http_supplied_cache_freshness_arithmetic":
        analysis = analyze_supplied_http_cache_freshness(payload["model"])
    elif component_id == "azure_supplied_nsg_directional_predicates":
        analysis = analyze_supplied_azure_nsg(payload["model"])
    elif component_id == "android_supplied_component_declarations":
        analysis = analyze_supplied_android_components(payload["model"])
    elif component_id == "kubernetes_supplied_service_endpoint_consistency":
        analysis = analyze_supplied_kubernetes_service_endpoints(payload["model"])
    elif component_id == "gcp_supplied_vpc_firewall_new_flow_predicates":
        analysis = analyze_supplied_gcp_firewall(payload["model"])
    elif component_id == "ios_supplied_entitlement_declaration_consistency":
        analysis = analyze_supplied_ios_entitlements(payload["model"])
    elif component_id == "mqtt_supplied_topic_filter_arithmetic":
        analysis = analyze_supplied_mqtt_topics(payload["model"])
    elif component_id == "modbus_supplied_tcp_read_exchange_structure":
        analysis = analyze_supplied_modbus_tcp(payload["model"])
    elif component_id == "android_supplied_dex035_structure":
        analysis = analyze_supplied_android_dex(payload["model"])
    elif component_id == "csp_supplied_external_fetch_predicates":
        analysis = analyze_supplied_csp_fetch(payload["model"])
    elif component_id == "ios_supplied_macho64_layout":
        analysis = analyze_supplied_macho_layout(payload["model"])
    elif component_id == "protobuf_supplied_wire_occurrences":
        analysis = analyze_supplied_protobuf_wire(payload["model"])
    elif component_id == "coap_supplied_get_piggyback_structure":
        analysis = analyze_supplied_coap(payload["model"])
    elif component_id == "linux_supplied_elf64_layout":
        analysis = analyze_supplied_elf64_layout(payload["model"])
    elif component_id == "windows_supplied_pe32plus_layout":
        analysis = analyze_supplied_pe32plus_layout(payload["model"])
    elif component_id == "dhcpv4_supplied_offer_ack_structure":
        analysis = analyze_supplied_dhcpv4(payload["model"])
    elif component_id == "webauthn_supplied_assertion_context_arithmetic":
        analysis = analyze_supplied_webauthn_assertion(payload["model"])
    elif component_id == "dkim_supplied_canonicalization_and_body_hash":
        analysis = analyze_supplied_dkim_canonicalization(payload["model"])
    elif component_id == "git_supplied_pack_ofs_delta_reconstruction":
        analysis = analyze_supplied_git_pack(payload["model"])
    elif component_id == "wasm_supplied_numeric_stack_and_interfaces":
        analysis = analyze_supplied_wasm_numeric_stack(payload["model"])
    elif component_id == "ssh_supplied_kexinit_selection_arithmetic":
        analysis = analyze_supplied_ssh_kexinit_pair(payload["model"])
    elif component_id == "ipv4_supplied_fragment_relations_and_header_checksums":
        analysis = analyze_supplied_ipv4_fragments(payload["model"])
    elif component_id == "bgp_supplied_update_structure":
        analysis = analyze_supplied_bgp_update(payload["model"])
    elif component_id == "wheel_supplied_zip_record_integrity":
        analysis = analyze_supplied_wheel_record(payload["model"])
    elif component_id == "amqp091_supplied_publish_content_assembly":
        analysis = analyze_supplied_amqp091_content(payload["model"])
    elif component_id == "http_supplied_byte_range_arithmetic":
        analysis = analyze_supplied_http_byte_ranges(payload["model"])
    elif component_id == "http_supplied_etag_precondition_order":
        analysis = analyze_supplied_http_etag_preconditions(payload["model"])
    elif component_id == "x509_supplied_san_reference_match":
        analysis = analyze_supplied_x509_san(payload["model"])
    elif component_id == "saml_supplied_conditions_audience_restrictions":
        analysis = analyze_supplied_saml_conditions(payload["model"])
    elif component_id == "dicom_supplied_pdata_pdv_structure":
        analysis = analyze_supplied_dicom_pdv(payload["model"])
    elif component_id == "aws-supplied-identity-scp-pair-v1":
        analysis = analyze_supplied_aws_policy_scp_pair(payload["model"])
    elif component_id == "oauth_supplied_code_pkce_transcript":
        analysis = analyze_supplied_oauth_pkce_transcript(payload["model"])
    elif component_id == "api_supplied_property_authorization":
        analysis = analyze_supplied_property_authorization(payload["model"])
    elif component_id == "http_supplied_cache_key_differential":
        analysis = analyze_supplied_cache_key_differential(payload["model"])
    elif component_id == "api_supplied_content_type_differential":
        analysis = analyze_supplied_content_type_differential(payload["model"])
    elif component_id == "api_supplied_rate_limit_projection":
        analysis = analyze_supplied_api_rate_limit(payload["model"])
    elif component_id == "https_supplied_url_navigation_projection":
        analysis = analyze_supplied_url_navigation(payload["model"])
    elif component_id == "api_supplied_gateway_route_selection":
        analysis = analyze_supplied_api_gateway_routes(payload["model"])
    elif component_id == "workload_identity_supplied_trust_projection":
        analysis = analyze_supplied_workload_identity_trust(payload["model"])
    elif component_id == "ci_supplied_workflow_trust_flow":
        analysis = analyze_supplied_ci_workflow_trust(payload["model"])
    elif component_id == "directory_supplied_lifecycle_projection":
        analysis = analyze_supplied_scim_lifecycle(payload["model"])
    elif component_id == "dependency_supplied_resolution_collision":
        analysis = analyze_supplied_dependency_resolution(payload["model"])
    elif component_id == "api_supplied_object_authorization":
        analysis = analyze_supplied_api_object_authorization(payload["model"])
    elif component_id == "identity_supplied_authorization_model_projection":
        analysis = analyze_supplied_authorization_model(payload["model"])
    elif component_id == "identity_supplied_jit_privilege_windows":
        analysis = analyze_supplied_jit_privilege_windows(payload["model"])
    elif component_id == "identity_supplied_service_secret_lifecycle":
        analysis = analyze_supplied_service_secret_lifecycle(payload["model"])
    elif component_id == "identity_supplied_spiffe_id_trust_projection":
        analysis = analyze_supplied_spiffe_id_trust(payload["model"])
    elif component_id == "identity_supplied_guest_trust_projection":
        analysis = analyze_supplied_guest_trust(payload["model"])
    elif component_id == "identity_supplied_certificate_auth_metadata":
        analysis = analyze_supplied_certificate_auth_metadata(payload["model"])
    elif component_id == "identity_supplied_kerberos_realm_path":
        analysis = analyze_supplied_kerberos_realm_path(payload["model"])
    elif component_id == "identity_supplied_password_lockout_timeline":
        analysis = analyze_supplied_password_lockout(payload["model"])
    elif component_id == "identity_supplied_mfa_factor_rebind":
        analysis = analyze_supplied_mfa_factor_rebind(payload["model"])
    elif component_id == "identity_supplied_biometric_assurance_projection":
        analysis = analyze_supplied_biometric_assurance(payload["model"])
    elif component_id == "recon_supplied_passive_source_freshness":
        analysis = analyze_supplied_passive_sources(payload["model"])
    elif component_id == "recon_supplied_organization_relationship_provenance":
        analysis = analyze_supplied_organization_relationships(payload["model"])
    elif component_id == "crypto_supplied_kdf_policy_comparison":
        analysis = analyze_supplied_kdf_policy(payload["model"])
    elif component_id == "crypto_supplied_symmetric_nonce_reuse":
        analysis = analyze_supplied_symmetric_nonce_reuse(payload["model"])
    elif component_id == "network_supplied_switch_vlan_projection":
        analysis = analyze_supplied_switch_vlan(payload["model"])
    elif component_id == "network_supplied_firewall_rule_order":
        analysis = analyze_supplied_firewall_rule_order(payload["model"])
    elif component_id == "network_supplied_nac_admission_consistency":
        analysis = analyze_supplied_nac_admission(payload["model"])
    elif component_id == "network_supplied_wifi_policy_projection":
        analysis = analyze_supplied_wifi_policy(payload["model"])
    elif component_id == "network_supplied_snmp_view_projection":
        analysis = analyze_supplied_snmp_view(payload["model"])
    elif component_id == "network_supplied_sdwan_overlay_projection":
        analysis = analyze_supplied_sdwan_overlay(payload["model"])
    elif component_id == "api_supplied_function_authorization_differential":
        analysis = analyze_supplied_api_function_authorization(payload["model"])
    elif component_id == "api_supplied_inventory_drift":
        analysis = analyze_supplied_api_inventory_drift(payload["model"])
    elif component_id == "api_supplied_downstream_trust_flow":
        analysis = analyze_supplied_api_downstream_trust(payload["model"])
    elif component_id == "dom_supplied_dataflow_projection":
        analysis = analyze_supplied_dom_dataflow(payload["model"])
    elif component_id == "supplied_attack_graph_model":
        analysis = analyze_supplied_attack_graph(payload["model"])
    elif component_id == "web_supplied_route_authorization":
        analysis = analyze_supplied_web_route_authorization(payload["model"])
    elif component_id == "browser_supplied_message_boundary_projection":
        analysis = analyze_supplied_browser_message_boundary(payload["model"])
    elif component_id == "supplied_web_content_handling":
        analysis = analyze_supplied_web_content_handling(payload["model"])
    elif component_id == "api_supplied_webhook_callback_trust":
        analysis = analyze_supplied_webhook_callback_trust(payload["model"])
    elif component_id == "api_supplied_service_mesh_trust_projection":
        analysis = analyze_supplied_service_mesh_trust(payload["model"])
    elif component_id == "supplied_template_context":
        analysis = analyze_supplied_template_context(payload["model"])
    elif component_id == "api_supplied_partner_connector_trust_projection":
        analysis = analyze_supplied_partner_connector_trust(payload["model"])
    elif component_id == "web_supplied_service_worker_scope":
        analysis = analyze_supplied_service_worker_scope(payload["model"])
    elif component_id == "agent_supplied_tool_authority_projection":
        analysis = analyze_supplied_agent_tool_authority(payload["model"])
    elif component_id == "agent_supplied_output_handling_boundary":
        analysis = analyze_supplied_agent_output_handling(payload["model"])
    elif component_id == "agent_supplied_indirect_prompt_boundary":
        analysis = analyze_supplied_indirect_prompt_boundary(payload["model"])
    elif component_id == "rag_supplied_index_provenance":
        analysis = analyze_supplied_rag_provenance(payload["model"])
    elif component_id == "agent_supplied_memory_provenance":
        analysis = analyze_supplied_agent_memory_provenance(payload["model"])
    elif component_id == "model_supplied_pickle_opcode_safety":
        analysis = analyze_supplied_model_pickle_opcodes(payload["model"])
    elif component_id == "model_supplied_artifact_integrity":
        analysis = analyze_supplied_model_artifact_integrity(payload["model"])
    elif component_id == "model_supplied_evasion_delta_measurement":
        analysis = analyze_supplied_evasion_deltas(payload["model"])
    elif component_id == "agent_supplied_credential_boundary":
        analysis = analyze_supplied_agent_credential_boundary(payload["model"])
    elif component_id == "mlops_supplied_release_lineage":
        analysis = analyze_supplied_mlops_lineage(payload["model"])
    elif component_id == "training_supplied_label_share_drift":
        analysis = analyze_supplied_training_label_drift(payload["model"])
    elif component_id == "model_supplied_trigger_selectivity":
        analysis = analyze_supplied_model_trigger_selectivity(payload["model"])
    elif component_id == "model_supplied_output_similarity":
        analysis = analyze_supplied_model_output_similarity(payload["model"])
    elif component_id == "model_supplied_membership_score_separation":
        analysis = analyze_supplied_membership_scores(payload["model"])
    elif component_id == "model_supplied_prompt_canary_exposure":
        analysis = analyze_supplied_prompt_canaries(payload["model"])
    elif component_id == "s3_supplied_public_grant_controls":
        analysis = analyze_supplied_s3_public_grants(payload["model"])
    elif component_id == "evm_supplied_proxy_storage_layout":
        analysis = analyze_supplied_proxy_storage_layout(payload["model"])
    elif component_id == "evm_supplied_callback_state_order":
        analysis = analyze_supplied_reentrancy_state_order(payload["model"])
    elif component_id == "defi_supplied_spot_twap_deviation":
        analysis = analyze_supplied_oracle_twap(payload["model"])
    elif component_id == "bridge_supplied_duplicate_accepted_claims":
        analysis = analyze_supplied_bridge_claims(payload["model"])
    elif component_id == "governance_supplied_quorum_reconciliation":
        analysis = analyze_supplied_governance_quorum(payload["model"])
    elif component_id == "consensus_supplied_conflicting_validator_votes":
        analysis = analyze_supplied_consensus_votes(payload["model"])
    elif component_id == "wallet_supplied_signer_threshold_authorization":
        analysis = analyze_supplied_wallet_threshold(payload["model"])
    elif component_id == "rpc_supplied_cross_endpoint_response_discrepancy":
        analysis = analyze_supplied_rpc_responses(payload["model"])
    elif component_id == "evm_supplied_origin_authorization_boundary":
        analysis = analyze_supplied_evm_origin_authorization(payload["model"])
    elif component_id == "wasm_supplied_host_import_allowlist":
        analysis = analyze_supplied_wasm_host_imports(payload["model"])
    elif component_id == "token_supplied_zero_fee_transfer_arithmetic":
        analysis = analyze_supplied_token_transfers(payload["model"])
    elif component_id == "mev_supplied_outer_trade_order_pattern":
        analysis = analyze_supplied_mev_trade_order(payload["model"])
    elif component_id == "cloud_supplied_private_endpoint_path_scope":
        analysis = analyze_supplied_private_endpoint_paths(payload["model"])
    elif component_id == "cloud_supplied_kms_grant_separation":
        analysis = analyze_supplied_kms_grants(payload["model"])
    elif component_id == "cloud_supplied_unalerted_logging_disable":
        analysis = analyze_supplied_cloud_logging(payload["model"])
    elif component_id == "workspace_supplied_external_sharing_policy":
        analysis = analyze_supplied_workspace_sharing(payload["model"])
    elif component_id == "compute_supplied_private_ingress_scope":
        analysis = analyze_supplied_compute_ingress(payload["model"])
    elif component_id == "managed_paas_supplied_grant_scope":
        analysis = analyze_supplied_managed_paas_grants(payload["model"])
    elif component_id == "idp_supplied_privileged_mfa_path_policy":
        analysis = analyze_supplied_workforce_idp_mfa_paths(payload["model"])
    elif component_id == "data_cloud_supplied_grant_scope_policy":
        analysis = analyze_supplied_data_cloud_grants(payload["model"])
    elif component_id == "bacnet_supplied_device_identifier_collision":
        analysis = analyze_supplied_bacnet_device_identity(payload["model"])
    elif component_id == "ros2_supplied_security_declaration_gap":
        analysis = analyze_supplied_ros2_security(payload["model"])
    elif component_id == "iec61850_supplied_subscription_reference_consistency":
        analysis = analyze_supplied_iec61850_subscriptions(payload["model"])
    elif component_id == "cip_supplied_security_property_gap":
        analysis = analyze_supplied_cip_security(payload["model"])
    elif component_id == "acpi_supplied_table_integrity":
        analysis = analyze_supplied_acpi_table(payload["model"])
    elif component_id == "redfish_supplied_role_privilege_ceiling":
        analysis = analyze_supplied_redfish_role_privileges(payload["model"])
    elif component_id == "usb_supplied_descriptor_framing":
        analysis = analyze_supplied_usb_descriptors(payload["model"])
    elif component_id == "iommu_supplied_group_separation":
        analysis = analyze_supplied_iommu_groups(payload["model"])
    elif component_id == "ot_supplied_zone_conduit_flow_projection":
        analysis = analyze_supplied_ot_zone_conduits(payload["model"])
    elif component_id == "gpu_supplied_instance_tenant_boundary":
        analysis = analyze_supplied_gpu_tenant_boundary(payload["model"])
    elif component_id == "riscv_supplied_pmp_interval_projection":
        analysis = analyze_supplied_riscv_pmp(payload["model"])
    elif component_id == "tpm_supplied_sha256_pcr_replay":
        analysis = analyze_supplied_tpm_pcr(payload["model"])
    elif component_id == "gpu_supplied_management_node_permissions":
        analysis = analyze_supplied_gpu_management_node_permissions(payload["model"])
    elif component_id == "esrt_supplied_device_firmware_version_projection":
        analysis = analyze_supplied_esrt_update_metadata(payload["model"])
    elif component_id == "amt_supplied_control_state_policy":
        analysis = analyze_supplied_management_engine_state(payload["model"])
    elif component_id == "ot_supplied_remote_access_policy_projection":
        analysis = analyze_supplied_ot_remote_access(payload["model"])
    elif component_id == "firmware_supplied_inventory_sbom_claim_reconciliation":
        analysis = analyze_supplied_firmware_inventory_sbom(payload["model"])
    elif component_id == "secure_boot_supplied_update_chain_projection":
        analysis = analyze_supplied_secure_boot_update_chain(payload["model"])
    elif component_id == "oci_supplied_image_layer_metadata":
        analysis = analyze_supplied_oci_image_layers(payload["model"])
    elif component_id == "supplied_third_party_trust_path_projection":
        analysis = analyze_supplied_third_party_trust_paths(payload["model"])
    elif component_id == "adcs_supplied_template_rights_projection":
        analysis = analyze_supplied_adcs_template_rights(payload["model"])
    elif component_id == "vehicle_supplied_gateway_flow_projection":
        analysis = analyze_supplied_vehicle_gateway_graph(payload["model"])
    elif component_id == "vehicle_supplied_diagnostic_policy_projection":
        analysis = analyze_supplied_vehicle_diagnostic_policy(payload["model"])
    elif component_id == "vehicle_supplied_service_zone_declarations":
        analysis = analyze_supplied_vehicle_service_declarations(payload["model"])
    elif component_id == "kubernetes_supplied_api_authentication_context":
        analysis = analyze_supplied_kubernetes_api_authentication(payload["model"])
    elif component_id == "kubernetes_supplied_secret_configmap_references":
        analysis = analyze_supplied_kubernetes_secret_references(payload["model"])
    elif component_id == "oci_supplied_registry_signature_bindings":
        analysis = analyze_supplied_oci_registry_signature_bindings(payload["model"])
    elif component_id == "kubernetes_supplied_runtime_reconciliation":
        analysis = analyze_supplied_kubernetes_runtime_reconciliation(payload["model"])
    elif component_id == "container_supplied_runtime_declarations":
        analysis = analyze_supplied_container_runtime_declarations(payload["model"])
    elif component_id == "kubernetes_supplied_control_plane_declarations":
        analysis = analyze_supplied_kubernetes_control_plane_declarations(payload["model"])
    elif component_id == "supplied_container_boundary_path_projection":
        analysis = analyze_supplied_container_boundary_paths(payload["model"])
    elif component_id == "serverless_supplied_function_event_bindings":
        analysis = analyze_supplied_serverless_event_declarations(payload["model"])
    elif component_id == "multicluster_supplied_tenant_declarations":
        analysis = analyze_supplied_multicluster_tenant_declarations(payload["model"])
    elif component_id == "agent_supplied_resource_budget":
        analysis = analyze_supplied_agent_resource_budget(payload["model"])
    elif component_id == "agent_supplied_plan_revision_integrity":
        analysis = analyze_supplied_agent_plan_integrity(payload["model"])
    elif component_id == "multi_agent_supplied_coordination_trust":
        analysis = analyze_supplied_multi_agent_coordination(payload["model"])
    elif component_id == "cd_supplied_release_provenance":
        analysis = analyze_supplied_cd_release_provenance(payload["model"])
    elif component_id == "hypervisor_supplied_management_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Hypervisor payload fields are invalid")
        analysis = analyze_supplied_hypervisor_management_posture(payload["model"])
    elif component_id == "vdi_supplied_session_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("VDI payload fields are invalid")
        analysis = analyze_supplied_vdi_session_posture(payload["model"])
    elif component_id == "backup_supplied_recovery_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Backup posture payload fields are invalid")
        analysis = analyze_supplied_backup_recovery_posture(payload["model"])
    elif component_id == "storage_supplied_access_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Storage posture payload fields are invalid")
        analysis = analyze_supplied_storage_access_posture(payload["model"])
    elif component_id == "enterprise_server_supplied_management_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Enterprise server payload fields are invalid")
        analysis = analyze_supplied_enterprise_server_management(payload["model"])
    elif component_id == "rmm_supplied_control_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("RMM payload fields are invalid")
        analysis = analyze_supplied_rmm_control_posture(payload["model"])
    elif component_id == "hpc_supplied_queue_posture_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("HPC payload fields are invalid")
        analysis = analyze_supplied_hpc_queue_posture(payload["model"])
    elif component_id == "crypto_supplied_key_lifecycle_posture":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Key lifecycle payload fields are invalid")
        analysis = analyze_supplied_key_lifecycle(payload["model"])
    elif component_id == "crypto_supplied_public_key_policy":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Public-key payload fields are invalid")
        analysis = analyze_supplied_public_key_policy(payload["model"])
    elif component_id == "crypto_supplied_token_payload_views":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Token-view payload fields are invalid")
        analysis = analyze_supplied_token_payload_views(payload["model"])
    elif component_id == "exploit_supplied_coverage_seed_selection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Coverage seed payload fields are invalid")
        analysis = analyze_supplied_coverage_seeds(payload["model"])
    elif component_id == "exploit_supplied_finite_grammar_plan":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Finite grammar payload fields are invalid")
        analysis = analyze_supplied_finite_grammar(payload["model"])
    elif component_id == "exploit_supplied_path_constraint_feasibility":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Path constraint payload fields are invalid")
        analysis = analyze_supplied_path_constraints(payload["model"])
    elif component_id == "exploit_supplied_binary_reference_graph":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Binary reference payload fields are invalid")
        analysis = analyze_supplied_binary_references(payload["model"])
    elif component_id == "exploit_supplied_source_variant_tokens":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Source variant payload fields are invalid")
        analysis = analyze_supplied_source_variant_tokens(payload["model"])
    elif component_id == "exploit_supplied_happens_before_conflicts":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Happens-before payload fields are invalid")
        analysis = analyze_supplied_happens_before(payload["model"])
    elif component_id == "exploit_supplied_integer_width_arithmetic":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Integer-width payload fields are invalid")
        analysis = analyze_supplied_integer_width(payload["model"])
    elif component_id == "exploit_supplied_heap_trace_consistency":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Heap-trace payload fields are invalid")
        analysis = analyze_supplied_heap_trace(payload["model"])
    elif component_id == "exploit_supplied_chain_trial_accounting":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Chain-trial payload fields are invalid")
        analysis = analyze_supplied_chain_trials(payload["model"])
    elif component_id == "campaign_supplied_threat_scenario_graph":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Scenario payload fields are invalid")
        analysis = analyze_supplied_threat_scenario(payload["model"])
    elif component_id == "crypto_supplied_rng_sample_consistency":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("RNG sample payload fields are invalid")
        analysis = analyze_supplied_rng_samples(payload["model"])
    elif component_id == "crypto_supplied_protocol_state_graph":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Protocol state payload fields are invalid")
        analysis = analyze_supplied_crypto_protocol(payload["model"])
    elif component_id == "crypto_supplied_e2ee_epoch_membership":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("E2EE epoch payload fields are invalid")
        analysis = analyze_supplied_e2ee_epochs(payload["model"])
    elif component_id == "crypto_supplied_hybrid_kem_lineage":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Hybrid lineage payload fields are invalid")
        analysis = analyze_supplied_hybrid_kem_lineage(payload["model"])
    elif component_id == "crypto_supplied_side_channel_timing_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Timing payload fields are invalid")
        analysis = analyze_supplied_side_channel_timings(payload["model"])
    elif component_id == "crypto_supplied_custom_protocol_framing":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Custom framing payload fields are invalid")
        analysis = analyze_supplied_custom_protocol_framing(payload["model"])
    elif component_id == "crypto_supplied_digest_vector_consistency":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Digest vector payload fields are invalid")
        analysis = analyze_supplied_digest_vectors(payload["model"])
    elif component_id == "mobile_supplied_pinset_coverage_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mobile pinset payload fields are invalid")
        analysis = analyze_supplied_mobile_pinsets(payload["model"])
    elif component_id == "mobile_supplied_storage_control_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mobile storage payload fields are invalid")
        analysis = analyze_supplied_mobile_storage(payload["model"])
    elif component_id == "mobile_supplied_distribution_consistency_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mobile distribution payload fields are invalid")
        analysis = analyze_supplied_mobile_distribution(payload["model"])
    elif component_id == "desktop_supplied_ipc_boundary_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Desktop IPC payload fields are invalid")
        analysis = analyze_supplied_desktop_ipc(payload["model"])
    elif component_id == "mobile_supplied_protection_coverage_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mobile protection payload fields are invalid")
        analysis = analyze_supplied_mobile_protection(payload["model"])
    elif component_id == "macos_supplied_release_metadata_consistency":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS release payload fields are invalid")
        analysis = analyze_supplied_macos_releases(payload["model"])
    elif component_id == "network_supplied_adc_route_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("ADC route payload fields are invalid")
        analysis = analyze_supplied_adc_routes(payload["model"])
    elif component_id == "network_supplied_sip_dialog_sequence_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SIP dialog payload fields are invalid")
        analysis = analyze_supplied_sip_dialog(payload["model"])
    elif component_id == "network_supplied_traffic_cadence_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Traffic cadence payload fields are invalid")
        analysis = analyze_supplied_traffic_cadence(payload["model"])
    elif component_id == "network_supplied_ble_gatt_permission_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("BLE GATT payload fields are invalid")
        analysis = analyze_supplied_ble_gatt(payload["model"])
    elif component_id == "hardware_supplied_i2c_write_frame_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("I2C write payload fields are invalid")
        analysis = analyze_supplied_i2c_write(payload["model"])
    elif component_id == "hardware_supplied_flash_region_map_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Flash region payload fields are invalid")
        analysis = analyze_supplied_flash_regions(payload["model"])
    elif component_id == "hardware_supplied_smartcard_file_access_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Smartcard file payload fields are invalid")
        analysis = analyze_supplied_smartcard_files(payload["model"])
    elif component_id == "recon_supplied_scan_scope_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Scan scope payload fields are invalid")
        analysis = analyze_supplied_scan_scopes(payload["model"])
    elif component_id == "linux_supplied_sudo_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Sudo grant payload fields are invalid")
        analysis = analyze_supplied_sudo_grants(payload["model"])
    elif component_id == "linux_supplied_namespace_cgroup_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Namespace payload fields are invalid")
        analysis = analyze_supplied_namespace_cgroups(payload["model"])
    elif component_id == "linux_supplied_scheduled_artifact_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Scheduled artifact payload fields are invalid")
        analysis = analyze_supplied_schedules(payload["model"])
    elif component_id == "windows_supplied_mailbox_forwarding_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mailbox forwarding payload fields are invalid")
        analysis = analyze_supplied_mailbox_forwarding(payload["model"])
    elif component_id == "windows_supplied_collaboration_sharing_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Collaboration payload fields are invalid")
        analysis = analyze_supplied_collaboration_sharing(payload["model"])
    elif component_id == "windows_supplied_endpoint_assignment_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Endpoint assignment payload fields are invalid")
        analysis = analyze_supplied_endpoint_assignments(payload["model"])
    elif component_id == "windows_supplied_privilege_artifact_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Privilege artifact payload fields are invalid")
        analysis = analyze_supplied_privilege_artifacts(payload["model"])
    elif component_id == "windows_supplied_autostart_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Autostart payload fields are invalid")
        analysis = analyze_supplied_autostarts(payload["model"])
    elif component_id == "windows_supplied_admin_invocation_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Admin invocation payload fields are invalid")
        analysis = analyze_supplied_admin_invocations(payload["model"])
    elif component_id == "windows_supplied_protected_material_access_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Material access payload fields are invalid")
        analysis = analyze_supplied_material_access(payload["model"])
    elif component_id == "windows_supplied_remote_route_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Remote route payload fields are invalid")
        analysis = analyze_supplied_remote_routes(payload["model"])
    elif component_id == "windows_supplied_security_control_state_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Control state payload fields are invalid")
        analysis = analyze_supplied_control_states(payload["model"])
    elif component_id == "linux_supplied_ebpf_helper_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("eBPF helper payload fields are invalid")
        analysis = analyze_supplied_ebpf_helpers(payload["model"])
    elif component_id == "linux_supplied_shell_tool_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Shell-tool payload fields are invalid")
        analysis = analyze_supplied_shell_tools(payload["model"])
    elif component_id == "linux_supplied_logging_route_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Logging-route payload fields are invalid")
        analysis = analyze_supplied_logging_routes(payload["model"])
    elif component_id == "exploit_engineering_supplied_pe_section_permission_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("PE section-policy payload fields are invalid")
        analysis = analyze_supplied_pe_section_permissions(payload["model"])
    elif component_id == "exploit_engineering_supplied_aarch64_elf_section_permission_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("ELF section-policy payload fields are invalid")
        analysis = analyze_supplied_elf_section_permissions(payload["model"])
    elif component_id == "campaign_supplied_initial_access_chain_controls":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Initial-access payload fields are invalid")
        analysis = analyze_supplied_initial_access_chain(payload["model"])
    elif component_id == "hardware_supplied_trace_difference_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Hardware-trace payload fields are invalid")
        analysis = analyze_supplied_hardware_traces(payload["model"])
    elif component_id == "campaign_supplied_path_review_checkpoint_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Path-review payload fields are invalid")
        analysis = analyze_supplied_path_review(payload["model"])
    elif component_id == "hardware_supplied_thread_mac_frame_control_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("MAC frame-control payload fields are invalid")
        analysis = analyze_supplied_thread_frame_control(payload["model"])
    elif component_id == "campaign_supplied_privilege_transition_controls":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Privilege-transition payload fields are invalid")
        analysis = analyze_supplied_privilege_transitions(payload["model"])
    elif component_id == "exploit_engineering_supplied_windows_driver_pe_marker_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Driver-marker payload fields are invalid")
        analysis = analyze_supplied_windows_driver_pe_markers(payload["model"])
    elif component_id == "exploit_engineering_supplied_linux_module_info_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Module-info payload fields are invalid")
        analysis = analyze_supplied_linux_module_info(payload["model"])
    elif component_id == "hardware_supplied_yosys_netlist_structural_delta":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Netlist-delta payload fields are invalid")
        analysis = analyze_supplied_yosys_netlist_delta(payload["model"])
    elif component_id == "exploit_engineering_supplied_apple_kernel_macho_markers":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Apple-kernel payload fields are invalid")
        analysis = analyze_supplied_apple_kernel_macho_markers(payload["model"])
    elif component_id == "exploit_engineering_supplied_hexagon_elf32_layout":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Hexagon ELF32 payload fields are invalid")
        analysis = analyze_supplied_hexagon_elf32_layout(payload["model"])
    elif component_id == "hardware_supplied_cache_set_mapping_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cache-set payload fields are invalid")
        analysis = analyze_supplied_cache_set_projection(payload["model"])
    elif component_id == "industrial_supplied_socketcan_classical_frame_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SocketCAN payload fields are invalid")
        analysis = analyze_supplied_socketcan_classical_frames(payload["model"])
    elif component_id == "transport_supplied_mavlink2_packet_envelope":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("MAVLink payload fields are invalid")
        analysis = analyze_supplied_mavlink2_packet_envelope(payload["model"])
    elif component_id == "transport_supplied_ccsds_space_packet_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("CCSDS payload fields are invalid")
        analysis = analyze_supplied_ccsds_space_packet(payload["model"])
    elif component_id == "transport_supplied_rinex_observation_header_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("RINEX payload fields are invalid")
        analysis = analyze_supplied_rinex_observation_header(payload["model"])
    elif component_id == "transport_supplied_ais_position_report_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("AIS payload fields are invalid")
        analysis = analyze_supplied_ais_position_report(payload["model"])
    elif component_id == "transport_supplied_ocpp16_data_transfer_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OCPP payload fields are invalid")
        analysis = analyze_supplied_ocpp16_data_transfer(payload["model"])
    elif component_id == "exploit_supplied_browser_minidump_directory":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Minidump payload fields are invalid")
        analysis = analyze_supplied_browser_minidump_directory(payload["model"])
    elif component_id == "industrial_supplied_sis_bpcs_resource_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SIS/BPCS payload fields are invalid")
        analysis = analyze_supplied_sis_bpcs_resource_projection(payload["model"])
    elif component_id == "exploit_supplied_pe_packing_triage":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("PE triage payload fields are invalid")
        analysis = analyze_supplied_pe_packing_triage(payload["model"])
    elif component_id == "social_supplied_passport_claim_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("PASSporT payload fields are invalid")
        analysis = analyze_supplied_passport_claim(payload["model"])
    elif component_id == "exploit_supplied_seccomp_bpf_subset_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Seccomp payload fields are invalid")
        analysis = analyze_supplied_seccomp_bpf_subset(payload["model"])
    elif component_id == "clinical_supplied_fhir_device_association_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("FHIR payload fields are invalid")
        analysis = analyze_supplied_fhir_device_association(payload["model"])
    elif component_id == "industrial_supplied_ot_vendor_support_map":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OT vendor map payload fields are invalid")
        analysis = analyze_supplied_ot_vendor_support_map(payload["model"])
    elif component_id == "social_supplied_activitystreams_create_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("ActivityStreams payload fields are invalid")
        analysis = analyze_supplied_activitystreams_create(payload["model"])
    elif component_id == "industrial_supplied_power_recovery_cadence_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Power recovery payload fields are invalid")
        analysis = analyze_supplied_power_recovery_cadence(payload["model"])
    elif component_id == "social_supplied_operator_offboarding_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Offboarding payload fields are invalid")
        analysis = analyze_supplied_operator_offboarding(payload["model"])
    elif component_id == "social_supplied_mfa_registration_audit_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("MFA audit payload fields are invalid")
        analysis = analyze_supplied_mfa_registration_audit(payload["model"])
    elif component_id == "social_supplied_visitor_escort_record_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Visitor record payload fields are invalid")
        analysis = analyze_supplied_visitor_escort_records(payload["model"])
    elif component_id == "social_supplied_osdp_poll_frame_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OSDP payload fields are invalid")
        analysis = analyze_supplied_osdp_poll_frame(payload["model"])
    elif component_id == "social_supplied_windows_device_event_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Device event payload fields are invalid")
        analysis = analyze_supplied_windows_device_event(payload["model"])
    elif component_id == "social_supplied_email_auth_results_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Email header payload fields are invalid")
        analysis = analyze_supplied_email_auth_results(payload["model"])
    elif component_id == "social_supplied_sms_uri_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SMS URI payload fields are invalid")
        analysis = analyze_supplied_sms_uri(payload["model"])
    elif component_id == "social_supplied_oauth_consent_uri_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Consent URI payload fields are invalid")
        analysis = analyze_supplied_oauth_consent_uri(payload["model"])
    elif component_id == "social_supplied_ooxml_relationship_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OOXML payload fields are invalid")
        analysis = analyze_supplied_ooxml_relationships(payload["model"])
    elif component_id == "mobile_supplied_android_instrumentation_trace_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Android trace payload fields are invalid")
        analysis = analyze_supplied_android_instrumentation(payload["model"])
    elif component_id == "mobile_supplied_android_device_trust_trace_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Android trust payload fields are invalid")
        analysis = analyze_supplied_android_device_trust(payload["model"])
    elif component_id == "mobile_supplied_ios_instrumentation_trace_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("iOS trace payload fields are invalid")
        analysis = analyze_supplied_ios_instrumentation(payload["model"])
    elif component_id == "mobile_supplied_ios_device_trust_trace_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("iOS trust payload fields are invalid")
        analysis = analyze_supplied_ios_device_trust(payload["model"])
    elif component_id == "model_supplied_direct_instruction_boundary_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Direct boundary payload fields are invalid")
        analysis = analyze_supplied_direct_instruction_boundary(payload["model"])
    elif component_id == "model_supplied_multimodal_provenance_claim_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Media claim payload fields are invalid")
        analysis = analyze_supplied_multimodal_provenance(payload["model"])
    elif component_id == "legacy_supplied_zos_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("z/OS grant payload fields are invalid")
        analysis = analyze_supplied_zos_grants(payload["model"])
    elif component_id == "legacy_supplied_ibmi_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("IBM i grant payload fields are invalid")
        analysis = analyze_supplied_ibmi_grants(payload["model"])
    elif component_id == "legacy_supplied_unix_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Unix grant payload fields are invalid")
        analysis = analyze_supplied_unix_enterprise_grants(payload["model"])
    elif component_id == "legacy_supplied_sap_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SAP grant payload fields are invalid")
        analysis = analyze_supplied_sap_grants(payload["model"])
    elif component_id == "legacy_supplied_oracle_grant_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Oracle grant payload fields are invalid")
        analysis = analyze_supplied_oracle_enterprise_grants(payload["model"])
    elif component_id == "telecom_supplied_appliance_management_relation_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Appliance relation payload fields are invalid")
        analysis = analyze_supplied_appliance_management(payload["model"])
    elif component_id == "telecom_supplied_mobile_core_relation_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Mobile-core relation payload fields are invalid")
        analysis = analyze_supplied_mobile_core_relations(payload["model"])
    elif component_id == "telecom_supplied_signaling_route_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Signaling route payload fields are invalid")
        analysis = analyze_supplied_signaling_routes(payload["model"])
    elif component_id == "telecom_supplied_rf_receive_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("RF receive payload fields are invalid")
        analysis = analyze_supplied_rf_receive_policy(payload["model"])
    elif component_id == "telecom_supplied_oran_policy_target_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Open RAN payload fields are invalid")
        analysis = analyze_supplied_oran_policy_targets(payload["model"])
    elif component_id == "telecom_supplied_esim_profile_transition_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("eSIM transition payload fields are invalid")
        analysis = analyze_supplied_esim_profile_transitions(payload["model"])
    elif component_id == "macos_supplied_privileged_item_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS item payload fields are invalid")
        analysis = analyze_supplied_macos_privilege_items(payload["model"])
    elif component_id == "macos_supplied_security_control_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS control payload fields are invalid")
        analysis = analyze_supplied_macos_controls(payload["model"])
    elif component_id == "macos_supplied_launch_job_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS launch payload fields are invalid")
        analysis = analyze_supplied_launch_jobs(payload["model"])
    elif component_id == "macos_supplied_store_access_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS store payload fields are invalid")
        analysis = analyze_supplied_store_access(payload["model"])
    elif component_id == "macos_supplied_ipc_client_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("macOS IPC payload fields are invalid")
        analysis = analyze_supplied_ipc_clients(payload["model"])
    elif component_id == "unix_supplied_privileged_ipc_permission_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Unix IPC payload fields are invalid")
        analysis = analyze_supplied_unix_ipc(payload["model"])
    elif component_id == "network_supplied_protocol_trace_differential":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Protocol trace payload fields are invalid")
        analysis = analyze_supplied_protocol_trace_differential(payload["model"])
    elif component_id == "managed_supplied_package_feed_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Managed package payload fields are invalid")
        analysis = analyze_supplied_managed_package_feed(payload["model"])
    elif component_id == "native_supplied_target_compatibility_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Native target payload fields are invalid")
        analysis = analyze_supplied_native_target_compatibility(payload["model"])
    elif component_id == "build_supplied_reproducibility_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Build metadata payload fields are invalid")
        analysis = analyze_supplied_build_reproducibility(payload["model"])
    elif component_id == "repository_supplied_secret_occurrence_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Secret metadata payload fields are invalid")
        analysis = analyze_supplied_repository_secret_metadata(payload["model"])
    elif component_id == "iac_supplied_change_dependency_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("IaC payload fields are invalid")
        analysis = analyze_supplied_iac_change_graph(payload["model"])
    elif component_id == "devcontainer_supplied_host_boundary_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Devcontainer payload fields are invalid")
        analysis = analyze_supplied_devcontainer_boundary(payload["model"])
    elif component_id == "vendor_supplied_update_lineage_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Vendor update payload fields are invalid")
        analysis = analyze_supplied_vendor_update_lineage(payload["model"])
    elif component_id == "kubernetes_supplied_admission_policy_projection":
        analysis = analyze_supplied_kubernetes_admission_boundary(payload["model"])
    elif component_id == "cloud_supplied_multicloud_federation_projection":
        analysis = analyze_supplied_multicloud_federation(payload["model"])
    elif component_id == "java_supplied_filter_mapping_boundary":
        analysis = analyze_supplied_java_filter_boundary(payload["model"])
    elif component_id == "dotnet_supplied_middleware_order_boundary":
        analysis = analyze_supplied_dotnet_middleware_boundary(payload["model"])
    elif component_id == "web_supplied_framework_stack_projection":
        analysis = analyze_supplied_web_framework_stack(payload["model"])
    elif component_id == "web_supplied_cms_permission_graph_projection":
        analysis = analyze_supplied_cms_permission_graph(payload["model"])
    elif component_id == "browser_supplied_webrtc_signaling_projection":
        analysis = analyze_supplied_webrtc_signaling(payload["model"])
    elif component_id == "data_supplied_nosql_access_grants_projection":
        analysis = analyze_supplied_nosql_access_grants(payload["model"])
    elif component_id == "data_supplied_vector_tenant_boundary_projection":
        analysis = analyze_supplied_vector_tenant_boundary(payload["model"])
    elif component_id == "identity_supplied_entitlement_toxic_combination":
        analysis = analyze_supplied_entitlement_toxic_combination(payload["model"])
    elif component_id == "identity_supplied_session_binding_timeline":
        analysis = analyze_supplied_session_binding_timeline(payload["model"])
    elif component_id == "browser_supplied_webview_bridge_origin_projection":
        analysis = analyze_supplied_webview_bridge_origin(payload["model"])
    elif component_id == "desktop_supplied_electron_bridge_origin_projection":
        analysis = analyze_supplied_electron_bridge_origin(payload["model"])
    elif component_id == "supplied_prefix_origin_mapping":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Prefix-origin payload fields are invalid")
        analysis = analyze_supplied_prefix_origins(payload["model"])
    elif component_id == "supplied_cloud_inventory_drift":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cloud-inventory payload fields are invalid")
        analysis = analyze_supplied_cloud_inventory_drift(payload["model"])
    elif component_id == "supplied_saas_signal_correlation":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SaaS-signal payload fields are invalid")
        analysis = analyze_supplied_saas_signals(payload["model"])
    elif component_id == "supplied_credential_exposure_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Exposure payload fields are invalid")
        analysis = analyze_supplied_credential_exposure(payload["model"])
    elif component_id == "supplied_repository_reference_graph":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Repository-reference payload fields are invalid")
        analysis = analyze_supplied_repository_references(payload["model"])
    elif component_id == "supplied_technology_evidence_reconciliation":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Technology-evidence payload fields are invalid")
        analysis = analyze_supplied_technology_evidence(payload["model"])
    elif component_id == "supplied_deception_cue_reconciliation":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Deception-cue payload fields are invalid")
        analysis = analyze_supplied_deception_cues(payload["model"])
    elif component_id == "supplied_price_rounding_arithmetic":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Price-rounding payload fields are invalid")
        analysis = analyze_supplied_price_rounding(payload["model"])
    elif component_id == "supplied_debit_idempotency_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Debit-timeline payload fields are invalid")
        analysis = analyze_supplied_debit_timeline(payload["model"])
    elif component_id == "supplied_workflow_state_replay":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Workflow-state payload fields are invalid")
        analysis = analyze_supplied_workflow_states(payload["model"])
    elif component_id == "supplied_coupon_redemption_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Coupon-redemption payload fields are invalid")
        analysis = analyze_supplied_coupon_redemptions(payload["model"])
    elif component_id == "supplied_consent_purpose_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Consent-purpose payload fields are invalid")
        analysis = analyze_supplied_consent_purposes(payload["model"])
    elif component_id == "supplied_account_recovery_threshold":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Account-recovery payload fields are invalid")
        analysis = analyze_supplied_account_recovery(payload["model"])
    elif component_id == "supplied_tenant_ownership_reconciliation":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Tenant-ownership payload fields are invalid")
        analysis = analyze_supplied_tenant_ownership(payload["model"])
    elif component_id == "supplied_auction_bid_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Auction-bid payload fields are invalid")
        analysis = analyze_supplied_auction_bids(payload["model"])
    elif component_id == "supplied_payment_reversal_ledger":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Payment-reversal payload fields are invalid")
        analysis = analyze_supplied_payment_reversals(payload["model"])
    elif component_id == "supplied_cross_channel_balance":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cross-channel payload fields are invalid")
        analysis = analyze_supplied_cross_channel_balance(payload["model"])
    elif component_id == "supplied_scalping_window_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Scalping-window payload fields are invalid")
        analysis = analyze_supplied_scalping_windows(payload["model"])
    elif component_id == "supplied_fraud_decision_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Fraud-decision payload fields are invalid")
        analysis = analyze_supplied_fraud_decisions(payload["model"])
    elif component_id == "supplied_directory_entitlement_path":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Directory-path payload fields are invalid")
        analysis = analyze_supplied_directory_paths(payload["model"])
    elif component_id == "supplied_directory_trust_paths":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Directory-trust payload fields are invalid")
        analysis = analyze_supplied_directory_trusts(payload["model"])
    elif component_id == "supplied_entra_role_claim_review":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Entra-role payload fields are invalid")
        analysis = analyze_supplied_entra_role_claims(payload["model"])
    elif component_id == "supplied_kerberos_ad_declarations":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Kerberos AD payload fields are invalid")
        analysis = analyze_supplied_kerberos_ad(payload["model"])
    elif component_id == "supplied_ntlm_control_pairs":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("NTLM control payload fields are invalid")
        analysis = analyze_supplied_ntlm_control_pairs(payload["model"])
    elif component_id == "supplied_dc_topology_declarations":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Domain controller payload fields are invalid")
        analysis = analyze_supplied_dc_topology(payload["model"])
    elif component_id == "supplied_hybrid_identity_mappings":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Hybrid identity payload fields are invalid")
        analysis = analyze_supplied_hybrid_identity_mappings(payload["model"])
    elif component_id == "secondary_cloud_supplied_control_declarations":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Secondary cloud payload fields are invalid")
        analysis = analyze_supplied_secondary_cloud_controls(payload["model"])
    elif component_id == "cloud_org_supplied_support_billing_boundary":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cloud organization payload fields are invalid")
        analysis = analyze_supplied_cloud_org_support_billing(payload["model"])
    elif component_id == "saas_supplied_tenant_admin_delegation":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("SaaS admin payload fields are invalid")
        analysis = analyze_supplied_enterprise_saas_admin(payload["model"])
    elif component_id == "cloud_supplied_post_compromise_control_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cloud timeline payload fields are invalid")
        analysis = analyze_supplied_cloud_post_compromise(payload["model"])
    elif component_id == "ot_supplied_controller_configuration":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OT controller payload fields are invalid")
        analysis = analyze_supplied_ot_controller_configuration(payload["model"])
    elif component_id == "ot_supplied_hmi_tag_mapping":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OT HMI payload fields are invalid")
        analysis = analyze_supplied_ot_hmi_tag_mapping(payload["model"])
    elif component_id == "ot_supplied_engineering_project_provenance":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("OT engineering payload fields are invalid")
        analysis = analyze_supplied_ot_engineering_project_provenance(payload["model"])
    elif component_id == "firmware_supplied_emulation_trace_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Firmware emulation payload fields are invalid")
        analysis = analyze_supplied_firmware_emulation_trace(payload["model"])
    elif component_id == "firmware_supplied_rtos_task_policy_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Firmware RTOS payload fields are invalid")
        analysis = analyze_supplied_firmware_rtos_task_policy(payload["model"])
    elif component_id == "firmware_supplied_debug_interface_inventory_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Firmware debug payload fields are invalid")
        analysis = analyze_supplied_firmware_debug_interface_inventory(payload["model"])
    elif component_id == "firmware_supplied_secure_element_assertions_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError(
                "Firmware secure-element payload fields are invalid"
            )
        analysis = analyze_supplied_firmware_secure_element_assertions(payload["model"])
    elif component_id == "firmware_supplied_tamper_provenance_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Firmware tamper payload fields are invalid")
        analysis = analyze_supplied_firmware_tamper_provenance(payload["model"])
    elif component_id == "supplied_relational_grant_path":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Relational-grant payload fields are invalid")
        analysis = analyze_supplied_relational_grants(payload["model"])
    elif component_id == "supplied_graph_tenant_routes":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Graph-tenant payload fields are invalid")
        analysis = analyze_supplied_graph_tenant_routes(payload["model"])
    elif component_id == "supplied_search_alias_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Search-alias payload fields are invalid")
        analysis = analyze_supplied_search_alias(payload["model"])
    elif component_id == "supplied_backup_chain_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Backup-chain payload fields are invalid")
        analysis = analyze_supplied_backup_chain(payload["model"])
    elif component_id == "supplied_stream_offset_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Stream-offset payload fields are invalid")
        analysis = analyze_supplied_stream_offsets(payload["model"])
    elif component_id == "supplied_warehouse_lineage":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Warehouse-lineage payload fields are invalid")
        analysis = analyze_supplied_warehouse_lineage(payload["model"])
    elif component_id == "supplied_spark_job_plan":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Spark-plan payload fields are invalid")
        analysis = analyze_supplied_spark_job_plan(payload["model"])
    elif component_id == "supplied_analytics_sharing":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Analytics-sharing payload fields are invalid")
        analysis = analyze_supplied_analytics_sharing(payload["model"])
    elif component_id == "supplied_archive_member_paths":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Archive-member payload fields are invalid")
        analysis = analyze_supplied_archive_member_paths(payload["model"])
    elif component_id == "supplied_dns_scope_timeline":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("DNS-scope payload fields are invalid")
        analysis = analyze_supplied_dns_scope_timeline(payload["model"])
    elif component_id == "supplied_etl_watermark_projection":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("ETL-watermark payload fields are invalid")
        analysis = analyze_supplied_etl_watermarks(payload["model"])
    elif component_id == "supplied_json_key_policy_differential":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("JSON-key payload fields are invalid")
        analysis = analyze_supplied_json_key_policies(payload["model"])
    elif component_id == "supplied_pickle_opcode_inventory":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Pickle-opcode payload fields are invalid")
        analysis = analyze_supplied_pickle_opcodes(payload["model"])
    elif component_id == "supplied_cross_surface_authorization":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cross-surface payload fields are invalid")
        analysis = analyze_supplied_cross_surface_authorization(payload["model"])
    elif component_id == "supplied_cross_channel_session":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Cross-channel payload fields are invalid")
        analysis = analyze_supplied_cross_channel_session(payload["model"])
    elif component_id == "supplied_request_origin_trust":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Request-origin payload fields are invalid")
        analysis = analyze_supplied_request_origin_trust(payload["model"])
    elif component_id == "supplied_toctou_state_schedule":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("TOCTOU-state payload fields are invalid")
        analysis = analyze_supplied_toctou_state_schedule(payload["model"])
    elif component_id == "supplied_resource_expansion_budget":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Resource-budget payload fields are invalid")
        analysis = analyze_supplied_resource_expansion_budget(payload["model"])
    elif component_id == "supplied_dependency_fail_closed":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Dependency-fallback payload fields are invalid")
        analysis = analyze_supplied_dependency_fail_closed(payload["model"])
    elif component_id == "supplied_configuration_defaults":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError(
                "Configuration-defaults payload fields are invalid"
            )
        analysis = analyze_supplied_configuration_defaults(payload["model"])
    elif component_id == "supplied_confused_deputy_boundary":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Deputy-boundary payload fields are invalid")
        analysis = analyze_supplied_confused_deputy_boundary(payload["model"])
    elif component_id == "supplied_integrity_poisoning":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Integrity-poisoning payload fields are invalid")
        analysis = analyze_supplied_integrity_poisoning(payload["model"])
    elif component_id == "supplied_query_input_boundary":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Query-input payload fields are invalid")
        analysis = analyze_supplied_query_input_boundary(payload["model"])
    elif component_id == "supplied_interpreter_input_boundary":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError("Interpreter-input payload fields are invalid")
        analysis = analyze_supplied_interpreter_input_boundary(payload["model"])
    elif component_id == "supplied_observable_discrepancy":
        if payload.keys() != {"model"}:
            raise OfflineSpecialistComponentError(
                "Observable-discrepancy payload fields are invalid"
            )
        analysis = analyze_supplied_observable_discrepancy(payload["model"])
    else:
        raise OfflineSpecialistComponentError("Registered component has no fixed dispatcher")
    body = {
        "schema_version": 1,
        "catalog_id": verified.to_dict()["catalog_id"],
        "catalog_sha256": verified.to_dict()["catalog_sha256"],
        "component": descriptor,
        "request_sha256": _canonical_sha256(owned),
        "input_provenance": "operator_supplied_unverified",
        "source_hash_profile": "canonical_native_request_with_embedded_source_text",
        "analysis": analysis.to_dict(),
        "operational_effects": dict(EFFECTS),
        "full_candidate_assembled": False,
        "positive_use_approved": False,
    }
    identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
    return {**body, "result_id": identifier, "result_sha256": digest}


def verify_offline_specialist_component_result(
    result: dict[str, Any],
    *,
    request: dict[str, Any],
    catalog: OfflineSpecialistComponentCatalog,
    repository_root: str | Path,
) -> dict[str, Any]:
    """Replay original source/config input and current bindings, never accept digest-only claims."""

    expected = run_offline_specialist_component(
        request, catalog=catalog, repository_root=repository_root
    )
    _same(result, expected, "Offline analysis result", maximum_bytes=MAX_REQUEST_BYTES)
    return expected
