"""Closed inert analysis dispatch, source ownership, replay and no-promotion regressions."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import run_offline_specialist_component as component_cli
from sunderkey import offline_specialist_components as component_module
from sunderkey.candidate_adapter_sdk import REFERENCE_PROFILES
from sunderkey.offline_cors_analysis import CorsAnalysisError
from sunderkey.offline_dns_message_analysis import DnsMessageAnalysisError
from sunderkey.offline_mqtt_topic_analysis import MqttTopicAnalysisError
from sunderkey.offline_specialist_components import (
    CATALOG_DOMAIN,
    COMPONENTS,
    FOUNDATION_PATHS,
    INTEGRATION_PATHS,
    MAX_CATALOG_BYTES,
    MAX_REQUEST_BYTES,
    STRATEGY_PATH,
    RESULT_DOMAIN,
    OfflineSpecialistComponentCatalog,
    OfflineSpecialistComponentError,
    _address,
    _native,
    _parse,
    build_offline_specialist_component_catalog,
    load_offline_specialist_component_request,
    parse_offline_specialist_component_request,
    prepare_offline_specialist_component_request,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)
from sunderkey.qualification import _canonical_json

ROOT = Path(__file__).resolve().parents[2]
NEW_SUPPLIED_MODEL_COMPONENTS = (
    (
        "offline-posix-acl-component.json",
        "linux_supplied_posix_acl_arithmetic",
        "AOE-GC-D12-S01",
        "analyze_supplied_posix_acl",
    ),
    (
        "offline-aws-vpc-flow-component.json",
        "aws_supplied_vpc_flow_predicates",
        "AOE-GC-D14-S03",
        "analyze_supplied_aws_vpc_flow",
    ),
    (
        "offline-postgresql-rls-component.json",
        "postgresql_supplied_select_rls",
        "AOE-GB-D07-S14",
        "analyze_supplied_postgresql_rls",
    ),
)
PROTOCOL_POD_DATA_COMPONENTS = (
    (
        "offline-websocket-frame-component.json",
        "websocket_supplied_frame_state",
        "AOE-GB-D06-S05",
        "analyze_supplied_websocket_frames",
    ),
    (
        "offline-kubernetes-pod-security-component.json",
        "kubernetes_supplied_linux_pod_security_controls",
        "AOE-GC-D15-S05",
        "analyze_supplied_kubernetes_pod_security",
    ),
    (
        "offline-redis-acl-component.json",
        "redis_supplied_acl_key_selectors",
        "AOE-GB-D07-S05",
        "analyze_supplied_redis_acl",
    ),
)
BGP_WHEEL_AMQP_COMPONENTS = (
    (
        "offline-bgp-update-component.json",
        "bgp_supplied_update_structure",
        "AOE-GC-D13-S02",
        "analyze_supplied_bgp_update",
        "BGPA-F2A0501B056602E2E5081C3D52955BE9",
        "sunderkey.offline-bgp-update-analysis.v1",
        "BGPA-",
    ),
    (
        "offline-wheel-record-component.json",
        "wheel_supplied_zip_record_integrity",
        "AOE-GC-D17-S05",
        "analyze_supplied_wheel_record",
        "WRA-AEAFD0AEC743831D9C04F1A251D5FF2A",
        "sunderkey.offline-wheel-record-analysis.v1",
        "WRA-",
    ),
    (
        "offline-amqp091-content-component.json",
        "amqp091_supplied_publish_content_assembly",
        "AOE-GB-D07-S07",
        "analyze_supplied_amqp091_content",
        "AMQA-50544EB621585EAD1578D248F0B94A78",
        "sunderkey.offline-amqp091-content-analysis.v1",
        "AMQA-",
    ),
)
DNS_CORS_COMPONENTS = (
    (
        "offline-dns-zone-component.json",
        "dns_supplied_zone_lookup",
        "AOE-GA-D01-S03",
        "analyze_supplied_dns_zone",
    ),
    (
        "offline-dns-message-component.json",
        "dns_supplied_wire_structure",
        "AOE-GC-D13-S03",
        "analyze_supplied_dns_message",
    ),
    (
        "offline-cors-component.json",
        "cors_supplied_negotiation_and_exposure",
        "AOE-GB-D05-S14",
        "analyze_supplied_cors",
    ),
)
OCI_TLS_COOKIE_COMPONENTS = (
    (
        "offline-oci-blob-component.json",
        "oci_supplied_blob_graph_integrity",
        "AOE-GC-D17-S10",
        "analyze_supplied_oci_blob_graph",
    ),
    (
        "offline-tls-hello-component.json",
        "tls13_supplied_hello_offer_selection",
        "AOE-GE-D22-S02",
        "analyze_supplied_tls_hello_pair",
    ),
    (
        "offline-cookie-selection-component.json",
        "retained_cookie_candidate_predicates",
        "AOE-GB-D05-S11",
        "analyze_supplied_cookie_selection",
    ),
)
SEMVER_CACHE_COMPONENTS = (
    (
        "offline-semver-interval-component.json",
        "javascript_supplied_semver_interval_arithmetic",
        "AOE-GC-D17-S04",
        "analyze_supplied_semver_intervals",
    ),
    (
        "offline-http-cache-freshness-component.json",
        "http_supplied_cache_freshness_arithmetic",
        "AOE-GB-D05-S02",
        "analyze_supplied_http_cache_freshness",
    ),
)
DECLARATION_ENDPOINT_COMPONENTS = (
    (
        "offline-azure-nsg-component.json",
        "azure_supplied_nsg_directional_predicates",
        "AOE-GC-D14-S05",
        "analyze_supplied_azure_nsg",
    ),
    (
        "offline-android-component.json",
        "android_supplied_component_declarations",
        "AOE-GB-D08-S03",
        "analyze_supplied_android_components",
    ),
    (
        "offline-kubernetes-service-component.json",
        "kubernetes_supplied_service_endpoint_consistency",
        "AOE-GC-D15-S07",
        "analyze_supplied_kubernetes_service_endpoints",
    ),
)
FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS = (
    (
        "offline-gcp-firewall-component.json",
        "gcp_supplied_vpc_firewall_new_flow_predicates",
        "AOE-GC-D14-S07",
        "analyze_supplied_gcp_firewall",
    ),
    (
        "offline-ios-entitlement-component.json",
        "ios_supplied_entitlement_declaration_consistency",
        "AOE-GB-D08-S07",
        "analyze_supplied_ios_entitlements",
    ),
    (
        "offline-mqtt-topic-component.json",
        "mqtt_supplied_topic_filter_arithmetic",
        "AOE-GD-D18-S15",
        "analyze_supplied_mqtt_topics",
    ),
)
PROTOCOL_ARTIFACT_COMPONENTS = (
    (
        "offline-modbus-tcp-component.json",
        "modbus_supplied_tcp_read_exchange_structure",
        "AOE-GD-D19-S06",
        "analyze_supplied_modbus_tcp",
    ),
    (
        "offline-android-dex-component.json",
        "android_supplied_dex035_structure",
        "AOE-GB-D08-S01",
        "analyze_supplied_android_dex",
    ),
    (
        "offline-csp-fetch-component.json",
        "csp_supplied_external_fetch_predicates",
        "AOE-GB-D05-S14",
        "analyze_supplied_csp_fetch",
    ),
)


WIRE_MOBILE_COMPONENTS = (
    (
        "offline-macho-component.json",
        "ios_supplied_macho64_layout",
        "AOE-GB-D08-S05",
        "analyze_supplied_macho_layout",
    ),
    (
        "offline-protobuf-wire-component.json",
        "protobuf_supplied_wire_occurrences",
        "AOE-GB-D06-S03",
        "analyze_supplied_protobuf_wire",
    ),
    (
        "offline-coap-component.json",
        "coap_supplied_get_piggyback_structure",
        "AOE-GD-D18-S15",
        "analyze_supplied_coap",
    ),
)


BINARY_DHCP_COMPONENTS = (
    (
        "offline-elf64-layout-component.json",
        "linux_supplied_elf64_layout",
        "AOE-GB-D08-S17",
        "analyze_supplied_elf64_layout",
        "flags",
    ),
    (
        "offline-pe32-layout-component.json",
        "windows_supplied_pe32plus_layout",
        "AOE-GB-D08-S15",
        "analyze_supplied_pe32plus_layout",
        "flags",
    ),
    (
        "offline-dhcpv4-component.json",
        "dhcpv4_supplied_offer_ack_structure",
        "AOE-GC-D13-S03",
        "analyze_supplied_dhcpv4",
        "flags",
    ),
)


def request(profile_id: str, payload: dict) -> dict:
    return {
        "schema_version": 1,
        "profile_id": profile_id,
        "environment": "synthetic",
        "action_tier": "R0",
        "dry_run": True,
        "credential_refs": [],
        "resources": {"network": [], "filesystem": [], "process": [], "credential": []},
        "payload": payload,
    }


def graphql_request() -> dict:
    schema = {
        "query_type": "Query",
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "users", "type": "[User!]!"}]},
            {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "type": "ID!"}]},
            {"name": "ID", "kind": "SCALAR", "fields": []},
        ],
    }
    return request(
        "AOE-GB-D06-S02",
        {
            "schema_content": json.dumps(schema),
            "query_content": "{ users { first: id second: id } }",
            "schema_source_id": "fixture.schema",
            "query_source_id": "fixture.query",
            "operation_name": None,
            "limits": {
                "max_schema_bytes": 4096,
                "max_query_bytes": 4096,
                "max_depth": 8,
                "max_tokens": 128,
                "max_nodes": 128,
                "max_expanded_selections": 128,
            },
        },
    )


def kubernetes_request() -> dict:
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "reader", "namespace": "test"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "reader-binding", "namespace": "test"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
        "subjects": [{"kind": "User", "name": "tester", "apiGroup": "rbac.authorization.k8s.io"}],
    }
    query = {
        "query_id": "get-pod",
        "principal": "tester",
        "groups": [],
        "namespace": "test",
        "resource_scope": "namespaced",
        "api_group": "",
        "resource": "pods",
        "subresource": "",
        "verb": "get",
        "name": "fixture-pod",
        "field_selector": "",
    }
    return request("AOE-GC-D15-S04", {"snapshot": {"objects": [role, binding]}, "queries": [query]})


class OfflineSpecialistComponentsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.catalog_document = cls.catalog.to_dict()

    def run_component(self, value: dict) -> dict:
        # The class setup verifies current source bytes once. Leaf behavior
        # tests reuse that exact catalog instead of rescanning all sources.
        with patch.object(
            component_module, "_catalog_document", return_value=self.catalog_document
        ):
            return run_offline_specialist_component(
                value, catalog=self.catalog, repository_root=ROOT
            )

    def verify_component(
        self,
        result: dict,
        *,
        request: dict,
        catalog: OfflineSpecialistComponentCatalog,
        repository_root: str | Path,
    ) -> dict:
        # The catalog and its source bytes were checked in setUpClass. Replay
        # the exact supplied request without repeating that source scan for
        # every leaf assertion. Dedicated tests still exercise fresh-source
        # invalidation through the unpatched production entry points.
        self.assertIs(catalog, self.catalog)
        self.assertEqual(Path(repository_root).resolve(), ROOT)
        with patch.object(
            component_module, "_catalog_document", return_value=self.catalog_document
        ):
            return verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=repository_root
            )

    def test_leaf_helper_reuses_checked_catalog_without_source_rescan(self) -> None:
        with patch.object(component_module, "_read_source", side_effect=AssertionError):
            result = self.run_component(graphql_request())
        self.assertEqual(result["component"]["profile_id"], "AOE-GB-D06-S02")
        self.assertFalse(result["positive_use_approved"])

    def test_published_catalog_fits_bound_and_round_trips_current_sources(self) -> None:
        content = (ROOT / "registry/offline-specialist-components-v1.json").read_bytes()
        self.assertLessEqual(len(content), MAX_CATALOG_BYTES)
        loaded = component_module.load_offline_specialist_component_catalog(repository_root=ROOT)
        self.assertEqual(loaded.to_dict(), self.catalog.to_dict())

    def test_foundation_cache_reuses_exact_bytes_and_rejects_stale_source(self) -> None:
        component_module._validated_foundation_program.cache_clear()
        original_read = component_module._read_source
        try:
            first = build_offline_specialist_component_catalog(repository_root=ROOT)
            second = build_offline_specialist_component_catalog(repository_root=ROOT)
            self.assertEqual(first.to_dict(), second.to_dict())
            self.assertEqual(component_module._validated_foundation_program.cache_info().misses, 1)
            self.assertEqual(component_module._validated_foundation_program.cache_info().hits, 1)

            def changed_read(repository_root: str | Path, relative_path: str) -> bytes:
                content = original_read(repository_root, relative_path)
                if relative_path == FOUNDATION_PATHS[4]:
                    return content + b"\n"
                return content

            with patch.object(component_module, "_read_source", side_effect=changed_read):
                changed = build_offline_specialist_component_catalog(repository_root=ROOT)
                self.assertNotEqual(first.to_dict()["catalog_id"], changed.to_dict()["catalog_id"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    component_module.OfflineSpecialistComponentCatalog.from_dict(
                        first.to_dict(), repository_root=ROOT
                    )
            self.assertEqual(component_module._validated_foundation_program.cache_info().misses, 2)
        finally:
            component_module._validated_foundation_program.cache_clear()

    def test_catalog_binds_partial_components_without_replacing_six_reference_slice(
        self,
    ) -> None:
        document = self.catalog.to_dict()
        self.assertEqual(len(REFERENCE_PROFILES), 6)
        self.assertEqual(
            document["coverage_summary"]["offline_algorithm_component_count"],
            len(COMPONENTS),
        )
        self.assertEqual(
            document["coverage_summary"]["partial_specialist_profile_count"],
            len({descriptor[0] for descriptor in COMPONENTS}),
        )
        self.assertEqual(document["coverage_summary"]["phase158_ready_candidate_count"], 0)
        components = {item["profile_id"]: item for item in document["components"]}
        self.assertEqual(components["AOE-GB-D06-S02"]["scheduled_wave_id"], "IW2-009")
        self.assertEqual(components["AOE-GC-D15-S04"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GC-D14-S01"]["scheduled_wave_id"], "IW2-004")
        self.assertEqual(components["AOE-GB-D06-S03"]["scheduled_wave_id"], "IW2-010")
        self.assertEqual(components["AOE-GE-D22-S03"]["scheduled_wave_id"], "IW2-016")
        self.assertEqual(components["AOE-GB-D05-S03"]["scheduled_wave_id"], "IW2-003")
        self.assertEqual(components["AOE-GC-D14-S04"]["scheduled_wave_id"], "IW2-007")
        self.assertEqual(components["AOE-GB-D06-S04"]["scheduled_wave_id"], "IW2-011")
        self.assertEqual(components["AOE-GC-D14-S06"]["scheduled_wave_id"], "IW2-009")
        self.assertEqual(components["AOE-GA-D03-S05"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GB-D06-S01"]["scheduled_wave_id"], "IW2-008")
        self.assertEqual(components["AOE-GC-D11-S05"]["scheduled_wave_id"], "IW2-005")
        self.assertEqual(components["AOE-GC-D15-S07"]["scheduled_wave_id"], "IW2-009")
        self.assertEqual(components["AOE-GC-D13-S02"]["scheduled_wave_id"], "IW2-005")
        self.assertEqual(components["AOE-GA-D01-S04"]["scheduled_wave_id"], "IW2-004")
        self.assertEqual(components["AOE-GA-D01-S05"]["scheduled_wave_id"], "IW2-005")
        self.assertEqual(components["AOE-GA-D01-S06"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GA-D01-S08"]["scheduled_wave_id"], "IW2-008")
        self.assertEqual(components["AOE-GA-D01-S07"]["scheduled_wave_id"], "IW2-007")
        self.assertEqual(components["AOE-GB-D09-S02"]["scheduled_wave_id"], "IW2-002")
        self.assertEqual(components["AOE-GB-D09-S03"]["scheduled_wave_id"], "IW2-003")
        self.assertEqual(components["AOE-GB-D09-S01"]["scheduled_wave_id"], "IW2-001")
        self.assertEqual(components["AOE-GB-D09-S07"]["scheduled_wave_id"], "IW2-007")
        self.assertEqual(components["AOE-GB-D09-S11"]["scheduled_wave_id"], "IW2-011")
        self.assertEqual(components["AOE-GB-D09-S05"]["scheduled_wave_id"], "IW2-005")
        self.assertEqual(components["AOE-GB-D09-S06"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GB-D09-S08"]["scheduled_wave_id"], "IW2-008")
        self.assertEqual(components["AOE-GB-D09-S04"]["scheduled_wave_id"], "IW2-004")
        self.assertEqual(components["AOE-GB-D09-S12"]["scheduled_wave_id"], "IW2-012")
        self.assertEqual(components["AOE-GB-D09-S09"]["scheduled_wave_id"], "IW2-009")
        self.assertEqual(components["AOE-GB-D09-S10"]["scheduled_wave_id"], "IW2-010")
        self.assertEqual(components["AOE-GC-D11-S01"]["scheduled_wave_id"], "IW2-001")
        self.assertEqual(components["AOE-GC-D11-S06"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GC-D11-S14"]["scheduled_wave_id"], "IW2-014")
        self.assertEqual(components["AOE-GA-D01-S10"]["scheduled_wave_id"], "IW2-010")
        self.assertEqual(components["AOE-GA-D01-S12"]["scheduled_wave_id"], "IW2-012")
        self.assertEqual(components["AOE-GB-D07-S01"]["scheduled_wave_id"], "IW2-001")
        self.assertEqual(components["AOE-GB-D07-S06"]["scheduled_wave_id"], "IW2-006")
        self.assertEqual(components["AOE-GB-D07-S13"]["scheduled_wave_id"], "IW2-013")
        self.assertEqual(components["AOE-GB-D07-S08"]["scheduled_wave_id"], "IW2-008")
        self.assertEqual(components["AOE-GB-D07-S11"]["scheduled_wave_id"], "IW2-011")
        self.assertEqual(components["AOE-GC-D17-S05"]["scheduled_wave_id"], "IW2-017")
        self.assertEqual(components["AOE-GB-D07-S07"]["scheduled_wave_id"], "IW2-007")
        self.assertEqual(components["AOE-GA-D03-S04"]["scheduled_wave_id"], "IW2-005")
        self.assertEqual(components["AOE-GA-D03-S13"]["scheduled_wave_id"], "IW2-014")
        self.assertEqual(components["AOE-GD-D20-S19"]["scheduled_wave_id"], "IW2-001")
        self.assertEqual(components["AOE-GD-D20-S20"]["scheduled_wave_id"], "IW2-002")
        self.assertEqual(components["AOE-GD-D20-S14"]["scheduled_wave_id"], "IW2-004")
        self.assertEqual(components["AOE-GD-D20-S13"]["scheduled_wave_id"], "IW2-017")
        self.assertEqual(components["AOE-GD-D20-S10"]["scheduled_wave_id"], "IW2-014")
        self.assertEqual(components["AOE-GD-D20-S11"]["scheduled_wave_id"], "IW2-015")
        self.assertEqual(components["AOE-GD-D20-S16"]["scheduled_wave_id"], "IW2-018")
        self.assertEqual(components["AOE-GC-D17-S03"]["scheduled_wave_id"], "IW2-015")
        self.assertEqual(components["AOE-GC-D15-S08"]["scheduled_wave_id"], "IW2-010")
        self.assertEqual(components["AOE-GC-D14-S09"]["scheduled_wave_id"], "IW2-012")
        for suffix, wave in ((6, 6), (7, 7), (8, 8), (17, 17), (18, 18)):
            self.assertEqual(
                components[f"AOE-GB-D05-S{suffix:02}"]["scheduled_wave_id"],
                f"IW2-{wave:03}",
            )
        for profile_id, wave_id in (
            ("AOE-GB-D07-S02", "IW2-002"),
            ("AOE-GB-D07-S04", "IW2-004"),
            ("AOE-GA-D03-S14", "IW2-015"),
            ("AOE-GA-D03-S16", "IW2-017"),
            ("AOE-GB-D08-S12", "IW2-016"),
            ("AOE-GB-D08-S18", "IW2-004"),
        ):
            self.assertEqual(components[profile_id]["scheduled_wave_id"], wave_id)
        aws_components = [
            item for item in document["components"] if item["profile_id"] == "AOE-GC-D14-S01"
        ]
        self.assertEqual(
            {item["component_id"] for item in aws_components},
            {
                "aws_organizations_supplied_scp_path",
                "aws-identity-policy-set-v1",
                "aws-supplied-identity-scp-pair-v1",
            },
        )
        for item in document["components"]:
            self.assertEqual(item["implementation_boundary"], "offline_algorithm_component")
            for field in (
                "full_candidate_assembled",
                "qualified",
                "routable",
                "deployed",
                "phase158_entry_approved",
            ):
                self.assertIs(item[field], False)
        document["components"].clear()
        self.assertEqual(len(self.catalog.to_dict()["components"]), len(COMPONENTS))

    def test_agent_output_handling_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-agent-output-handling-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_defi_bridge_governance_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-oracle-twap-deviation-component.json",
            "offline-bridge-claim-replay-component.json",
            "offline-governance-quorum-reconciliation-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_consensus_wallet_rpc_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-consensus-vote-equivocation-component.json",
            "offline-wallet-threshold-authorization-component.json",
            "offline-rpc-response-discrepancy-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_ledger_core_market_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-evm-origin-authorization-component.json",
            "offline-wasm-host-import-boundary-component.json",
            "offline-token-transfer-arithmetic-component.json",
            "offline-mev-trade-order-pattern-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_cloud_control_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-private-endpoint-path-component.json",
            "offline-kms-grant-separation-component.json",
            "offline-cloud-logging-guardrail-timeline-component.json",
            "offline-workspace-external-sharing-component.json",
            "offline-compute-ingress-scope-component.json",
            "offline-managed-paas-grant-scope-component.json",
            "offline-workforce-idp-mfa-paths-component.json",
            "offline-data-cloud-grant-scope-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_ot_policy_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-bacnet-device-identity-component.json",
            "offline-ros2-security-declaration-component.json",
            "offline-iec61850-subscription-refs-component.json",
            "offline-cip-security-declaration-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_platform_declaration_dispatch_and_replay_remain_inert(self) -> None:
        for filename in (
            "offline-acpi-table-integrity-component.json",
            "offline-redfish-role-privileges-component.json",
            "offline-usb-descriptor-framing-component.json",
            "offline-iommu-group-separation-component.json",
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], 1)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_indirect_prompt_boundary_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-indirect-prompt-boundary-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_rag_provenance_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-rag-provenance-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 2)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_agent_memory_provenance_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-agent-memory-provenance-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 2)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_pickle_opcode_safety_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-pickle-opcode-safety-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["analysis"]["deserialization_performed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_model_artifact_integrity_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-model-artifact-integrity-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 2)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["analysis"]["provider_fetch_performed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_evasion_delta_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-evasion-delta-measurement-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["analysis"]["model_evaluation_performed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_agent_credential_boundary_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-agent-credential-boundary-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 4)
        self.assertEqual(result["analysis"]["unknown_count"], 1)
        self.assertFalse(result["analysis"]["credential_use_performed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_mlops_lineage_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-mlops-lineage-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 2)
        self.assertEqual(result["analysis"]["unknown_count"], 2)
        self.assertFalse(result["analysis"]["stage_execution_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_training_label_drift_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-training-label-drift-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 2)
        self.assertEqual(result["analysis"]["unknown_count"], 0)
        self.assertFalse(result["analysis"]["training_data_read"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_model_trigger_selectivity_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-model-trigger-selectivity-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 2)
        self.assertFalse(result["analysis"]["model_evaluation_performed"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_ai_output_score_and_canary_dispatch_remain_inert(self) -> None:
        for filename, expected_candidates in (
            ("offline-model-output-similarity-component.json", 1),
            ("offline-membership-score-separation-component.json", 1),
            ("offline-prompt-canary-exposure-component.json", 1),
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], expected_candidates)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_s3_and_contract_state_dispatch_remain_inert(self) -> None:
        for filename, expected_candidates in (
            ("offline-s3-public-grant-controls-component.json", 2),
            ("offline-proxy-storage-layout-component.json", 2),
            ("offline-reentrancy-state-order-component.json", 1),
        ):
            with self.subTest(filename=filename):
                request = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(request)
                self.assertEqual(result["analysis"]["candidate_count"], expected_candidates)
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_agent_resource_budget_dispatch_and_replay_remain_inert(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-agent-resource-budget-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertEqual(result["analysis"]["unknown_count"], 2)
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )

    def test_aws_scp_dispatch_preserves_three_valued_context_and_path_scope(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-aws-scp-component.json"
        )
        result = self.run_component(value)
        decisions = {item["query_id"]: item["decision"] for item in result["analysis"]["results"]}
        self.assertEqual(
            decisions,
            {
                "a-secure": "not_blocked_by_supplied_scps",
                "b-insecure": "blocked",
                "c-unavailable": "inconclusive",
                "d-outside": "inconclusive",
            },
        )
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        self.assertIs(result["positive_use_approved"], False)

    def test_protobuf_dispatch_parses_tag_reservation_and_rpc_changes(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-protobuf-component.json"
        )
        result = self.run_component(value)
        self.assertGreater(result["analysis"]["observation_count"], 0)
        self.assertIs(result["analysis"]["wire_compatibility_certified"], False)
        self.assertIs(result["analysis"]["security_findings_verified"], False)
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        altered = copy.deepcopy(value)
        altered["payload"]["current_content"] += "\n// Different supplied source bytes\n"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=altered, catalog=self.catalog, repository_root=ROOT
            )

    def test_new_components_deny_resources_before_entering_analyzers(self) -> None:
        bindings = (
            ("offline-aws-scp-component.json", "analyze_aws_scp"),
            ("offline-protobuf-component.json", "analyze_protobuf_schema_evolution"),
            ("offline-x509-chain-component.json", "analyze_supplied_x509_chain"),
        )
        for filename, analyzer_name in bindings:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for field in ("network", "filesystem", "process", "credential"):
                    changed = copy.deepcopy(original)
                    changed["resources"][field] = ["not-authorized"]
                    with self.subTest(profile=original["profile_id"], field=field):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_x509_dispatch_verifies_signatures_without_establishing_trust(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-x509-chain-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        self.assertEqual(analysis["supported_checks_outcome"], "pass")
        self.assertEqual(
            [item["signature_status"] for item in analysis["issuer_links"]],
            ["verified", "verified"],
        )
        self.assertIs(analysis["full_pkix_validated"], False)
        self.assertIs(analysis["trust_established"], False)
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        altered = copy.deepcopy(value)
        altered["payload"]["model"]["evaluated_at"] = "2026-09-28T12:00:01Z"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=altered, catalog=self.catalog, repository_root=ROOT
            )

    def test_new_cohashed_analysis_and_operational_promotions_fail_full_source_replay(self) -> None:
        changes = (
            ("offline-aws-scp-component.json", "effective_access_granted"),
            ("offline-protobuf-component.json", "wire_compatibility_certified"),
            ("offline-x509-chain-component.json", "trust_established"),
        )
        for filename, field in changes:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(original)
            changed["analysis"][field] = True
            changed["positive_use_approved"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_graphql_dispatch_calculates_structure_and_replays(self) -> None:
        value = graphql_request()
        result = self.run_component(value)
        self.assertEqual(result["analysis"]["metrics"]["expanded_field_count"], 3)
        self.assertEqual(result["analysis"]["metrics"]["expanded_alias_count"], 2)
        self.assertEqual(result["analysis"]["metrics"]["max_field_depth"], 2)
        self.assertEqual(result["analysis"]["metrics"]["max_list_layers_on_path"], 1)
        replay = self.verify_component(
            result, request=value, catalog=self.catalog, repository_root=ROOT
        )
        self.assertEqual(result, replay)
        self.assertIsNot(result, replay)
        self.assertIs(result["positive_use_approved"], False)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})

    def test_framing_azure_soap_deny_resources_and_open_payload_before_analysis(self) -> None:
        bindings = (
            (
                "offline-http-request-framing-component.json",
                "analyze_supplied_http_request_framing",
            ),
            ("offline-azure-rbac-component.json", "analyze_azure_rbac"),
            ("offline-soap-component.json", "analyze_soap_contract_instance"),
        )
        for filename, analyzer_name in bindings:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"], changed=changed):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_http_framing_dispatch_binds_octets_without_a_server_prediction(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-http-request-framing-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        self.assertEqual(analysis["supported_checks_outcome"], "pass")
        self.assertEqual(analysis["source"]["byte_count"], 38)
        self.assertEqual(analysis["framing"]["body_framing"], "none")
        self.assertIs(analysis["framing"]["body_complete"], True)
        self.assertEqual(analysis["framing"]["body_start"], 38)
        self.assertEqual(analysis["framing"]["body_end"], 38)
        self.assertEqual(analysis["framing"]["unconsumed_bytes"], 0)
        self.assertIs(analysis["server_vulnerability_proven"], False)
        self.assertNotIn("example.test", _canonical_json(analysis))
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(value)
        changed["payload"]["model"]["request_base64"] = base64.b64encode(
            b"GET /other HTTP/1.1\r\nHost: example.test\r\n\r\n"
        ).decode("ascii")
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_soap_dispatch_joins_a_contract_and_checks_actual_scalar_content(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-soap-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        self.assertEqual(analysis["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(analysis["statistics"]["scalar_checks"], 2)
        self.assertEqual(analysis["statistics"]["sequence_checks"], 1)
        self.assertEqual(
            analysis["structural_summary"]["declared_payload_qname"], "{urn:fixture}Lookup"
        )
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(value)
        changed["payload"]["envelope_content"] = changed["payload"]["envelope_content"].replace(
            "<f:id>7</f:id>", "<f:id>not-an-integer</f:id>"
        )
        mismatch = self.run_component(changed)["analysis"]
        self.assertEqual(mismatch["analysis_status"], "mismatch")
        self.assertTrue(any(item["kind"] == "violation" for item in mismatch["observations"]))
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_azure_dispatch_keeps_role_regrant_planes_and_scope_separate(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-azure-rbac-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        outcomes = {item["query_id"]: item["outcome"] for item in analysis["results"]}
        self.assertEqual(
            outcomes,
            {
                "control-regrant": "matching_supplied_role_grant",
                "data-is-separate": "no_matching_supplied_role_grant",
                "sibling-no-grant": "no_matching_supplied_role_grant",
            },
        )
        self.assertIs(analysis["effective_access_verified"], False)
        self.assertEqual(set(analysis["effects"].values()), {"none"})
        self.assertEqual(
            result,
            self.verify_component(
                result, request=value, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(value)
        changed["payload"]["queries"][0]["group_membership_complete"] = False
        uncertain = self.run_component(changed)["analysis"]
        self.assertEqual(uncertain["results"][0]["query_id"], "control-regrant")
        self.assertEqual(uncertain["results"][0]["outcome"], "inconclusive")
        self.assertTrue(uncertain["results"][0]["known_grant_witnesses"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_framing_azure_soap_operational_promotion_cannot_replace_source_replay(self) -> None:
        for filename in (
            "offline-http-request-framing-component.json",
            "offline-azure-rbac-component.json",
            "offline-soap-component.json",
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            self.assertFalse(original["positive_use_approved"])
            self.assertEqual(set(original["operational_effects"].values()), {"none"})
            self.assertEqual(
                original,
                self.verify_component(
                    original, request=value, catalog=self.catalog, repository_root=ROOT
                ),
            )
            changed = copy.deepcopy(original)
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_gcp_jose_openapi_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, analyzer_name in (
            ("offline-gcp-iam-component.json", "analyze_gcp_iam"),
            ("offline-jose-component.json", "analyze_supplied_jose"),
            (
                "offline-openapi-security-evolution-component.json",
                "analyze_openapi_security_evolution",
            ),
        ):
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_gcp_jose_openapi_cohashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename in (
            "offline-gcp-iam-component.json",
            "offline-jose-component.json",
            "offline-openapi-security-evolution-component.json",
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            self.assertFalse(original["positive_use_approved"])
            self.assertEqual(set(original["operational_effects"].values()), {"none"})
            self.assertEqual(
                original,
                self.verify_component(
                    original,
                    request=value,
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
            )
            changed = copy.deepcopy(original)
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed,
                        request=value,
                        catalog=self.catalog,
                        repository_root=ROOT,
                    )

    def test_gcp_dispatch_preserves_ancestry_and_unassessed_conditions(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-gcp-iam-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        self.assertEqual(
            {row["query_id"]: row["outcome"] for row in analysis["results"]},
            {
                "inherited-reader": "matching_supplied_allow_binding",
                "sibling-no-grant": "no_matching_supplied_allow_binding",
                "conditional-writer": "inconclusive",
            },
        )
        self.assertFalse(analysis["effective_access_proven"])
        changed = copy.deepcopy(value)
        changed["payload"]["snapshot"]["coverage"]["allow_policies_complete"] = False
        uncertain = next(
            row
            for row in self.run_component(changed)["analysis"]["results"]
            if row["query_id"] == "inherited-reader"
        )
        self.assertEqual(uncertain["outcome"], "inconclusive")
        self.assertTrue(uncertain["known_allow_witnesses"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result,
                request=changed,
                catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_jose_dispatch_verifies_math_without_issuer_or_live_use_authority(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-jose-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        self.assertEqual(analysis["checks"]["signature"], "valid")
        self.assertEqual(analysis["checks"]["issuer"], "match")
        self.assertFalse(analysis["issuer_authenticated"])
        self.assertFalse(analysis["live_use_approved"])
        self.assertFalse(analysis["key_currentness_verified"])
        changed = copy.deepcopy(value)
        changed["payload"]["model"]["expected_audience"] = "different-supplied-audience"
        alternate = self.run_component(changed)["analysis"]
        self.assertEqual(alternate["checks"]["signature"], "valid")
        self.assertEqual(alternate["checks"]["audience"], "mismatch")
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result,
                request=changed,
                catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_openapi_dispatch_computes_symbolic_implication_not_live_access(self) -> None:
        value = load_offline_specialist_component_request(
            ROOT / "examples/offline-openapi-security-evolution-component.json"
        )
        result = self.run_component(value)
        analysis = result["analysis"]
        row = analysis["operations"][0]
        self.assertEqual(
            (row["method"], row["path"], row["relationship"]), ("GET", "/synthetic", "weakened")
        )
        self.assertTrue(row["previous_implies_current"])
        self.assertFalse(row["current_implies_previous"])
        self.assertEqual(row["current_not_previous_witness"], [{"scheme": "bearer", "scopes": []}])
        self.assertFalse(analysis["server_behavior_verified"])
        changed = copy.deepcopy(value)
        changed["payload"]["model"]["current_document"]["security"] = [{"key": []}]
        alternate = self.run_component(changed)["analysis"]["operations"][0]
        self.assertEqual(alternate["relationship"], "weakened")
        self.assertNotEqual(
            alternate["current_not_previous_witness"], row["current_not_previous_witness"]
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result,
                request=changed,
                catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_kubernetes_dispatch_returns_model_witnesses(self) -> None:
        value = kubernetes_request()
        result = self.run_component(value)
        query_result = result["analysis"]["results"][0]
        self.assertEqual(query_result["decision"], "allow_in_supplied_model")
        self.assertEqual(len(query_result["witnesses"]), 1)
        self.assertEqual(result["input_provenance"], "operator_supplied_unverified")
        self.assertIs(result["full_candidate_assembled"], False)

    def test_resource_scope_credential_and_native_boundary_denied_before_analysis(self) -> None:
        cases = []
        for key, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("dry_run", 1),
            ("action_tier", "R1"),
            ("environment", "production"),
            ("credential_refs", ["env:TOKEN"]),
            ("profile_id", "AOE-GA-D01-S01"),
            ("callback", "arbitrary"),
        ):
            altered = graphql_request()
            altered[key] = value
            cases.append(altered)
        for kind in ("network", "filesystem", "process", "credential"):
            altered = graphql_request()
            altered["resources"][kind] = ["not-allowed"]
            cases.append(altered)
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyze:
            for altered in cases:
                with self.subTest(request=altered):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(altered)
            analyze.assert_not_called()

    def test_rehashed_catalog_promotion_and_public_wrapper_forgery_are_rejected(self) -> None:
        for field, value in (
            ("full_candidate_assembled", True),
            ("qualified", True),
            ("phase158_entry_approved", True),
            ("qualified", 0),
            ("commander_profile_id", "AOE-HQ-01"),
        ):
            altered = self.catalog.to_dict()
            altered["components"][0][field] = value
            body = {
                key: item
                for key, item in altered.items()
                if key not in {"catalog_id", "catalog_sha256"}
            }
            identifier, digest = _address(body, CATALOG_DOMAIN, "OSC-")
            altered.update(catalog_id=identifier, catalog_sha256=digest)
            forged = OfflineSpecialistComponentCatalog(_canonical_json(altered))
            with self.subTest(field=field, value=value):
                with self.assertRaises(OfflineSpecialistComponentError):
                    run_offline_specialist_component(
                        graphql_request(), catalog=forged, repository_root=ROOT
                    )
        malformed = object.__new__(OfflineSpecialistComponentCatalog)
        with self.assertRaises(OfflineSpecialistComponentError):
            run_offline_specialist_component(
                graphql_request(), catalog=malformed, repository_root=ROOT
            )

    def test_rehashed_false_result_replays_original_input(self) -> None:
        value = graphql_request()
        result = self.run_component(value)
        altered = copy.deepcopy(result)
        altered["analysis"]["metrics"]["expanded_field_count"] = 0
        body = {
            key: item for key, item in altered.items() if key not in {"result_id", "result_sha256"}
        }
        identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
        altered.update(result_id=identifier, result_sha256=digest)
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                altered, request=value, catalog=self.catalog, repository_root=ROOT
            )
        changed = copy.deepcopy(value)
        changed["payload"]["query_content"] += "\n# Changed supplied source spelling"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_current_source_change_invalidates_old_catalog(self) -> None:
        request = graphql_request()
        result = self.run_component(request)
        paths = (
            *FOUNDATION_PATHS,
            STRATEGY_PATH,
            *INTEGRATION_PATHS,
            *(path for item in COMPONENTS for path in item[4:]),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in paths:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            source = root / "src/sunderkey/offline_graphql_analysis.py"
            source.write_bytes(source.read_bytes() + b"\n")
            with self.assertRaises(OfflineSpecialistComponentError):
                run_offline_specialist_component(
                    request, catalog=self.catalog, repository_root=root
                )
            with self.assertRaises(OfflineSpecialistComponentError):
                verify_offline_specialist_component_result(
                    result, request=request, catalog=self.catalog, repository_root=root
                )

    def test_duplicate_keys_nonfinite_numbers_unknown_fields_and_cycles_are_rejected(self) -> None:
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"value":NaN}',
            b'{"value":1.0}',
            b"[]",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(OfflineSpecialistComponentError):
                    parse_offline_specialist_component_request(raw)
        cyclic = graphql_request()
        cyclic["payload"]["cycle"] = cyclic
        with self.assertRaises(OfflineSpecialistComponentError):
            self.run_component(cyclic)
        altered = graphql_request()
        altered["payload"]["callback"] = "not-allowed"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.run_component(altered)

    def test_repeated_native_content_exceeds_aggregate_bound_before_serialization(self) -> None:
        shared = "x" * (MAX_REQUEST_BYTES // 2)
        with patch("sunderkey.offline_specialist_components._canonical_json") as canonical:
            with self.assertRaises(OfflineSpecialistComponentError):
                _native([shared, shared, shared], maximum_bytes=MAX_REQUEST_BYTES)
            canonical.assert_not_called()
        with patch("sunderkey.offline_specialist_components._canonical_json") as canonical:
            with self.assertRaises(OfflineSpecialistComponentError):
                _native("\x7f" * 100, maximum_bytes=300)
            canonical.assert_not_called()
        shared_tree = None
        for _ in range(21):
            shared_tree = [shared_tree] * 10_000
        with self.assertRaisesRegex(OfflineSpecialistComponentError, "queued structure"):
            _native(shared_tree, maximum_bytes=MAX_REQUEST_BYTES)
        escaped = "\x00" * 100
        with self.assertRaises(OfflineSpecialistComponentError):
            _native([escaped, escaped], maximum_bytes=1000)
        with self.assertRaises(OfflineSpecialistComponentError):
            OfflineSpecialistComponentCatalog("x" * (MAX_CATALOG_BYTES + 1)).to_dict()

    def test_raw_json_cost_limits_precede_decoder_and_preserve_exact_boundaries(self) -> None:
        cases = (
            b"[" + b"null," * 200_000 + b"null]",
            b"[" * 81 + b"null" + b"]" * 81,
            b"18446744073709551616",
            b"-18446744073709551616",
            b"9" * 100,
            b"1.0",
            b"NaN",
            b"Infinity",
        )
        for content in cases:
            with self.subTest(size=len(content), prefix=content[:25]):
                with (
                    patch(
                        "sunderkey.offline_specialist_components.loads_json_without_duplicate_keys"
                    ) as decoder,
                    patch("sunderkey.offline_specialist_components._canonical_json") as canonical,
                ):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        _parse(content, MAX_REQUEST_BYTES)
                    self.assertEqual(decoder.call_count, 0)
                    canonical.assert_not_called()
        self.assertEqual(_parse(b"18446744073709551615", MAX_REQUEST_BYTES), (1 << 64) - 1)
        self.assertEqual(_parse(b"-18446744073709551615", MAX_REQUEST_BYTES), -((1 << 64) - 1))
        self.assertEqual(
            len(_parse(b"[" + b"null," * 199_998 + b"null]", MAX_REQUEST_BYTES)),
            199_999,
        )
        self.assertEqual(
            _parse(b"[" * 81 + b"]" * 81, MAX_REQUEST_BYTES), json.loads("[" * 81 + "]" * 81)
        )
        escaped = {'quoted\\"key': ["[{,}:]", '\\"', "\u03bb"]}
        self.assertEqual(_parse(json.dumps(escaped).encode(), MAX_REQUEST_BYTES), escaped)

    def test_explicit_fixture_reader_is_bounded_local_and_regular(self) -> None:
        with patch("sunderkey.offline_specialist_components.os.open") as opened:
            for path in (
                r"\\server\share\fixture.json",
                "https://example.invalid/fixture.json",
                ROOT,
            ):
                with self.subTest(path=path):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        load_offline_specialist_component_request(path)
            opened.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.json"
            value = graphql_request()
            fixture.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(load_offline_specialist_component_request(fixture), value)

    def test_every_registered_fixture_reaches_its_closed_dispatcher(self) -> None:
        """Exercise every algorithm once without repeating the source-hash scan."""

        current = self.catalog.to_dict()
        descriptors = {item["component_id"]: item for item in current["components"]}
        fixtures = sorted((ROOT / "examples").glob("*-component.json"))
        self.assertEqual(len(fixtures), len(COMPONENTS))
        seen: set[str] = set()
        with patch.object(component_module, "_catalog_document", return_value=current):
            for path in fixtures:
                with self.subTest(fixture=path.name):
                    value = load_offline_specialist_component_request(path)
                    result = self.run_component(value)
                    component_id = result["component"]["component_id"]
                    self.assertNotIn(component_id, seen)
                    seen.add(component_id)
                    self.assertEqual(result["component"], descriptors[component_id])
                    self.assertEqual(result["component"]["profile_id"], value["profile_id"])
                    self.assertEqual(set(result["operational_effects"].values()), {"none"})
                    self.assertFalse(result["full_candidate_assembled"])
                    self.assertFalse(result["positive_use_approved"])
        self.assertEqual(seen, set(descriptors))

    def test_checked_examples_run_through_cli_main_and_match_pure_dispatch(self) -> None:
        current = self.catalog.to_dict()
        for relative in (
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
            "examples/offline-azure-nsg-component.json",
            "examples/offline-android-component.json",
            "examples/offline-kubernetes-service-component.json",
            "examples/offline-gcp-firewall-component.json",
            "examples/offline-ios-entitlement-component.json",
            "examples/offline-mqtt-topic-component.json",
            "examples/offline-modbus-tcp-component.json",
            "examples/offline-android-dex-component.json",
            "examples/offline-csp-fetch-component.json",
            "examples/offline-macho-component.json",
            "examples/offline-protobuf-wire-component.json",
            "examples/offline-coap-component.json",
            "examples/offline-elf64-layout-component.json",
            "examples/offline-pe32-layout-component.json",
            "examples/offline-dhcpv4-component.json",
            "examples/offline-authorization-model-projection-component.json",
            "examples/offline-jit-privilege-windows-component.json",
            "examples/offline-service-secret-lifecycle-component.json",
            "examples/offline-spiffe-id-trust-projection-component.json",
            "examples/offline-guest-trust-component.json",
            "examples/offline-certificate-auth-metadata-component.json",
            "examples/offline-kerberos-realm-path-component.json",
            "examples/offline-password-lockout-timeline-component.json",
            "examples/offline-switch-vlan-component.json",
            "examples/offline-firewall-rule-order-component.json",
            "examples/offline-nac-admission-component.json",
            "examples/offline-wifi-policy-component.json",
            "examples/offline-snmp-view-component.json",
            "examples/offline-sdwan-overlay-component.json",
        ):
            with self.subTest(relative=relative):
                value = load_offline_specialist_component_request(ROOT / relative)
                with patch.object(component_module, "_catalog_document", return_value=current):
                    expected = self.run_component(value)
                output = io.StringIO()
                with (
                    patch.object(
                        sys, "argv", ["component-cli", "--input-fixture", str(ROOT / relative)]
                    ),
                    patch.object(
                        component_cli,
                        "load_offline_specialist_component_catalog",
                        return_value=self.catalog,
                    ),
                    patch.object(
                        component_cli,
                        "run_offline_specialist_component",
                        return_value=expected,
                    ) as dispatch,
                    redirect_stdout(output),
                ):
                    self.assertEqual(component_cli.main(), 0)
                dispatch.assert_called_once_with(value, catalog=self.catalog, repository_root=ROOT)
                self.assertEqual(json.loads(output.getvalue()), expected)

    def test_cli_subprocess_smoke_uses_real_catalog_loader(self) -> None:
        for relative in (
            "examples/offline-graphql-component.json",
            "examples/offline-firewall-rule-order-component.json",
        ):
            with self.subTest(relative=relative):
                value = load_offline_specialist_component_request(ROOT / relative)
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "scripts/run_offline_specialist_component.py",
                        "--input-fixture",
                        relative,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                self.assertEqual(json.loads(completed.stdout), self.run_component(value))

    def test_authorization_model_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-authorization-model-projection-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S13")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["relations"] = []
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_jit_window_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-jit-privilege-windows-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S12")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["revocations"].clear()
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_service_secret_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-service-secret-lifecycle-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S11")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["secrets"][0]["revoked_at"] = 25
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_spiffe_id_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-spiffe-id-trust-projection-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S10")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["trusted_domains"].append("other.example")
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_guest_trust_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-guest-trust-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S09")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["trusts"][0]["enabled"] = True
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_certificate_auth_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-certificate-auth-metadata-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S07")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["trusted_issuers"].clear()
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_kerberos_realm_path_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-kerberos-realm-path-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S06")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["trusted_realms"].append("synthetic:transit-realm")
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_password_lockout_timeline_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-password-lockout-timeline-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S01")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["events"][2]["reported_outcome"] = "failed"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_mfa_factor_rebind_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-mfa-factor-rebind-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S02")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 2)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["events"][3]["reported_outcome"] = "rejected"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_biometric_assurance_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-biometric-assurance-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S17")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["records"][1]["reported_outcome"] = "rejected"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_passive_source_freshness_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-passive-source-freshness-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D01-S01")
        self.assertEqual(result["analysis"]["summary"]["conflict_candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["observations"][1]["claim"] = "present"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_organization_relationships_are_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-organization-relationship-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D01-S09")
        self.assertEqual(result["analysis"]["summary"]["conflict_candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["records"][1]["reported_state"] = "current"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_kdf_policy_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-kdf-policy-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D22-S04")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["records"][0]["parameters"]["memory_kib"] = 65536
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_symmetric_nonce_reuse_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-symmetric-nonce-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D22-S05")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["records"][2]["key_id"] = "synthetic:key-two"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_crypto_public_key_lifecycle_and_token_views_are_inert_and_replayed(self) -> None:
        cases = (
            (
                "offline-public-key-policy-component.json",
                "AOE-GE-D22-S06",
                lambda model: model["policy"]["allowed_ec_curves"].__setitem__(
                    0, "secp256r1"
                ),
            ),
            (
                "offline-key-lifecycle-posture-component.json",
                "AOE-GE-D22-S10",
                lambda model: model["keys"][0].__setitem__("last_use_at", None),
            ),
            (
                "offline-token-payload-views-component.json",
                "AOE-GE-D22-S11",
                lambda model: model["parser_views"][0]["claims"].__setitem__(
                    "sub", "other"
                ),
            ),
        )
        for filename, profile_id, change in cases:
            with self.subTest(profile_id=profile_id):
                request = load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                )
                result = self.run_component(request)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertGreater(result["analysis"]["candidate_count"], 0)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                changed = copy.deepcopy(request)
                change(changed["payload"]["model"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        result, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_exploit_research_plans_are_inert_and_source_replayed(self) -> None:
        cases = (
            (
                "offline-coverage-seed-selection-component.json",
                "AOE-GE-D21-S13",
                lambda model: model["seeds"][0].__setitem__("cost_units", 3),
            ),
            (
                "offline-finite-grammar-component.json",
                "AOE-GE-D21-S14",
                lambda model: model["rules"][1]["alternatives"][0][0].__setitem__(
                    "literal", "Z"
                ),
            ),
            (
                "offline-path-constraint-component.json",
                "AOE-GE-D21-S15",
                lambda model: model["constraints"][0].__setitem__("constant", -2),
            ),
            (
                "offline-binary-reference-component.json",
                "AOE-GE-D21-S16",
                lambda model: model["functions"][1].__setitem__("call_symbol_ids", []),
            ),
            (
                "offline-source-variant-component.json",
                "AOE-GE-D21-S17",
                lambda model: model["right_functions"][0]["tokens"].append("extra"),
            ),
            (
                "offline-happens-before-component.json",
                "AOE-GE-D21-S11",
                lambda model: model["events"][0].__setitem__("access", "read"),
            ),
            (
                "offline-integer-width-component.json",
                "AOE-GE-D21-S12",
                lambda model: model["operations"][0].__setitem__("observed_result", 5),
            ),
            (
                "offline-heap-trace-component.json",
                "AOE-GE-D21-S09",
                lambda model: model["events"][2].__setitem__("length", 1),
            ),
            (
                "offline-chain-trial-component.json",
                "AOE-GE-D21-S18",
                lambda model: model["trials"][0].__setitem__(
                    "environment_id", "fixture_b"
                ),
            ),
            (
                "offline-threat-scenario-component.json",
                "AOE-GA-D04-S01",
                lambda model: model["stages"][0].__setitem__("evidence_status", "missing"),
            ),
            (
                "offline-rng-sample-component.json",
                "AOE-GE-D22-S08",
                lambda model: model["samples"][0].__setitem__("value_hex", "03"),
            ),
            (
                "offline-crypto-protocol-state-component.json",
                "AOE-GE-D22-S01",
                lambda model: model["transitions"][0].__setitem__(
                    "asserted_peer_authentication", False
                ),
            ),
            (
                "offline-e2ee-epoch-component.json",
                "AOE-GE-D22-S13",
                lambda model: model["epochs"][1].__setitem__(
                    "envelope_recipient_ids", ["a", "c"]
                ),
            ),
            (
                "offline-hybrid-kem-lineage-component.json",
                "AOE-GE-D22-S07",
                lambda model: model["derivations"][0].__setitem__(
                    "input_material_ids", ["traditional"]
                ),
            ),
            (
                "offline-side-channel-timing-component.json",
                "AOE-GE-D22-S09",
                lambda model: model["groups"][0]["samples"][0].__setitem__(
                    "duration_ns", 9
                ),
            ),
        )
        for filename, profile_id, change in cases:
            with self.subTest(profile_id=profile_id):
                request = load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                )
                result = self.run_component(request)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertEqual(result["analysis"]["candidate_count"], 0)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertFalse(result["positive_use_approved"])
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                changed = copy.deepcopy(request)
                change(changed["payload"]["model"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        result, request=changed, catalog=self.catalog,
                        repository_root=ROOT,
                    )

    def test_switch_vlan_projection_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-switch-vlan-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D13-S04")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["ports"][1]["stp_forwarding_vlans"] = [30]
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_firewall_rule_order_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-firewall-rule-order-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D13-S05")
        self.assertEqual(result["analysis"]["summary"]["declared_allow_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["rules"].reverse()
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_nac_admission_is_inert_and_source_replayed(self) -> None:
        request = load_offline_specialist_component_request(
            ROOT / "examples/offline-nac-admission-component.json"
        )
        result = self.run_component(request)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D13-S07")
        self.assertEqual(result["analysis"]["summary"]["candidate_count"], 1)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            result,
            self.verify_component(
                result, request=request, catalog=self.catalog, repository_root=ROOT
            ),
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["sessions"][1]["controlled_port_state"] = "unauthorized"
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=changed, catalog=self.catalog, repository_root=ROOT
            )

    def test_explicit_fixed_selector_preserves_legacy_default_without_aliasing_request(
        self,
    ) -> None:
        for legacy, component_id in (
            (graphql_request(), "graphql_query_structure"),
            (
                load_offline_specialist_component_request(
                    ROOT / "examples/offline-aws-scp-component.json"
                ),
                "aws_organizations_supplied_scp_path",
            ),
        ):
            explicit = copy.deepcopy(legacy)
            explicit["component_id"] = component_id
            original = self.run_component(legacy)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["component"], selected["component"])
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(selected["component"]["component_id"], component_id)
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                self.assertNotEqual(original["result_id"], selected["result_id"])
                self.assertEqual(
                    selected,
                    self.verify_component(
                        selected, request=explicit, catalog=self.catalog, repository_root=ROOT
                    ),
                )

    def test_windows_iam_network_policy_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, lane in (
            (
                "offline-windows-dacl-component.json",
                "windows_supplied_dacl_arithmetic",
                "AOE-GC-D11-S05",
            ),
            (
                "offline-aws-identity-policy-component.json",
                "aws-identity-policy-set-v1",
                "AOE-GC-D14-S01",
            ),
            (
                "offline-kubernetes-network-policy-component.json",
                "kubernetes_supplied_network_policy_flows",
                "AOE-GC-D15-S07",
            ),
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], lane)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                if component_id == "windows_supplied_dacl_arithmetic":
                    self.assertEqual(
                        result["analysis"]["evaluation"]["outcome"],
                        "supplied_dacl_allows_requested_bits",
                    )
                elif component_id == "aws-identity-policy-set-v1":
                    self.assertEqual(
                        result["analysis"]["results"][0]["decision"],
                        "allowed_by_supplied_identity_policies",
                    )
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "AIP-C2F92383D435FB6B46450672B61B9D69"
                    )
                else:
                    self.assertEqual(
                        {
                            row["flow_id"]: row["outcome"]
                            for row in result["analysis"]["flow_results"]
                        },
                        {
                            "database": "allowed_in_supplied_policy_model",
                            "other-port": "blocked_in_supplied_policy_model",
                        },
                    )

    def test_iam_selector_never_silently_changes_aws_scp_default_or_payload(self) -> None:
        explicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-aws-identity-policy-component.json"
        )
        missing = copy.deepcopy(explicit)
        missing.pop("component_id")
        with patch("sunderkey.offline_specialist_components.analyze_aws_scp") as scp:
            with patch(
                "sunderkey.offline_specialist_components.analyze_aws_identity_policy_set"
            ) as iam:
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.run_component(missing)
                scp.assert_not_called()
                iam.assert_not_called()
        scp_request = load_offline_specialist_component_request(
            ROOT / "examples/offline-aws-scp-component.json"
        )
        wrong_payload = copy.deepcopy(scp_request)
        wrong_payload["component_id"] = "aws-identity-policy-set-v1"
        with patch(
            "sunderkey.offline_specialist_components.analyze_aws_identity_policy_set"
        ) as iam:
            with self.assertRaises(OfflineSpecialistComponentError):
                self.run_component(wrong_payload)
            iam.assert_not_called()
        self.assertEqual(
            self.run_component(scp_request)["component"]["component_id"],
            "aws_organizations_supplied_scp_path",
        )

    def test_windows_iam_network_policy_deny_resources_and_open_payload_before_analysis(
        self,
    ) -> None:
        for filename, analyzer_name in (
            ("offline-windows-dacl-component.json", "analyze_supplied_windows_dacl"),
            ("offline-aws-identity-policy-component.json", "analyze_aws_identity_policy_set"),
            (
                "offline-kubernetes-network-policy-component.json",
                "analyze_supplied_kubernetes_network_policy",
            ),
        ):
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_windows_iam_network_policy_rehashed_promotion_cannot_replace_source_replay(
        self,
    ) -> None:
        for filename in (
            "offline-windows-dacl-component.json",
            "offline-aws-identity-policy-component.json",
            "offline-kubernetes-network-policy-component.json",
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(original)
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_windows_iam_network_policy_original_model_change_requires_new_result(self) -> None:
        for filename, change_model in (
            ("offline-windows-dacl-component.json", lambda model: model.update(desired_access=1)),
            (
                "offline-aws-identity-policy-component.json",
                lambda model: model.update(attachments_complete=False),
            ),
            (
                "offline-kubernetes-network-policy-component.json",
                lambda model: model["flows"][0].update(destination_port=5433),
            ),
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            change_model(changed["payload"]["model"])
            with self.subTest(filename=filename):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_explicit_selector_cannot_replace_the_original_request_in_replay(self) -> None:
        original = graphql_request()
        explicit = copy.deepcopy(original)
        explicit["component_id"] = "graphql_query_structure"
        selected = self.run_component(explicit)
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                selected, request=original, catalog=self.catalog, repository_root=ROOT
            )
        defaulted = self.run_component(original)
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                defaulted, request=explicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_unknown_native_or_cross_profile_selector_is_denied_before_analysis(self) -> None:
        cases = (None, True, 1, [], {}, "", "not-registered", "kubernetes_rbac_supplied_model")
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyzer:
            for selector in cases:
                changed = graphql_request()
                changed["component_id"] = selector
                with self.subTest(selector=selector):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_explicit_selection_does_not_widen_deny_all_resources(self) -> None:
        original = graphql_request()
        original["component_id"] = "graphql_query_structure"
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyzer:
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                with self.subTest(field=field):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_selector_cannot_use_non_native_or_unregistered_profile_identity(self) -> None:
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyzer:
            for profile in (None, True, 1, [], {}, "", "not-registered", "AOE-GC-D15-S04"):
                changed = graphql_request()
                changed["profile_id"] = profile
                changed["component_id"] = "graphql_query_structure"
                with self.subTest(profile=profile):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_posix_vpc_rls_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, profile_id, _analyzer in NEW_SUPPLIED_MODEL_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                if component_id == "linux_supplied_posix_acl_arithmetic":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "LPA-E2620599A2D7BE5CA8AB6EE62F48C845"
                    )
                    self.assertEqual(
                        {
                            row["request_id"]: row["decision"]
                            for row in result["analysis"]["request_results"]
                        },
                        {
                            "read": "allowed_by_supplied_posix_dac",
                            "write": "not_allowed_by_supplied_posix_dac",
                        },
                    )
                elif component_id == "aws_supplied_vpc_flow_predicates":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "VFA-0B99E2C511BA522BAD6565B25D6FE4F8"
                    )
                    row = result["analysis"]["flow_results"][0]
                    self.assertEqual(row["forward"]["outcome"], "allowed_in_supplied_policy_model")
                    self.assertEqual(
                        row["reverse"]["outcome"], "conditionally_allowed_in_supplied_policy_model"
                    )
                else:
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "PRL-289CEA05ECF972F68D012DE260DD6540"
                    )
                    self.assertEqual(
                        [row["outcome"] for row in result["analysis"]["query_results"]],
                        [
                            "row_available_in_supplied_select_rls_model",
                            "row_filtered_in_supplied_select_rls_model",
                            "row_filtered_in_supplied_select_rls_model",
                        ],
                    )

    def test_posix_vpc_rls_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in NEW_SUPPLIED_MODEL_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_posix_vpc_rls_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in NEW_SUPPLIED_MODEL_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_posix_vpc_rls_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model["principal"].update(fsuid=1000),
            lambda model: model["flows"][0].update(destination_port=444),
            lambda model: model["rows"][0]["values"].update(active=False),
        )
        for descriptor, mutate in zip(NEW_SUPPLIED_MODEL_COMPONENTS, mutations, strict=True):
            filename = descriptor[0]
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=filename):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_posix_vpc_rls_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in NEW_SUPPLIED_MODEL_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_websocket_pod_redis_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, profile_id, _analyzer in PROTOCOL_POD_DATA_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                if component_id == "websocket_supplied_frame_state":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "WFA-8D74F3875E545019F308BF162F35716A"
                    )
                    self.assertEqual(
                        result["analysis"]["analysis_status"], "consistent_with_supported_subset"
                    )
                    self.assertEqual(result["analysis"]["summary"]["frame_count"], 1)
                    self.assertEqual(result["analysis"]["summary"]["message_count"], 1)
                    self.assertEqual(result["analysis"]["messages"][0]["utf8_status"], "valid")
                elif component_id == "kubernetes_supplied_linux_pod_security_controls":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "PSA-A5D9854B996C8ECFFFB7A75C5D2BC2AE"
                    )
                    self.assertEqual(result["analysis"]["outcome"], "satisfies_supported_controls")
                    self.assertEqual(result["analysis"]["summary"]["container_count"], 3)
                    self.assertEqual(len(result["analysis"]["controls"]), 5)
                    self.assertEqual(result["analysis"]["summary"]["violation_count"], 0)
                    self.assertIs(result["analysis"]["flags"]["full_pss_verified"], False)
                else:
                    expected_allowed = {"app1-read", "app2-read", "copy-into-app1"}
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "RAC-9DF56DA03849C2B975EAB1E3F966289A"
                    )
                    rows = result["analysis"]["results"]
                    self.assertEqual(len(rows), 7)
                    for row in rows:
                        self.assertEqual(
                            row["status"],
                            "allowed_by_supplied_acl"
                            if row["query_id"] in expected_allowed
                            else "not_allowed_by_supplied_acl",
                        )
                    self.assertIs(result["analysis"]["effective_access_proven"], False)

    def test_websocket_pod_redis_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in PROTOCOL_POD_DATA_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_websocket_pod_redis_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in PROTOCOL_POD_DATA_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_websocket_pod_redis_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model.update(sender_role="client"),
            lambda model: model["pod"].update(host_users=False),
            lambda model: model.update(selectors_complete=False),
        )
        for descriptor, mutate in zip(PROTOCOL_POD_DATA_COMPONENTS, mutations, strict=True):
            filename = descriptor[0]
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=filename):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_websocket_pod_redis_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in PROTOCOL_POD_DATA_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_dns_cors_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, profile_id, _analyzer in DNS_CORS_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                if component_id == "dns_supplied_zone_lookup":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "DZA-EF85B60D02D64FDBD374544598A749B5"
                    )
                    rows = result["analysis"]["query_results"]
                    self.assertEqual(
                        [row["outcome"] for row in rows],
                        [
                            "answer_in_supplied_projection",
                            "answer_in_supplied_projection",
                            "referral_in_supplied_projection",
                            "no_data_in_supplied_projection",
                        ],
                    )
                    self.assertEqual(rows[0]["rdata"], ["192.0.2.10"])
                    self.assertEqual(rows[1]["source_of_synthesis"], "*.example.test.")
                    self.assertEqual(rows[2]["rdata"], [])
                elif component_id == "dns_supplied_wire_structure":
                    self.assertEqual(
                        result["analysis"]["analysis_id"], "DNS-11459030D91AEAC582A266D52F657446"
                    )
                    self.assertEqual(
                        result["analysis"]["supported_checks_outcome"], "consistent_supplied_subset"
                    )
                    self.assertEqual(result["analysis"]["source"]["byte_count"], 65)
                    self.assertEqual(result["analysis"]["header"]["transaction_id"], 0x1234)
                    self.assertEqual(len(result["analysis"]["sections"]["answers"]), 2)
                    self.assertIs(result["analysis"]["message_authenticity_verified"], False)
                else:
                    self.assertEqual(
                        result["analysis"]["report_id"], "CRA-6E647D978BAB1CB48A14B3ADD93EDF35"
                    )
                    row = result["analysis"]["cases"][0]
                    self.assertEqual(row["preflight_check"]["outcome"], "passes_supplied_check")
                    self.assertEqual(
                        row["actual_response_check"]["outcome"], "passes_supplied_check"
                    )
                    self.assertEqual(
                        row["exposed_header_names"], ["content-type", "x-synthetic-result"]
                    )
                    self.assertIs(result["analysis"]["server_authorization_verified"], False)

    def test_dns_cors_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in DNS_CORS_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_dns_cors_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in DNS_CORS_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_dns_cors_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model["zone"].update(complete=False),
            lambda model: model.update(
                message_base64=base64.b64encode(
                    b"\x12\x35" + base64.b64decode(model["message_base64"])[2:]
                ).decode("ascii")
            ),
            lambda model: model["cases"][0]["request"].update(credentials_mode="include"),
        )
        for descriptor, mutate in zip(DNS_CORS_COMPONENTS, mutations, strict=True):
            filename = descriptor[0]
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=filename):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_dns_cors_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in DNS_CORS_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_oci_tls_cookie_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, profile_id, _analyzer in OCI_TLS_COOKIE_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                analysis = result["analysis"]
                if component_id == "oci_supplied_blob_graph_integrity":
                    self.assertEqual(
                        analysis["analysis_id"], "OBA-53F87EC0AFA3BA907E9365E6029D40B1"
                    )
                    self.assertEqual(analysis["verdict"], "pass")
                    self.assertEqual(analysis["reachable_blob_count"], 5)
                    self.assertEqual(len(analysis["references"]), 8)
                    self.assertEqual(analysis["parsed_document_count"], 3)
                    self.assertEqual(analysis["maximum_graph_depth"], 3)
                    self.assertEqual(analysis["source_model"], value["payload"]["model"])
                    self.assertIs(analysis["flags"]["signed_origin_verified"], False)
                    self.assertIs(analysis["flags"]["image_runtime_safety_verified"], False)
                    self.assertIs(analysis["flags"]["sanitized_for_publication"], False)
                elif component_id == "tls13_supplied_hello_offer_selection":
                    self.assertEqual(
                        analysis["analysis_id"], "THA-5C4792683DD417BB8537391B63B72DCC"
                    )
                    self.assertEqual(
                        analysis["outcome"], "consistent_with_supported_hello_selection"
                    )
                    self.assertIs(analysis["supported_checks_complete"], True)
                    self.assertEqual(set(analysis["selection_checks"].values()), {"passes"})
                    self.assertEqual(analysis["violations"], [])
                    self.assertEqual(analysis["source"]["client_hello_bytes"], 112)
                    self.assertEqual(analysis["source"]["server_hello_bytes"], 92)
                    self.assertEqual(analysis["server_hello"]["key_share"]["group"], 29)
                else:
                    self.assertEqual(
                        analysis["analysis_id"], "CKS-0C48DD34662DCE4EC3766D5134C7227D"
                    )
                    self.assertEqual(analysis["pair_count"], 4)
                    self.assertEqual(
                        [row["outcome"] for row in analysis["pair_observations"]],
                        [
                            "matches_supplied_predicates",
                            "matches_supplied_predicates",
                            "does_not_match_supplied_predicates",
                            "matches_supplied_predicates",
                        ],
                    )
                    self.assertIs(analysis["flags"]["browser_transmission_proven"], False)
                    self.assertIs(analysis["flags"]["server_authorization_verified"], False)

    def test_oci_tls_cookie_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in OCI_TLS_COOKIE_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_oci_tls_cookie_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in OCI_TLS_COOKIE_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_oci_tls_cookie_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model["root_descriptor"].update(
                size=model["root_descriptor"]["size"] + 1
            ),
            lambda model: model.update(
                server_hello_base64=base64.b64encode(
                    base64.b64decode(model["server_hello_base64"])[:-1] + b"x"
                ).decode("ascii")
            ),
            lambda model: model["requests"][0].update(path="/app/item/extra"),
        )
        for descriptor, mutate in zip(OCI_TLS_COOKIE_COMPONENTS, mutations, strict=True):
            filename = descriptor[0]
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=filename):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_oci_tls_cookie_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in OCI_TLS_COOKIE_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_semver_cache_run_distinct_math_without_candidate_promotion(self) -> None:
        for filename, component_id, profile_id, _analyzer in SEMVER_CACHE_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                analysis = result["analysis"]
                self.assertEqual(analysis["source_model"], value["payload"]["model"])
                if component_id == "javascript_supplied_semver_interval_arithmetic":
                    self.assertEqual(
                        analysis["analysis_id"], "SVA-A6E6CFD7BA022DCC5257D44D6C3610F7"
                    )
                    self.assertEqual(
                        [row["relation"] for row in analysis["comparisons"]],
                        ["less", "less", "equal"],
                    )
                    self.assertEqual(
                        [row["membership"] for row in analysis["memberships"]],
                        ["inside", "outside", "inside"],
                    )
                else:
                    self.assertEqual(
                        analysis["analysis_id"], "HCF-0BAD647F4D3912738A81DF19809036A5"
                    )
                    self.assertEqual(
                        [row["freshness_comparison"] for row in analysis["case_observations"]],
                        [False, True, None],
                    )

    def test_semver_cache_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in SEMVER_CACHE_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(profile=original["profile_id"]):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_semver_cache_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in SEMVER_CACHE_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_semver_cache_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model["versions"][0].update(version="1.0.0-beta.3"),
            lambda model: model["cases"][0].update(max_age_seconds=61),
        )
        for descriptor, mutate in zip(SEMVER_CACHE_COMPONENTS, mutations, strict=True):
            value = load_offline_specialist_component_request(ROOT / "examples" / descriptor[0])
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=descriptor[0]):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_semver_cache_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in SEMVER_CACHE_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_declaration_endpoints_run_distinct_math_without_candidate_promotion(self) -> None:
        identities = (
            "NSGA-6757B2E65C44905F4C8812CFC956D390",
            "ACD-94DF8096C55E2BC435527108C195B381",
            "KSE-1EE03ABF668C8C665E649CB1B8DF0DF5",
        )
        for descriptor, analysis_id in zip(
            DECLARATION_ENDPOINT_COMPONENTS, identities, strict=True
        ):
            filename, component_id, profile_id, _analyzer = descriptor
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                analysis = result["analysis"]
                self.assertEqual(analysis["analysis_id"], analysis_id)
                self.assertEqual(analysis["source_model"], value["payload"]["model"])
                if component_id == "azure_supplied_nsg_directional_predicates":
                    self.assertEqual(
                        [row["decision"] for row in analysis["flow_observations"]],
                        ["allow_under_supplied_nsg_predicates", "unassessed"],
                    )
                    self.assertIs(analysis["flags"]["reachability_proven"], False)
                elif component_id == "android_supplied_component_declarations":
                    self.assertEqual(
                        [row["outcome"] for row in analysis["component_observations"]],
                        [
                            "declaration_subset_resolved",
                            "missing_required_exported_declaration",
                            "declaration_subset_resolved",
                        ],
                    )
                    self.assertEqual(
                        [row["declared_exported"] for row in analysis["component_observations"]],
                        [False, None, False],
                    )
                    self.assertIs(analysis["flags"]["installability_verified"], False)
                else:
                    self.assertEqual(analysis["summary"]["status"], "consistent_supplied_subset")
                    self.assertEqual(analysis["summary"]["selected_pod_count"], 2)
                    self.assertEqual(
                        [row["port"] for row in analysis["expected_endpoint_tuples"]], [8080, 9090]
                    )
                    self.assertEqual(
                        [row["serving"] for row in analysis["expected_endpoint_tuples"]],
                        [True, False],
                    )
                    self.assertEqual(analysis["uncertainties"], [])
                    self.assertIs(analysis["claims"]["connectivity_proven"], False)

    def test_declaration_endpoints_deny_resources_and_open_payload_before_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in DECLARATION_ENDPOINT_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_declaration_endpoints_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in DECLARATION_ENDPOINT_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_declaration_endpoints_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model["attachments"].update(complete=False),
            lambda model: model.update(application_enabled=False),
            lambda model: model["coverage"].update(pods_complete=False),
        )
        for descriptor, mutate in zip(DECLARATION_ENDPOINT_COMPONENTS, mutations, strict=True):
            value = load_offline_specialist_component_request(ROOT / "examples" / descriptor[0])
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=descriptor[0]):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_azure_android_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in DECLARATION_ENDPOINT_COMPONENTS[:2]:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            self.assertNotIn("component_id", implicit)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_service_explicit_selection_preserves_network_policy_profile_default(self) -> None:
        legacy = load_offline_specialist_component_request(
            ROOT / "examples/offline-kubernetes-network-policy-component.json"
        )
        service = load_offline_specialist_component_request(
            ROOT / "examples/offline-kubernetes-service-component.json"
        )
        self.assertEqual(legacy["profile_id"], service["profile_id"])
        self.assertNotIn("component_id", legacy)
        self.assertEqual(
            service["component_id"], "kubernetes_supplied_service_endpoint_consistency"
        )
        prepared = prepare_offline_specialist_component_request(
            service, catalog=self.catalog, repository_root=ROOT
        )
        self.assertEqual(prepared, service)
        self.assertIsNot(prepared, service)
        legacy_result = self.run_component(legacy)
        service_result = self.run_component(service)
        self.assertEqual(
            legacy_result["component"]["component_id"], "kubernetes_supplied_network_policy_flows"
        )
        self.assertEqual(
            service_result["component"]["component_id"],
            "kubernetes_supplied_service_endpoint_consistency",
        )
        descriptors = [
            item
            for item in self.catalog.to_dict()["components"]
            if item["profile_id"] == "AOE-GC-D15-S07"
        ]
        self.assertEqual(
            {item["component_id"] for item in descriptors},
            {
                "kubernetes_supplied_network_policy_flows",
                "kubernetes_supplied_service_endpoint_consistency",
            },
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                legacy_result, request=service, catalog=self.catalog, repository_root=ROOT
            )

    def test_firewall_entitlement_topic_run_distinct_math_without_candidate_promotion(
        self,
    ) -> None:
        identities = (
            "GCFA-8E3869008A986AF8D276431ADA36B8A3",
            "IEA-6B521E7012850EFFCFE54D67DA106371",
            "MQT-34556B64BB2AE71B5D849A8FC97EFBCC",
        )
        for descriptor, analysis_id in zip(
            FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS, identities, strict=True
        ):
            filename, component_id, profile_id, _analyzer = descriptor
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                analysis = result["analysis"]
                self.assertEqual(analysis["analysis_id"], analysis_id)
                self.assertEqual(analysis["source_model"], value["payload"]["model"])
                self.assertEqual(set(analysis["effects"].values()), {"none"})
                if component_id == "gcp_supplied_vpc_firewall_new_flow_predicates":
                    rows = {row["flow_id"]: row for row in analysis["flow_observations"]}
                    self.assertEqual(
                        rows["synthetic-ingress"]["decision"],
                        "allow_under_supplied_vpc_predicates",
                    )
                    self.assertEqual(
                        rows["synthetic-ingress"]["winning_rule_ids"],
                        ["ingress-one", "ingress-two"],
                    )
                    self.assertIs(rows["synthetic-ingress"]["winning_witnesses_complete"], True)
                    self.assertEqual(rows["synthetic-egress"]["decision"], "unassessed")
                    self.assertEqual(rows["synthetic-egress"]["candidate_priority"], 50)
                    self.assertEqual(
                        analysis["summary"],
                        {"flows": 2, "allow": 1, "deny": 0, "unassessed": 1},
                    )
                    self.assertEqual(set(analysis["flags"].values()), {False})
                elif component_id == "ios_supplied_entitlement_declaration_consistency":
                    self.assertEqual(
                        analysis["summary"],
                        {
                            "status": "consistent_supplied_subset",
                            "application_claim_count": 4,
                            "profile_grant_count": 5,
                            "matched_claim_count": 4,
                            "mismatched_claim_count": 0,
                            "unavailable_claim_count": 0,
                        },
                    )
                    token = [
                        row
                        for row in analysis["entitlement_observations"]
                        if row["claim_value"] == "com.apple.token"
                    ]
                    self.assertEqual(len(token), 1)
                    self.assertEqual(token[0]["matched_profile_grants"], ["com.apple.token"])
                    self.assertEqual(analysis["uncertainties"], [])
                    self.assertEqual(set(analysis["flags"].values()), {False})
                else:
                    self.assertEqual(
                        {row["query_id"]: row["matches"] for row in analysis["match_results"]},
                        {
                            "empty-level": True,
                            "literal-system": True,
                            "parent": True,
                            "sensor-a": True,
                            "unicode": True,
                            "wildcard-system": False,
                        },
                    )
                    self.assertEqual(
                        [
                            (row["query_id"], row["status"], row["witness_topic"])
                            for row in analysis["overlap_results"]
                        ],
                        [
                            ("sensors", "overlap_witness", "sensors//temperature"),
                            ("system-root", "disjoint", None),
                            ("system-self", "overlap_witness", "$SYS"),
                        ],
                    )
                    self.assertEqual(analysis["unicode_cautions"], [])
                    self.assertEqual(set(analysis["claims"].values()), {False})

    def test_firewall_entitlement_topic_deny_resources_and_open_payload_before_analysis(
        self,
    ) -> None:
        for (
            filename,
            _component_id,
            _profile_id,
            analyzer_name,
        ) in FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_firewall_entitlement_topic_rehashed_promotion_cannot_replace_source_replay(
        self,
    ) -> None:
        for (
            filename,
            _component_id,
            _profile_id,
            _analyzer,
        ) in FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_firewall_entitlement_topic_original_model_change_requires_new_result(
        self,
    ) -> None:
        mutations = (
            lambda model: model.update(rules_complete=False),
            lambda model: model["coverage"].update(profile_entitlements_complete=False),
            lambda model: model["topics"][0].update(topic_name="different/topic"),
        )
        for descriptor, mutate in zip(
            FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS, mutations, strict=True
        ):
            value = load_offline_specialist_component_request(ROOT / "examples" / descriptor[0])
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=descriptor[0]):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_firewall_entitlement_topic_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in FIREWALL_ENTITLEMENT_TOPIC_COMPONENTS:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            self.assertNotIn("component_id", implicit)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_protocol_artifact_predicates_run_without_candidate_promotion(self) -> None:
        identities = (
            "MBA-E5E5C5DE7EDB86092DA55CBB427CE751",
            "DXA-3D127A90FAF3E4D797F6BBAB7C33F484",
            "CFA-E502807486A313E8A1834D615A80C434",
        )
        for descriptor, analysis_id in zip(PROTOCOL_ARTIFACT_COMPONENTS, identities, strict=True):
            filename, component_id, profile_id, _analyzer = descriptor
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(value)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(
                    result,
                    self.verify_component(
                        result, request=value, catalog=self.catalog, repository_root=ROOT
                    ),
                )
                analysis = result["analysis"]
                self.assertEqual(analysis["analysis_id"], analysis_id)
                self.assertEqual(analysis["source_model"], value["payload"]["model"])
                self.assertEqual(set(analysis["effects"].values()), {"none"})
                if component_id == "modbus_supplied_tcp_read_exchange_structure":
                    self.assertEqual(analysis["outcome"], "consistent_supported_read_structure")
                    self.assertEqual(analysis["response"]["register_values"], [555, 0, 100])
                    self.assertEqual(analysis["source_bytes"]["request_length"], 12)
                    self.assertEqual(analysis["source_bytes"]["response_length"], 15)
                    self.assertEqual(set(analysis["claims"].values()), {False})
                elif component_id == "android_supplied_dex035_structure":
                    self.assertEqual(
                        analysis["analysis_status"], "supported_structure_subset_consistent"
                    )
                    self.assertEqual(
                        analysis["integrity"],
                        {
                            "adler32_matches": True,
                            "sha1_matches": True,
                            "authenticates_origin": False,
                        },
                    )
                    self.assertEqual(set(analysis["flags"].values()), {False})
                    self.assertEqual(analysis["source_file_bytes"], 196)
                    self.assertEqual(
                        [row["utf16_units"] for row in analysis["string_observations"]],
                        [[0, 65], [72, 101, 108, 108, 111], [55296]],
                    )
                else:
                    self.assertEqual(
                        {
                            row["query_id"]: row["decision"]
                            for row in analysis["query_observations"]
                        },
                        {
                            "image.same-upgrade": "allowed_supplied_subset",
                            "font.denied": "blocked_supplied_subset",
                            "connect.external": "allowed_supplied_subset",
                        },
                    )
                    self.assertEqual(set(analysis["flags"].values()), {False})

    def test_protocol_artifact_resources_and_open_payload_deny_before_leaf_analysis(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in PROTOCOL_ARTIFACT_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("credential_refs", ["env:TOKEN"]),
                ("dry_run", False),
                ("component_id", "graphql_query_structure"),
                ("schema_version", True),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            changed = copy.deepcopy(original)
            changed["payload"]["callback"] = "not-authorized"
            cases.append(changed)
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_protocol_artifact_rehashed_promotion_cannot_replace_source_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in PROTOCOL_ARTIFACT_COMPONENTS:
            value = load_offline_specialist_component_request(ROOT / "examples" / filename)
            changed = copy.deepcopy(self.run_component(value))
            changed["positive_use_approved"] = True
            changed["full_candidate_assembled"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: item
                for key, item in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identifier, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identifier, result_sha256=digest)
            with self.subTest(filename=filename):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=value, catalog=self.catalog, repository_root=ROOT
                    )

    def test_protocol_artifact_original_model_change_requires_new_result(self) -> None:
        mutations = (
            lambda model: model.update(routing_context="unknown"),
            lambda model: model.update(source_id="different-supplied-dex"),
            lambda model: model.update(policy_list_complete=False),
        )
        for descriptor, mutate in zip(PROTOCOL_ARTIFACT_COMPONENTS, mutations, strict=True):
            value = load_offline_specialist_component_request(ROOT / "examples" / descriptor[0])
            original = self.run_component(value)
            changed = copy.deepcopy(value)
            mutate(changed["payload"]["model"])
            with self.subTest(filename=descriptor[0]):
                self.assertNotEqual(
                    original["request_sha256"], self.run_component(changed)["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        original, request=changed, catalog=self.catalog, repository_root=ROOT
                    )

    def test_modbus_dex_explicit_defaults_bind_original_request(self) -> None:
        for filename, component_id, _profile_id, _analyzer in PROTOCOL_ARTIFACT_COMPONENTS[:2]:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            self.assertNotIn("component_id", implicit)
            explicit = copy.deepcopy(implicit)
            explicit["component_id"] = component_id
            original = self.run_component(implicit)
            selected = self.run_component(explicit)
            with self.subTest(component_id=component_id):
                self.assertEqual(original["analysis"], selected["analysis"])
                self.assertEqual(original["component"], selected["component"])
                self.assertNotEqual(original["request_sha256"], selected["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        selected, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_csp_explicit_selection_preserves_cors_profile_default(self) -> None:
        cors = load_offline_specialist_component_request(
            ROOT / "examples/offline-cors-component.json"
        )
        csp = load_offline_specialist_component_request(
            ROOT / "examples/offline-csp-fetch-component.json"
        )
        self.assertNotIn("component_id", cors)
        self.assertEqual(cors["profile_id"], csp["profile_id"])
        self.assertEqual(csp["component_id"], "csp_supplied_external_fetch_predicates")
        legacy = self.run_component(cors)
        selected = self.run_component(csp)
        self.assertEqual(
            legacy["component"]["component_id"], "cors_supplied_negotiation_and_exposure"
        )
        self.assertEqual(selected["component"]["component_id"], csp["component_id"])
        descriptors = [
            item
            for item in self.catalog.to_dict()["components"]
            if item["profile_id"] == "AOE-GB-D05-S14"
        ]
        self.assertEqual(
            {item["component_id"] for item in descriptors},
            {"cors_supplied_negotiation_and_exposure", "csp_supplied_external_fetch_predicates"},
        )
        omitted = copy.deepcopy(csp)
        del omitted["component_id"]
        with self.assertRaises(CorsAnalysisError):
            self.run_component(omitted)
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                legacy, request=csp, catalog=self.catalog, repository_root=ROOT
            )

    def test_wire_mobile_components_bind_existing_profiles_and_complete_leaf_results(self) -> None:
        identities = (
            "MCA-B483D07354A521FE0B2D95415A832051",
            "PWA-02722282DD5DD43063BDF55EAEE4A331",
            "CPA-66FB4FD8E250AD5B9C97C6175EF56DC6",
        )
        for descriptor, identity in zip(WIRE_MOBILE_COMPONENTS, identities, strict=True):
            filename, component_id, profile_id, analyzer_name = descriptor
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            source = copy.deepcopy(original)
            result = self.run_component(source)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["analysis"]["analysis_id"], identity)
                self.assertEqual(
                    result["analysis"],
                    getattr(component_module, analyzer_name)(
                        original["payload"]["model"]
                    ).to_dict(),
                )
                self.assertEqual(source, original)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                for flag in ("full_candidate_assembled", "positive_use_approved"):
                    self.assertIs(result[flag], False)
                claim_family = (
                    "flags" if component_id == "ios_supplied_macho64_layout" else "claims"
                )
                self.assertIs(result["analysis"][claim_family]["qualification_claimed"], False)
                self.assertEqual(
                    self.verify_component(
                        result, request=original, catalog=self.catalog, repository_root=ROOT
                    ),
                    result,
                )

    def test_wire_mobile_resource_envelopes_deny_before_any_leaf(self) -> None:
        for filename, _component_id, _profile_id, analyzer_name in WIRE_MOBILE_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("dry_run", False),
                ("credential_refs", ["env:TOKEN"]),
                ("schema_version", True),
                ("component_id", "graphql_query_structure"),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_wire_mobile_cohashed_promotion_and_source_changes_require_fresh_replay(self) -> None:
        for filename, _component_id, _profile_id, _analyzer in WIRE_MOBILE_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(original)
            changed = copy.deepcopy(result)
            changed["full_candidate_assembled"] = True
            changed["positive_use_approved"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: value
                for key, value in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    changed, request=original, catalog=self.catalog, repository_root=ROOT
                )
            alternate = copy.deepcopy(original)
            key = "request_source_id" if filename == "offline-coap-component.json" else "source_id"
            alternate["payload"]["model"][key] = "different-supplied-source"
            self.assertNotEqual(
                self.run_component(alternate)["request_sha256"], result["request_sha256"]
            )
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    result, request=alternate, catalog=self.catalog, repository_root=ROOT
                )

    def test_protobuf_wire_and_coap_selectors_preserve_existing_defaults(self) -> None:
        for old_filename, new_filename, expected_default in (
            (
                "offline-protobuf-component.json",
                "offline-protobuf-wire-component.json",
                "protobuf_schema_evolution",
            ),
            (
                "offline-mqtt-topic-component.json",
                "offline-coap-component.json",
                "mqtt_supplied_topic_filter_arithmetic",
            ),
        ):
            old = load_offline_specialist_component_request(ROOT / "examples" / old_filename)
            new = load_offline_specialist_component_request(ROOT / "examples" / new_filename)
            self.assertNotIn("component_id", old)
            self.assertEqual(old["profile_id"], new["profile_id"])
            self.assertEqual(self.run_component(old)["component"]["component_id"], expected_default)
            self.assertEqual(
                self.run_component(new)["component"]["component_id"], new["component_id"]
            )
            omitted = copy.deepcopy(new)
            omitted.pop("component_id")
            expected_error = (
                OfflineSpecialistComponentError
                if expected_default == "protobuf_schema_evolution"
                else MqttTopicAnalysisError
            )
            with self.assertRaises(expected_error):
                self.run_component(omitted)

    def test_macho_default_and_explicit_selection_retain_distinct_original_envelopes(self) -> None:
        implicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-macho-component.json"
        )
        self.assertNotIn("component_id", implicit)
        explicit = implicit | {"component_id": "ios_supplied_macho64_layout"}
        first, second = self.run_component(implicit), self.run_component(explicit)
        self.assertEqual(first["analysis"], second["analysis"])
        self.assertEqual(first["component"], second["component"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                second, request=implicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_binary_dhcp_components_bind_existing_profiles_and_complete_leaf_results(self) -> None:
        identities = (
            "ELA-FB5174CB553DB919349588D8ACCD4F1B",
            "PLA-1050EEA7981D9E9098761D1618D067BE",
            "D4A-2448D8984FAB8D9ECA12DC19D87894B3",
        )
        for descriptor, identity in zip(BINARY_DHCP_COMPONENTS, identities, strict=True):
            filename, component_id, profile_id, analyzer_name, claim_family = descriptor
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            source = copy.deepcopy(original)
            result = self.run_component(source)
            with self.subTest(component_id=component_id):
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["analysis"]["analysis_id"], identity)
                self.assertEqual(
                    result["analysis"],
                    getattr(component_module, analyzer_name)(
                        original["payload"]["model"]
                    ).to_dict(),
                )
                self.assertEqual(source, original)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                for flag in ("full_candidate_assembled", "positive_use_approved"):
                    self.assertIs(result[flag], False)
                self.assertIs(result["analysis"][claim_family]["qualification_claimed"], False)
                self.assertEqual(
                    self.verify_component(
                        result, request=original, catalog=self.catalog, repository_root=ROOT
                    ),
                    result,
                )

    def test_binary_dhcp_resource_envelopes_deny_before_any_leaf(self) -> None:
        for filename, _component, _profile, analyzer_name, _claims in BINARY_DHCP_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("action_tier", "R1"),
                ("environment", "production"),
                ("dry_run", False),
                ("credential_refs", ["env:TOKEN"]),
                ("schema_version", True),
                ("component_id", "graphql_query_structure"),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
            with patch("sunderkey.offline_specialist_components." + analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_binary_dhcp_cohashed_promotions_and_source_changes_require_current_replay(
        self,
    ) -> None:
        for filename, _component, _profile, _analyzer, _claims in BINARY_DHCP_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(original)
            changed = copy.deepcopy(result)
            changed["full_candidate_assembled"] = True
            changed["positive_use_approved"] = True
            changed["operational_effects"]["execution"] = "approved"
            body = {
                key: value
                for key, value in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    changed, request=original, catalog=self.catalog, repository_root=ROOT
                )
            alternate = copy.deepcopy(original)
            key = (
                "request_source_id" if filename == "offline-dhcpv4-component.json" else "source_id"
            )
            alternate["payload"]["model"][key] = "different-supplied-source"
            self.assertNotEqual(
                self.run_component(alternate)["request_sha256"], result["request_sha256"]
            )
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    result, request=alternate, catalog=self.catalog, repository_root=ROOT
                )

    def test_dhcp_selector_preserves_the_original_dns_message_default(self) -> None:
        dns = load_offline_specialist_component_request(
            ROOT / "examples/offline-dns-message-component.json"
        )
        dhcp = load_offline_specialist_component_request(
            ROOT / "examples/offline-dhcpv4-component.json"
        )
        self.assertNotIn("component_id", dns)
        self.assertEqual(dns["profile_id"], dhcp["profile_id"])
        self.assertEqual(
            self.run_component(dns)["component"]["component_id"],
            "dns_supplied_wire_structure",
        )
        self.assertEqual(
            self.run_component(dhcp)["component"]["component_id"],
            "dhcpv4_supplied_offer_ack_structure",
        )
        omitted = copy.deepcopy(dhcp)
        omitted.pop("component_id")
        with self.assertRaises(DnsMessageAnalysisError):
            self.run_component(omitted)

    def test_binary_default_and_explicit_selectors_bind_their_original_envelopes(self) -> None:
        for filename, component_id, _profile, _analyzer, _claims in BINARY_DHCP_COMPONENTS[:2]:
            implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
            self.assertNotIn("component_id", implicit)
            explicit = implicit | {"component_id": component_id}
            first, second = self.run_component(implicit), self.run_component(explicit)
            self.assertEqual(first["analysis"], second["analysis"])
            self.assertEqual(first["component"], second["component"])
            self.assertNotEqual(first["request_sha256"], second["request_sha256"])
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    second, request=implicit, catalog=self.catalog, repository_root=ROOT
                )

    def test_prepare_preserves_original_defaults_and_detached_owned_envelope(self) -> None:
        original = graphql_request()
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyzer:
            prepared = prepare_offline_specialist_component_request(
                original, catalog=self.catalog, repository_root=ROOT
            )
            self.assertEqual(prepared, original)
            self.assertIsNot(prepared, original)
            self.assertIsNot(prepared["payload"], original["payload"])
            self.assertNotIn("component_id", prepared)
            prepared["payload"]["query_content"] = "{ users { id } }"
            self.assertNotEqual(prepared["payload"], original["payload"])
            explicit = copy.deepcopy(original)
            explicit["component_id"] = "graphql_query_structure"
            self.assertEqual(
                prepare_offline_specialist_component_request(
                    explicit, catalog=self.catalog, repository_root=ROOT
                ),
                explicit,
            )
            analyzer.assert_not_called()

    def test_native_del_escaping_is_reserved_before_canonical_serialization(self) -> None:
        for value in (
            "\x7f" * 60,
            "\x7f\u03bb" * 30,
            {"\x7f" * 8: "\x7f" * 12},
            ["\x7f" * 12, "\x7f\U0001f642" * 4],
        ):
            rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            maximum = len(rendered.encode("ascii"))
            with self.subTest(value_type=type(value).__name__, maximum=maximum):
                self.assertEqual(_native(value, maximum_bytes=maximum), rendered)
                with (
                    patch("sunderkey.offline_specialist_components._canonical_json") as canonical,
                    self.assertRaises(OfflineSpecialistComponentError),
                ):
                    _native(value, maximum_bytes=maximum - 1)
                canonical.assert_not_called()

    def test_prepare_rejects_shared_boundary_and_open_payload_before_analysis(self) -> None:
        original = graphql_request()
        cases = []
        for field in ("network", "filesystem", "process", "credential"):
            changed = copy.deepcopy(original)
            changed["resources"][field] = ["not-authorized"]
            cases.append(changed)
        for field, value in (
            ("schema_version", True),
            ("action_tier", "R1"),
            ("dry_run", False),
            ("credential_refs", ["env:TOKEN"]),
            ("environment", "production"),
            ("component_id", "dns_supplied_zone_lookup"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        changed = copy.deepcopy(original)
        changed["payload"]["callback"] = "not-authorized"
        cases.append(changed)
        with patch("sunderkey.offline_specialist_components.analyze_graphql_operation") as analyzer:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        prepare_offline_specialist_component_request(
                            changed, catalog=self.catalog, repository_root=ROOT
                        )
            analyzer.assert_not_called()

    def test_webauthn_binds_existing_profile_and_complete_original_leaf(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-webauthn-assertion-component.json"
        )
        supplied = copy.deepcopy(original)
        result = self.run_component(supplied)
        self.assertEqual(result["component"]["profile_id"], "AOE-GA-D03-S08")
        self.assertEqual(
            result["component"]["component_id"],
            "webauthn_supplied_assertion_context_arithmetic",
        )
        self.assertEqual(result["analysis"]["analysis_id"], "WAA-BE65FA2B0545BFC348421C8EB4E4ACA8")
        self.assertEqual(
            result["analysis"],
            component_module.analyze_supplied_webauthn_assertion(
                original["payload"]["model"]
            ).to_dict(),
        )
        self.assertEqual(supplied, original)
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in result["analysis"]["claims"].values()))
        for flag in ("full_candidate_assembled", "positive_use_approved"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            self.verify_component(
                result, request=original, catalog=self.catalog, repository_root=ROOT
            ),
            result,
        )

    def test_webauthn_open_envelopes_deny_before_any_assertion_analysis(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-webauthn-assertion-component.json"
        )
        cases = []
        for field in ("network", "filesystem", "process", "credential"):
            changed = copy.deepcopy(original)
            changed["resources"][field] = ["not-authorized"]
            cases.append(changed)
        for field, value in (
            ("action_tier", "R1"),
            ("environment", "production"),
            ("dry_run", False),
            ("credential_refs", ["env:TOKEN"]),
            ("schema_version", True),
            ("component_id", "supplied_jose_signature_and_claims"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
        with patch.object(component_module, "analyze_supplied_webauthn_assertion") as analyzer:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_webauthn_cohashed_authority_or_false_checks_require_current_replay(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-webauthn-assertion-component.json"
        )
        result = self.run_component(original)
        for false_leaf in (False, True):
            changed = copy.deepcopy(result)
            if false_leaf:
                analysis = changed["analysis"]
                analysis["checks"]["origin_matches"] = False
                analysis["analysis_status"] = "contradictory_supplied_checks"
                leaf_body = {
                    key: child
                    for key, child in analysis.items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                preimage = (
                    "sunderkey.offline-webauthn-assertion-analysis.v1\n"
                    + json.dumps(
                        leaf_body,
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                ).encode("ascii")
                leaf_digest = hashlib.sha256(preimage).hexdigest()
                analysis.update(
                    analysis_id="WAA-" + leaf_digest[:32].upper(),
                    analysis_sha256="sha256:" + leaf_digest,
                )
            else:
                changed["full_candidate_assembled"] = True
                changed["positive_use_approved"] = True
                changed["operational_effects"]["execution"] = "approved"
            body = {
                key: child
                for key, child in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.subTest(false_leaf=false_leaf):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=original, catalog=self.catalog, repository_root=ROOT
                    )

    def test_webauthn_source_change_requires_the_separately_supplied_original(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-webauthn-assertion-component.json"
        )
        result = self.run_component(original)
        alternate = copy.deepcopy(original)
        alternate["payload"]["model"]["source_id"] = "different-assertion-source"
        self.assertNotEqual(
            self.run_component(alternate)["request_sha256"], result["request_sha256"]
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=alternate, catalog=self.catalog, repository_root=ROOT
            )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_webauthn_default_and_explicit_selectors_bind_distinct_envelopes(self) -> None:
        implicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-webauthn-assertion-component.json"
        )
        self.assertNotIn("component_id", implicit)
        explicit = implicit | {"component_id": "webauthn_supplied_assertion_context_arithmetic"}
        first, second = self.run_component(implicit), self.run_component(explicit)
        self.assertEqual(first["analysis"], second["analysis"])
        self.assertEqual(first["component"], second["component"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                second, request=implicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_mail_pack_components_bind_existing_profiles_and_complete_leaf_results(self) -> None:
        selections = (
            (
                "offline-dkim-component.json",
                "AOE-GC-D13-S14",
                "dkim_supplied_canonicalization_and_body_hash",
                "DCA-F58B5A06975C4D52D03EF747BA432A59",
                "analyze_supplied_dkim_canonicalization",
                "flags",
            ),
            (
                "offline-git-pack-component.json",
                "AOE-GC-D17-S01",
                "git_supplied_pack_ofs_delta_reconstruction",
                "GPA-BEBB5F5D47375804D82DAB4E0EB7D4F6",
                "analyze_supplied_git_pack",
                "claims",
            ),
        )
        for filename, profile, component, golden, analyzer_name, flags in selections:
            with self.subTest(component=component):
                original = load_offline_specialist_component_request(ROOT / "examples" / filename)
                supplied = copy.deepcopy(original)
                result = self.run_component(supplied)
                self.assertEqual(result["component"]["profile_id"], profile)
                self.assertEqual(result["component"]["component_id"], component)
                self.assertEqual(result["analysis"]["analysis_id"], golden)
                analyzer = getattr(component_module, analyzer_name)
                self.assertEqual(
                    result["analysis"], analyzer(original["payload"]["model"]).to_dict()
                )
                self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])
                self.assertEqual(supplied, original)
                self.assertTrue(all(value is False for value in result["analysis"][flags].values()))
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                for flag in ("full_candidate_assembled", "positive_use_approved"):
                    self.assertIs(result[flag], False)
                self.assertEqual(
                    self.verify_component(
                        result, request=original, catalog=self.catalog, repository_root=ROOT
                    ),
                    result,
                )

    def test_mail_pack_open_envelopes_deny_before_any_leaf(self) -> None:
        selections = (
            ("offline-dkim-component.json", "analyze_supplied_dkim_canonicalization"),
            ("offline-git-pack-component.json", "analyze_supplied_git_pack"),
        )
        for filename, analyzer_name in selections:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("schema_version", True),
                ("action_tier", "R1"),
                ("environment", "production"),
                ("dry_run", False),
                ("credential_refs", ["env:TOKEN"]),
                ("component_id", "webauthn_supplied_assertion_context_arithmetic"),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
            with patch.object(component_module, analyzer_name) as analyzer:
                for changed in cases:
                    with self.subTest(filename=filename, changed=changed):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(changed)
                analyzer.assert_not_called()

    def test_mail_pack_cohashed_reports_and_alternate_sources_require_current_replay(self) -> None:
        selections = (
            (
                "offline-dkim-component.json",
                "sunderkey.offline-dkim-canonicalization-analysis.v1",
                "DCA-",
            ),
            (
                "offline-git-pack-component.json",
                "sunderkey.offline-git-pack-analysis.v1",
                "GPA-",
            ),
        )
        for filename, leaf_domain, leaf_prefix in selections:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            result = self.run_component(original)
            for false_leaf in (False, True):
                changed = copy.deepcopy(result)
                if false_leaf:
                    analysis = changed["analysis"]
                    if leaf_prefix == "DCA-":
                        analysis["body_observation"]["body_hash_matches_supplied_bh"] = False
                        analysis["declared_arithmetic_violations"].append(
                            "declared_body_hash_mismatch"
                        )
                    else:
                        analysis["pack"]["entries"][0]["mechanical_object_sha1"] = (
                            "sha1:" + "0" * 40
                        )
                    leaf_body = {
                        key: value
                        for key, value in analysis.items()
                        if key not in {"analysis_id", "analysis_sha256"}
                    }
                    preimage = (
                        leaf_domain
                        + "\n"
                        + json.dumps(
                            leaf_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                        )
                    ).encode("ascii")
                    digest = hashlib.sha256(preimage).hexdigest()
                    analysis.update(
                        analysis_id=leaf_prefix + digest[:32].upper(),
                        analysis_sha256="sha256:" + digest,
                    )
                else:
                    changed["full_candidate_assembled"] = True
                    changed["positive_use_approved"] = True
                    changed["operational_effects"]["execution"] = "approved"
                body = {
                    key: value
                    for key, value in changed.items()
                    if key not in {"result_id", "result_sha256"}
                }
                identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
                changed.update(result_id=identity, result_sha256=digest)
                with self.subTest(filename=filename, false_leaf=false_leaf):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.verify_component(
                            changed, request=original, catalog=self.catalog, repository_root=ROOT
                        )
            alternate = copy.deepcopy(original)
            alternate["payload"]["model"]["source_id"] = "different-supplied-source"
            self.assertNotEqual(
                self.run_component(alternate)["request_sha256"], result["request_sha256"]
            )
            with self.assertRaises(OfflineSpecialistComponentError):
                self.verify_component(
                    result, request=alternate, catalog=self.catalog, repository_root=ROOT
                )
            self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_mail_pack_defaults_and_explicit_selectors_keep_original_envelopes(self) -> None:
        selections = (
            ("offline-dkim-component.json", "dkim_supplied_canonicalization_and_body_hash"),
            ("offline-git-pack-component.json", "git_supplied_pack_ofs_delta_reconstruction"),
        )
        for filename, component in selections:
            with self.subTest(component=component):
                implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
                self.assertNotIn("component_id", implicit)
                explicit = implicit | {"component_id": component}
                first, second = self.run_component(implicit), self.run_component(explicit)
                self.assertEqual(first["analysis"], second["analysis"])
                self.assertEqual(first["component"], second["component"])
                self.assertNotEqual(first["request_sha256"], second["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        second, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    def test_wasm_binds_existing_profile_and_complete_original_leaf(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-wasm-numeric-stack-component.json"
        )
        supplied = copy.deepcopy(original)
        result = self.run_component(supplied)
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D21-S19")
        self.assertEqual(
            result["component"]["component_id"], "wasm_supplied_numeric_stack_and_interfaces"
        )
        self.assertEqual(result["analysis"]["analysis_id"], "WSA-D4337DA9B92BBAFA34E1F4278AAC2294")
        self.assertEqual(
            result["analysis"],
            component_module.analyze_supplied_wasm_numeric_stack(
                original["payload"]["model"]
            ).to_dict(),
        )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])
        self.assertEqual(result["analysis"]["functions"][0]["terminal_result_types"], ["i32"])
        self.assertIs(result["analysis"]["flags"]["full_wasm_validation"], False)
        self.assertIs(result["analysis"]["flags"]["host_permissions_verified"], False)
        self.assertTrue(all(value is False for value in result["analysis"]["flags"].values()))
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertIs(result["full_candidate_assembled"], False)
        self.assertIs(result["positive_use_approved"], False)
        self.assertEqual(supplied, original)
        self.assertEqual(
            self.verify_component(
                result, request=original, catalog=self.catalog, repository_root=ROOT
            ),
            result,
        )

    def test_wasm_open_envelopes_deny_before_module_analysis(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-wasm-numeric-stack-component.json"
        )
        cases = []
        for field in ("network", "filesystem", "process", "credential"):
            changed = copy.deepcopy(original)
            changed["resources"][field] = ["not-authorized"]
            cases.append(changed)
        for field, value in (
            ("schema_version", True),
            ("action_tier", "R1"),
            ("environment", "production"),
            ("dry_run", False),
            ("credential_refs", ["env:TOKEN"]),
            ("component_id", "git_supplied_pack_ofs_delta_reconstruction"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
        with patch.object(component_module, "analyze_supplied_wasm_numeric_stack") as analyzer:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_wasm_cohashed_stack_or_authority_cannot_replace_original_replay(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-wasm-numeric-stack-component.json"
        )
        result = self.run_component(original)
        for false_leaf in (False, True):
            changed = copy.deepcopy(result)
            if false_leaf:
                analysis = changed["analysis"]
                analysis["functions"][0]["terminal_result_types"] = ["i64"]
                leaf_body = {
                    key: value
                    for key, value in analysis.items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                preimage = (
                    "sunderkey.offline-wasm-numeric-stack-analysis.v1\n"
                    + json.dumps(
                        leaf_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    )
                ).encode("ascii")
                digest = hashlib.sha256(preimage).hexdigest()
                analysis.update(
                    analysis_id="WSA-" + digest[:32].upper(),
                    analysis_sha256="sha256:" + digest,
                )
            else:
                changed["full_candidate_assembled"] = True
                changed["positive_use_approved"] = True
                changed["operational_effects"]["execution"] = "approved"
            body = {
                key: value
                for key, value in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.subTest(false_leaf=false_leaf):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=original, catalog=self.catalog, repository_root=ROOT
                    )
        alternate = copy.deepcopy(original)
        alternate["payload"]["model"]["source_id"] = "different-module-source"
        self.assertNotEqual(
            self.run_component(alternate)["request_sha256"], result["request_sha256"]
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=alternate, catalog=self.catalog, repository_root=ROOT
            )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_wasm_default_and_explicit_selectors_keep_original_envelopes(self) -> None:
        implicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-wasm-numeric-stack-component.json"
        )
        self.assertNotIn("component_id", implicit)
        explicit = implicit | {"component_id": "wasm_supplied_numeric_stack_and_interfaces"}
        first, second = self.run_component(implicit), self.run_component(explicit)
        self.assertEqual(first["analysis"], second["analysis"])
        self.assertEqual(first["component"], second["component"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                second, request=implicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_ssh_binds_existing_profile_and_complete_original_leaf(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ssh-kexinit-component.json"
        )
        supplied = copy.deepcopy(original)
        result = self.run_component(supplied)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D12-S06")
        self.assertEqual(
            result["component"]["component_id"], "ssh_supplied_kexinit_selection_arithmetic"
        )
        self.assertEqual(result["analysis"]["analysis_id"], "SKA-3CB2321BD41F99BB674FD0CA767537D4")
        self.assertEqual(
            result["analysis"],
            component_module.analyze_supplied_ssh_kexinit_pair(
                original["payload"]["model"]
            ).to_dict(),
        )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])
        self.assertEqual(
            result["analysis"]["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )
        self.assertTrue(all(value is False for value in result["analysis"]["claims"].values()))
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertIs(result["full_candidate_assembled"], False)
        self.assertIs(result["positive_use_approved"], False)
        self.assertEqual(supplied, original)
        self.assertEqual(
            self.verify_component(
                result, request=original, catalog=self.catalog, repository_root=ROOT
            ),
            result,
        )

    def test_ssh_open_envelopes_deny_before_declaration_analysis(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ssh-kexinit-component.json"
        )
        cases = []
        for field in ("network", "filesystem", "process", "credential"):
            changed = copy.deepcopy(original)
            changed["resources"][field] = ["not-authorized"]
            cases.append(changed)
        for field, value in (
            ("schema_version", True),
            ("action_tier", "R1"),
            ("environment", "production"),
            ("dry_run", False),
            ("credential_refs", ["env:TOKEN"]),
            ("component_id", "wasm_supplied_numeric_stack_and_interfaces"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
        with patch.object(component_module, "analyze_supplied_ssh_kexinit_pair") as analyzer:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_ssh_cohashed_candidate_or_authority_requires_original_replay(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ssh-kexinit-component.json"
        )
        result = self.run_component(original)
        for false_leaf in (False, True):
            changed = copy.deepcopy(result)
            if false_leaf:
                analysis = changed["analysis"]
                analysis["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"] = (
                    "diffie-hellman-group1-sha1"
                )
                leaf_body = {
                    key: value
                    for key, value in analysis.items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                preimage = (
                    "sunderkey.offline-ssh-kexinit-analysis.v1\n"
                    + json.dumps(
                        leaf_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    )
                ).encode("ascii")
                digest = hashlib.sha256(preimage).hexdigest()
                analysis.update(
                    analysis_id="SKA-" + digest[:32].upper(),
                    analysis_sha256="sha256:" + digest,
                )
            else:
                changed["full_candidate_assembled"] = True
                changed["positive_use_approved"] = True
                changed["operational_effects"]["execution"] = "approved"
            body = {
                key: value
                for key, value in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.subTest(false_leaf=false_leaf):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=original, catalog=self.catalog, repository_root=ROOT
                    )
        alternate = copy.deepcopy(original)
        alternate["payload"]["model"]["source_id"] = "different-ssh-declarations"
        self.assertNotEqual(
            self.run_component(alternate)["request_sha256"], result["request_sha256"]
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=alternate, catalog=self.catalog, repository_root=ROOT
            )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_ssh_default_and_explicit_selectors_keep_original_envelopes(self) -> None:
        implicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-ssh-kexinit-component.json"
        )
        self.assertNotIn("component_id", implicit)
        explicit = implicit | {"component_id": "ssh_supplied_kexinit_selection_arithmetic"}
        first, second = self.run_component(implicit), self.run_component(explicit)
        self.assertEqual(first["analysis"], second["analysis"])
        self.assertEqual(first["component"], second["component"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                second, request=implicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_ipv4_binds_existing_profile_and_complete_original_leaf(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ipv4-fragment-component.json"
        )
        supplied = copy.deepcopy(original)
        result = self.run_component(supplied)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D13-S01")
        self.assertEqual(
            result["component"]["component_id"],
            "ipv4_supplied_fragment_relations_and_header_checksums",
        )
        self.assertEqual(result["analysis"]["analysis_id"], "IPFA-64520398ED7C645DF9A533D3EA01F3EB")
        self.assertEqual(
            result["analysis"],
            component_module.analyze_supplied_ipv4_fragments(
                original["payload"]["model"]
            ).to_dict(),
        )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])
        relation = result["analysis"]["fragment_sets"][0]
        self.assertEqual(relation["merged_supplied_intervals"], [[0, 24]])
        self.assertEqual(relation["union_octets"], 24)
        self.assertEqual(
            relation["conditional_single_tuple_conclusion"], "consistent_supplied_arithmetic"
        )
        self.assertTrue(all(value is False for value in result["analysis"]["claims"].values()))
        self.assertEqual(set(result["analysis"]["effects"].values()), {"none"})
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertIs(result["full_candidate_assembled"], False)
        self.assertIs(result["positive_use_approved"], False)
        self.assertEqual(supplied, original)
        self.assertEqual(
            self.verify_component(
                result, request=original, catalog=self.catalog, repository_root=ROOT
            ),
            result,
        )

    def test_ipv4_open_envelopes_deny_before_octet_analysis(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ipv4-fragment-component.json"
        )
        cases = []
        for field in ("network", "filesystem", "process", "credential"):
            changed = copy.deepcopy(original)
            changed["resources"][field] = ["not-authorized"]
            cases.append(changed)
        for field, value in (
            ("schema_version", True),
            ("action_tier", "R1"),
            ("environment", "production"),
            ("dry_run", False),
            ("credential_refs", ["env:TOKEN"]),
            ("component_id", "ssh_supplied_kexinit_selection_arithmetic"),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            cases.append(changed)
        cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
        with patch.object(component_module, "analyze_supplied_ipv4_fragments") as analyzer:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaises(OfflineSpecialistComponentError):
                        self.run_component(changed)
            analyzer.assert_not_called()

    def test_ipv4_cohashed_relationship_or_authority_requires_original_replay(self) -> None:
        original = load_offline_specialist_component_request(
            ROOT / "examples/offline-ipv4-fragment-component.json"
        )
        result = self.run_component(original)
        for false_leaf in (False, True):
            changed = copy.deepcopy(result)
            if false_leaf:
                analysis = changed["analysis"]
                analysis["fragment_sets"][0]["union_octets"] = 25
                leaf_body = {
                    key: value
                    for key, value in analysis.items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                preimage = (
                    "sunderkey.offline-ipv4-fragment-analysis.v1\n"
                    + json.dumps(
                        leaf_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    )
                ).encode("ascii")
                digest = hashlib.sha256(preimage).hexdigest()
                analysis.update(
                    analysis_id="IPFA-" + digest[:32].upper(),
                    analysis_sha256="sha256:" + digest,
                )
            else:
                changed["full_candidate_assembled"] = True
                changed["positive_use_approved"] = True
                changed["operational_effects"]["execution"] = "approved"
            body = {
                key: value
                for key, value in changed.items()
                if key not in {"result_id", "result_sha256"}
            }
            identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
            changed.update(result_id=identity, result_sha256=digest)
            with self.subTest(false_leaf=false_leaf):
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        changed, request=original, catalog=self.catalog, repository_root=ROOT
                    )
        alternate = copy.deepcopy(original)
        alternate["payload"]["model"]["source_id"] = "different-fragment-source"
        self.assertNotEqual(
            self.run_component(alternate)["request_sha256"], result["request_sha256"]
        )
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                result, request=alternate, catalog=self.catalog, repository_root=ROOT
            )
        self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_ipv4_default_and_explicit_selectors_keep_original_envelopes(self) -> None:
        implicit = load_offline_specialist_component_request(
            ROOT / "examples/offline-ipv4-fragment-component.json"
        )
        self.assertNotIn("component_id", implicit)
        explicit = implicit | {
            "component_id": "ipv4_supplied_fragment_relations_and_header_checksums"
        }
        first, second = self.run_component(implicit), self.run_component(explicit)
        self.assertEqual(first["analysis"], second["analysis"])
        self.assertEqual(first["component"], second["component"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify_component(
                second, request=implicit, catalog=self.catalog, repository_root=ROOT
            )

    def test_bgp_wheel_amqp_bind_existing_profiles_and_complete_original_leaves(self) -> None:
        for (
            filename,
            component_id,
            profile_id,
            analyzer_name,
            golden_id,
            _,
            _,
        ) in BGP_WHEEL_AMQP_COMPONENTS:
            with self.subTest(component_id=component_id):
                original = load_offline_specialist_component_request(ROOT / "examples" / filename)
                supplied = copy.deepcopy(original)
                result = self.run_component(supplied)
                analysis = result["analysis"]
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertEqual(analysis["analysis_id"], golden_id)
                self.assertEqual(
                    analysis,
                    getattr(component_module, analyzer_name)(
                        original["payload"]["model"]
                    ).to_dict(),
                )
                self.assertEqual(analysis["source_model"], original["payload"]["model"])
                self.assertTrue(all(value is False for value in analysis["claims"].values()))
                self.assertEqual(set(analysis["effects"].values()), {"none"})
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(supplied, original)
                self.assertEqual(
                    self.verify_component(
                        result, request=original, catalog=self.catalog, repository_root=ROOT
                    ),
                    result,
                )
                if component_id == "bgp_supplied_update_structure":
                    self.assertEqual(
                        analysis["announced_prefixes"][0]["canonical_prefix"],
                        "203.0.113.0/24",
                    )
                    self.assertEqual(
                        analysis["analysis_status"], "consistent_with_supported_subset"
                    )
                elif component_id == "wheel_supplied_zip_record_integrity":
                    self.assertEqual(analysis["outcome"], "internal_integrity_matches")
                    self.assertEqual(analysis["member_count"], 4)
                else:
                    self.assertEqual(
                        analysis["analysis_status"], "consistent_with_supported_subset"
                    )
                    self.assertEqual(analysis["accounting"]["complete_publication_count"], 2)

    def test_bgp_wheel_amqp_open_envelopes_deny_before_leaf_analysis(self) -> None:
        for filename, component_id, _, analyzer_name, _, _, _ in BGP_WHEEL_AMQP_COMPONENTS:
            original = load_offline_specialist_component_request(ROOT / "examples" / filename)
            cases = []
            for field in ("network", "filesystem", "process", "credential"):
                changed = copy.deepcopy(original)
                changed["resources"][field] = ["not-authorized"]
                cases.append(changed)
            for field, value in (
                ("schema_version", True),
                ("action_tier", "R1"),
                ("environment", "production"),
                ("dry_run", False),
                ("credential_refs", ["env:TOKEN"]),
                ("component_id", "wasm_supplied_numeric_stack_and_interfaces"),
            ):
                changed = copy.deepcopy(original)
                changed[field] = value
                cases.append(changed)
            cases.append(original | {"payload": original["payload"] | {"callback": "denied"}})
            with self.subTest(component_id=component_id):
                with patch.object(component_module, analyzer_name) as analyzer:
                    for changed in cases:
                        with self.subTest(changed=changed):
                            with self.assertRaises(OfflineSpecialistComponentError):
                                self.run_component(changed)
                    analyzer.assert_not_called()

    def test_bgp_wheel_amqp_cohashed_false_results_require_original_replay(self) -> None:
        for filename, component_id, _, _, _, domain, prefix in BGP_WHEEL_AMQP_COMPONENTS:
            with self.subTest(component_id=component_id):
                original = load_offline_specialist_component_request(ROOT / "examples" / filename)
                result = self.run_component(original)
                for false_leaf in (False, True):
                    changed = copy.deepcopy(result)
                    if false_leaf:
                        analysis = changed["analysis"]
                        if component_id == "wheel_supplied_zip_record_integrity":
                            analysis["outcome"] = "internal_integrity_mismatch"
                        else:
                            analysis["analysis_status"] = "unassessed"
                        leaf_body = {
                            key: value
                            for key, value in analysis.items()
                            if key not in {"analysis_id", "analysis_sha256"}
                        }
                        preimage = (
                            domain
                            + "\n"
                            + json.dumps(
                                leaf_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                            )
                        ).encode("ascii")
                        digest = hashlib.sha256(preimage).hexdigest()
                        analysis.update(
                            analysis_id=prefix + digest[:32].upper(),
                            analysis_sha256="sha256:" + digest,
                        )
                    else:
                        changed["full_candidate_assembled"] = True
                        changed["positive_use_approved"] = True
                        changed["operational_effects"]["execution"] = "approved"
                    body = {
                        key: value
                        for key, value in changed.items()
                        if key not in {"result_id", "result_sha256"}
                    }
                    identity, digest = _address(body, RESULT_DOMAIN, "OSR-")
                    changed.update(result_id=identity, result_sha256=digest)
                    with self.subTest(false_leaf=false_leaf):
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.verify_component(
                                changed,
                                request=original,
                                catalog=self.catalog,
                                repository_root=ROOT,
                            )
                alternate = copy.deepcopy(original)
                alternate["payload"]["model"]["source_id"] = "different-supplied-source"
                self.assertNotEqual(
                    self.run_component(alternate)["request_sha256"], result["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        result, request=alternate, catalog=self.catalog, repository_root=ROOT
                    )
                self.assertEqual(result["analysis"]["source_model"], original["payload"]["model"])

    def test_bgp_wheel_amqp_defaults_bind_original_request_envelopes(self) -> None:
        for filename, component_id, _, _, _, _, _ in BGP_WHEEL_AMQP_COMPONENTS:
            with self.subTest(component_id=component_id):
                implicit = load_offline_specialist_component_request(ROOT / "examples" / filename)
                self.assertNotIn("component_id", implicit)
                explicit = implicit | {"component_id": component_id}
                first, second = self.run_component(implicit), self.run_component(explicit)
                self.assertEqual(first["analysis"], second["analysis"])
                self.assertEqual(first["component"], second["component"])
                self.assertNotEqual(first["request_sha256"], second["request_sha256"])
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify_component(
                        second, request=implicit, catalog=self.catalog, repository_root=ROOT
                    )

    @unittest.skipUnless(hasattr(__import__("os"), "mkfifo"), "POSIX FIFO only")
    def test_fifo_fixture_rejected_before_opening(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fixture.fifo"
            os.mkfifo(fifo)
            with patch("sunderkey.offline_specialist_components.os.open") as opened:
                with self.assertRaises(OfflineSpecialistComponentError):
                    load_offline_specialist_component_request(fifo)
                opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
