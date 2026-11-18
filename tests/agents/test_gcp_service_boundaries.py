"""Synthetic, effect-free GCP service-boundary review regressions."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import sunderkey.gcp_service_boundaries as boundary

from sunderkey.deployment_profile_contracts import build_standard_profile
from sunderkey.egress_proxy_contracts import EgressPolicy, EndpointRule
from sunderkey.gcp_resource_bindings import build_gcp_resource_binding_plan
from sunderkey.gcp_service_boundaries import (
    MAX_ITEMS,
    MAX_REVIEW_BYTES,
    GcpServiceBoundaryError,
    GcpServiceBoundaryReview,
    _address,
    review_gcp_service_boundaries,
    verify_gcp_service_boundary_review,
)
from sunderkey.production_deployment_decision_dossier import (
    load_production_deployment_decision_dossier,
)
from sunderkey.regional_custody_contracts import TenantRegionBinding

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "sunderkey-synthetic"
KEY = f"projects/{PROJECT}/locations/us-west3/keyRings/synthetic/cryptoKeys/"


class GcpServiceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = {
            "dossier": load_production_deployment_decision_dossier(
                ROOT / "registry/production-deployment-decision-dossier-d014.json"
            ),
            "deployment_profile": build_standard_profile("managed_service"),
            "regional_binding": TenantRegionBinding(
                "tenantref:synthetic",
                "policyref:synthetic",
                "sha256:" + "1" * 64,
                "1.0.0",
                "us-west3",
                ("us-west3",),
                ("us-west3",),
                "keyref:synthetic-encryption",
                "2026-09-27T12:00:00Z",
            ),
        }
        self.coordinates = {
            "provider": "gcp",
            "primary_region": "us-west3",
            "recovery_region": None,
            "projects": [{"project_id": PROJECT, "project_number": "123456789012"}],
            "service_accounts": [
                {
                    "service_identity_ref": "principalref:synthetic-" + name,
                    "project_id": PROJECT,
                    "account_id": "synthetic-" + name,
                    "unique_id": str(123456789012345678900 + index),
                }
                for index, name in enumerate(("worker", "custody", "proxy", "verifier"), 1)
            ],
            "kms_key_versions": [
                {
                    "key_ref": "keyref:synthetic-encryption",
                    "resource_name": KEY + "encryption/cryptoKeyVersions/1",
                    "purpose": "ENCRYPT_DECRYPT",
                    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                    "protection_level": "SOFTWARE",
                },
                {
                    "key_ref": "keyref:synthetic-signing",
                    "resource_name": KEY + "signing/cryptoKeyVersions/2",
                    "purpose": "ASYMMETRIC_SIGN",
                    "algorithm": "EC_SIGN_ED25519",
                    "protection_level": "SOFTWARE",
                },
            ],
            "gcs_buckets": [
                {
                    "storage_ref": "storeref:encrypted-local-evidence",
                    "project_id": PROJECT,
                    "bucket_name": "sunderkey-synthetic-evidence",
                    "location": "us-west3",
                    "encryption_key_ref": "keyref:synthetic-encryption",
                }
            ],
            "cloud_sql_instances": [],
        }
        self.resource_plan = build_gcp_resource_binding_plan(self.coordinates, **self.sources)
        self.policy = EgressPolicy(
            tenant_ref="tenantref:synthetic",
            mission_ref="missionref:synthetic",
            scope_ref="scoperef:synthetic",
            worker_ref=self.sources["deployment_profile"].worker_ref,
            policy_version=1,
            valid_from="2026-09-27T12:00:00Z",
            valid_until="2026-09-27T13:00:00Z",
            maximum_resolution_age_seconds=120,
            endpoint_rules=(
                EndpointRule(
                    "egressrule:synthetic",
                    "api.synthetic.example",
                    443,
                    ("POST",),
                    ("/v1/results",),
                    ("203.0.113.0/24", "2001:db8::/32"),
                    ("sha256:" + "2" * 64,),
                    4096,
                    8192,
                ),
            ),
        )
        policy = self.policy.to_dict()
        self.inputs = {
            "service_assignments": [
                {
                    "service_ref": "componentref:synthetic-worker",
                    "role": "restricted_execution_worker",
                    "service_identity_ref": "principalref:synthetic-worker",
                    "operations": [],
                },
                {
                    "service_ref": "componentref:synthetic-custody",
                    "role": "release_head_signing",
                    "service_identity_ref": "principalref:synthetic-custody",
                    "operations": [
                        {"operation": "sign_head", "resource_ref": "keyref:synthetic-signing"}
                    ],
                },
                {
                    "service_ref": "componentref:synthetic-proxy",
                    "role": "default_deny_egress_proxy",
                    "service_identity_ref": "principalref:synthetic-proxy",
                    "operations": [],
                },
            ],
            "application_network_edges": [
                {
                    "worker_service_ref": "componentref:synthetic-worker",
                    "worker_ref": self.policy.worker_ref,
                    "proxy_service_ref": "componentref:synthetic-proxy",
                    "policy_id": policy["policy_id"],
                    "policy_sha256": policy["policy_sha256"],
                    "resolver_ref": "resolver:synthetic-host-dns",
                    "proxy_only": True,
                }
            ],
            "host_resolver_policy": {
                "resolver_ref": "resolver:synthetic-host-dns",
                "proxy_service_ref": "componentref:synthetic-proxy",
                "addresses": ["169.254.169.254"],
                "port": 53,
                "transports": ["udp", "tcp"],
                "worker_direct_dns": False,
            },
            "stop_binding": self.sources["deployment_profile"].stop_cleanup_policy.to_dict(),
        }

    def build(self, inputs: dict | None = None, **changes: object) -> GcpServiceBoundaryReview:
        arguments = {
            "resource_plan": self.resource_plan,
            "egress_policies": (self.policy,),
            **self.sources,
        }
        arguments.update(changes)
        return review_gcp_service_boundaries(self.inputs if inputs is None else inputs, **arguments)

    def verify(
        self, review: GcpServiceBoundaryReview, **changes: object
    ) -> GcpServiceBoundaryReview:
        arguments = {
            "resource_plan": self.resource_plan,
            "egress_policies": (self.policy,),
            **self.sources,
        }
        arguments.update(changes)
        return verify_gcp_service_boundary_review(review, **arguments)

    def rebind_policy(self, policy: EgressPolicy, inputs: dict | None = None) -> dict:
        raw = copy.deepcopy(self.inputs if inputs is None else inputs)
        source = policy.to_dict()
        raw["application_network_edges"][0].update(
            {"policy_id": source["policy_id"], "policy_sha256": source["policy_sha256"]}
        )
        return raw

    @staticmethod
    def rehash(raw: dict) -> dict:
        body = {
            key: value for key, value in raw.items() if key not in {"review_id", "review_sha256"}
        }
        raw["review_id"], raw["review_sha256"] = _address(body)
        return raw

    def test_separated_synthetic_roles_bind_exact_sources_and_remain_nonqualifying(self) -> None:
        review = self.build()
        raw = review.to_dict()
        self.assertEqual(raw["owner_input_blocker_codes"], [])
        self.assertEqual(raw["status"], "valid_for_offline_planning_only")
        self.assertEqual(raw["identity_assurance"], "operator_asserted_unsigned")
        self.assertEqual(set(raw["effects"].values()), {"none"})
        self.assertIn("authenticated_d014_selection_required", raw["permanent_blocker_codes"])
        self.assertIn(
            "effective_iam_and_federation_policy_required", raw["permanent_blocker_codes"]
        )
        self.assertIn("recovery_region_unselected", raw["resource_plan_blocker_codes"])
        self.assertIn("database_coordinates_missing", raw["resource_plan_blocker_codes"])
        self.assertEqual(self.verify(review), review)
        self.assertIsNot(self.verify(review), review)

    def test_deterministic_permutations_round_trip_and_input_preservation(self) -> None:
        before = copy.deepcopy(self.inputs)
        review = self.build()
        self.assertEqual(self.inputs, before)
        reversed_input = copy.deepcopy(self.inputs)
        reversed_input["service_assignments"].reverse()
        reversed_input["host_resolver_policy"]["transports"].reverse()
        self.assertEqual(self.build(reversed_input), review)
        self.assertEqual(GcpServiceBoundaryReview.from_json(json.dumps(review.to_dict())), review)
        self.assertEqual(GcpServiceBoundaryReview.from_dict(review.to_dict()), review)

    def test_worker_and_proxy_cannot_alias_custody_account(self) -> None:
        for index in (0, 2):
            raw = copy.deepcopy(self.inputs)
            raw["service_assignments"][index]["service_identity_ref"] = (
                "principalref:synthetic-custody"
            )
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(GcpServiceBoundaryError, "aliases a custody"),
            ):
                self.build(raw)

    def test_worker_cannot_alias_proxy_or_control_plane_identity(self) -> None:
        raw = copy.deepcopy(self.inputs)
        raw["service_assignments"][2]["service_identity_ref"] = "principalref:synthetic-worker"
        with self.assertRaisesRegex(GcpServiceBoundaryError, "aliases a trusted"):
            self.build(raw)
        raw = copy.deepcopy(self.inputs)
        raw["service_assignments"].append(
            {
                "service_ref": "componentref:synthetic-api",
                "role": "control_plane_api",
                "service_identity_ref": "principalref:synthetic-worker",
                "operations": [],
            }
        )
        with self.assertRaisesRegex(GcpServiceBoundaryError, "aliases a trusted"):
            self.build(raw)

    def test_release_signer_and_verifier_require_distinct_declared_accounts(self) -> None:
        raw = copy.deepcopy(self.inputs)
        verifier = {
            "service_ref": "componentref:synthetic-verifier",
            "role": "release_head_verification",
            "service_identity_ref": "principalref:synthetic-verifier",
            "operations": [
                {"operation": "verify_signed_head", "resource_ref": "keyref:synthetic-signing"}
            ],
        }
        raw["service_assignments"].append(verifier)
        self.build(raw)
        verifier["service_identity_ref"] = "principalref:synthetic-custody"
        with self.assertRaisesRegex(GcpServiceBoundaryError, "must be independent"):
            self.build(raw)

    def test_worker_custody_wildcard_admin_and_unknown_roles_are_rejected(self) -> None:
        for role, name in (
            ("restricted_execution_worker", "sign_head"),
            ("restricted_execution_worker", "compare_and_swap_head"),
            ("release_head_signing", "*"),
            ("release_head_signing", "roles/owner"),
            ("release_head_signing", "setIamPolicy"),
            ("release_head_signing", "destroy_key"),
        ):
            raw = copy.deepcopy(self.inputs)
            assignment = raw["service_assignments"][
                0 if role == "restricted_execution_worker" else 1
            ]
            assignment["operations"] = [
                {"operation": name, "resource_ref": "keyref:synthetic-signing"}
            ]
            with (
                self.subTest(role=role, name=name),
                self.assertRaisesRegex(GcpServiceBoundaryError, "allowlist"),
            ):
                self.build(raw)
        for role in ("owner", "*", "serviceAccountAdmin"):
            raw = copy.deepcopy(self.inputs)
            raw["service_assignments"][0]["role"] = role
            with (
                self.subTest(role=role),
                self.assertRaisesRegex(GcpServiceBoundaryError, "role is unsupported"),
            ):
                self.build(raw)

    def test_operations_bind_declared_resource_purpose_not_opaque_names_alone(self) -> None:
        for ref in (
            "keyref:unknown",
            "keyref:synthetic-encryption",
            "storeref:encrypted-local-evidence",
        ):
            raw = copy.deepcopy(self.inputs)
            raw["service_assignments"][1]["operations"][0]["resource_ref"] = ref
            with self.subTest(ref=ref), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)
        raw = copy.deepcopy(self.inputs)
        raw["service_assignments"][1].update(
            {
                "role": "conditional_ledger_head",
                "operations": [
                    {
                        "operation": "compare_and_swap_head",
                        "resource_ref": "storeref:encrypted-local-evidence",
                    }
                ],
            }
        )
        self.build(raw)
        raw["service_assignments"][1]["operations"][0]["resource_ref"] = "storeref:unknown"
        with self.assertRaisesRegex(GcpServiceBoundaryError, "resource is not explicitly declared"):
            self.build(raw)

    def test_undeclared_account_service_and_duplicate_scopes_are_rejected(self) -> None:
        mutations = (
            lambda raw: raw["service_assignments"][0].update(
                {"service_identity_ref": "principalref:unknown"}
            ),
            lambda raw: raw["application_network_edges"][0].update(
                {"worker_service_ref": "componentref:unknown"}
            ),
            lambda raw: raw["application_network_edges"][0].update(
                {"proxy_service_ref": "componentref:unknown"}
            ),
            lambda raw: raw["service_assignments"].append(
                copy.deepcopy(raw["service_assignments"][0])
            ),
            lambda raw: raw["application_network_edges"].append(
                copy.deepcopy(raw["application_network_edges"][0])
            ),
            lambda raw: raw["service_assignments"][1]["operations"].append(
                copy.deepcopy(raw["service_assignments"][1]["operations"][0])
            ),
        )
        for index, mutate in enumerate(mutations):
            raw = copy.deepcopy(self.inputs)
            mutate(raw)
            with self.subTest(index=index), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)

    def test_metadata_hostnames_fail_even_with_non_metadata_declared_addresses(self) -> None:
        for host in ("metadata.google.internal", "metadata.goog"):
            policy = replace(
                self.policy, endpoint_rules=(replace(self.policy.endpoint_rules[0], host=host),)
            )
            with (
                self.subTest(host=host),
                self.assertRaisesRegex(GcpServiceBoundaryError, "metadata hostname"),
            ):
                self.build(self.rebind_policy(policy), egress_policies=(policy,))

    def test_metadata_ipv4_ipv6_mapped_and_broad_cidrs_are_rejected(self) -> None:
        for cidr in (
            "169.254.169.254/32",
            "169.254.0.0/16",
            "0.0.0.0/0",
            "fd20:ce::254/128",
            "fd20:ce::/64",
            "::/0",
            "::ffff:a9fe:a9fe/128",
            "::ffff:169.254.169.254/128",
            "::ffff:0:0/96",
        ):
            policy = replace(
                self.policy,
                endpoint_rules=(
                    replace(self.policy.endpoint_rules[0], allowed_ip_networks=(cidr,)),
                ),
            )
            with (
                self.subTest(cidr=cidr),
                self.assertRaisesRegex(GcpServiceBoundaryError, "overlaps metadata"),
            ):
                self.build(self.rebind_policy(policy), egress_policies=(policy,))

    def test_metadata_case_trailing_dot_and_short_host_aliases_fail_before_review(self) -> None:
        for host in ("Metadata.Google.Internal", "metadata.google.internal.", "metadata"):
            policy = replace(self.policy)
            rule = replace(policy.endpoint_rules[0])
            object.__setattr__(rule, "host", host)
            object.__setattr__(policy, "endpoint_rules", (rule,))
            with (
                self.subTest(host=host),
                self.assertRaisesRegex(
                    GcpServiceBoundaryError, "Egress source revalidation failed"
                ),
            ):
                self.build(self.rebind_policy(policy), egress_policies=(policy,))

    def test_host_dns_metadata_address_is_separate_from_worker_application_egress(self) -> None:
        raw = copy.deepcopy(self.inputs)
        raw["host_resolver_policy"]["addresses"] = ["fd20:ce::254", "169.254.169.254"]
        review = self.build(raw)
        self.assertEqual(review.to_dict()["owner_input_blocker_codes"], [])
        for field, value in (
            ("port", 80),
            ("worker_direct_dns", True),
            ("transports", ["https"]),
            ("addresses", ["169.254.169.254", "169.254.169.254"]),
        ):
            malformed = copy.deepcopy(raw)
            malformed["host_resolver_policy"][field] = value
            with self.subTest(field=field), self.assertRaises(GcpServiceBoundaryError):
                self.build(malformed)

    def test_proxy_bypass_and_mismatched_resolver_bindings_are_rejected(self) -> None:
        for field, value in (
            ("proxy_only", False),
            ("proxy_only", 1),
            ("proxy_service_ref", "componentref:synthetic-worker"),
            ("resolver_ref", "resolver:other"),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["application_network_edges"][0][field] = value
            with self.subTest(field=field), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)
        raw = copy.deepcopy(self.inputs)
        raw["host_resolver_policy"]["proxy_service_ref"] = "componentref:synthetic-worker"
        with self.assertRaisesRegex(GcpServiceBoundaryError, "declared egress proxy"):
            self.build(raw)

    def test_missing_resolver_stop_and_partial_assignments_are_explicit_blockers(self) -> None:
        raw = copy.deepcopy(self.inputs)
        raw["host_resolver_policy"] = None
        raw["stop_binding"] = None
        raw["application_network_edges"][0]["resolver_ref"] = None
        review = self.build(raw)
        self.assertEqual(
            set(review.to_dict()["owner_input_blocker_codes"]),
            {
                "host_resolver_policy_required",
                "worker_resolver_binding_required",
                "exact_stop_cleanup_restoration_binding_required",
            },
        )
        self.verify(review)
        raw = {
            "service_assignments": [],
            "application_network_edges": [],
            "host_resolver_policy": None,
            "stop_binding": None,
        }
        review = self.build(raw, egress_policies=())
        self.assertTrue(
            {
                "worker_service_assignment_required",
                "custody_service_assignment_required",
                "egress_proxy_service_assignment_required",
            }.issubset(review.to_dict()["owner_input_blocker_codes"])
        )

    def test_unbound_worker_and_empty_custody_operations_cannot_look_complete(self) -> None:
        raw = copy.deepcopy(self.inputs)
        raw["application_network_edges"] = []
        raw["service_assignments"][1]["operations"] = []
        review = self.build(raw, egress_policies=())
        self.assertIn(
            "worker_application_network_edge_required",
            review.to_dict()["owner_input_blocker_codes"],
        )
        self.assertIn(
            "custody_operation_scope_required", review.to_dict()["owner_input_blocker_codes"]
        )

    def test_stop_contract_and_native_flags_must_match_the_profile(self) -> None:
        for field, value in (
            ("stop_contract_ref", "stopref:other"),
            ("cleanup_contract_ref", "cleanupref:other"),
            ("restoration_contract_ref", "restorationref:other"),
            ("maximum_stop_ack_seconds", 31),
            ("maximum_stop_ack_seconds", True),
            ("stop_supported", 1),
            ("cleanup_required", False),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["stop_binding"][field] = value
            with self.subTest(field=field), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)

    def test_policy_id_hash_worker_tenant_and_unused_sources_fail_closed(self) -> None:
        for field, value in (
            ("policy_sha256", "sha256:" + "0" * 64),
            ("worker_ref", "workerref:other"),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["application_network_edges"][0][field] = value
            with self.subTest(field=field), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)
        for field, value in (("tenant_ref", "tenantref:other"), ("worker_ref", "workerref:other")):
            policy = replace(self.policy, **{field: value})
            with self.subTest(field=field), self.assertRaises(GcpServiceBoundaryError):
                self.build(self.rebind_policy(policy), egress_policies=(policy,))
        with self.assertRaisesRegex(GcpServiceBoundaryError, "must be unique"):
            self.build(egress_policies=(self.policy, self.policy))
        raw = copy.deepcopy(self.inputs)
        raw["application_network_edges"] = []
        with self.assertRaisesRegex(GcpServiceBoundaryError, "Every supplied policy"):
            self.build(raw)

    def test_disconnected_profile_cannot_acquire_application_network_edges(self) -> None:
        profile = build_standard_profile("disconnected_operation")
        sources = {**self.sources, "deployment_profile": profile}
        plan = build_gcp_resource_binding_plan(self.coordinates, **sources)
        policy = replace(self.policy, worker_ref=profile.worker_ref)
        raw = self.rebind_policy(policy)
        raw["application_network_edges"][0]["worker_ref"] = profile.worker_ref
        raw["stop_binding"] = profile.stop_cleanup_policy.to_dict()
        with self.assertRaisesRegex(GcpServiceBoundaryError, "Disconnected profiles"):
            self.build(
                raw, resource_plan=plan, deployment_profile=profile, egress_policies=(policy,)
            )

    def test_strict_native_inputs_reject_subclasses_floats_extra_and_missing_fields(self) -> None:
        class Text(str):
            pass

        class Object(dict):
            pass

        for mutate in (
            lambda raw: raw.update({"credentials": "not-supported"}),
            lambda raw: raw.pop("stop_binding"),
            lambda raw: raw["service_assignments"][0].update(
                {"role": Text("restricted_execution_worker")}
            ),
            lambda raw: raw["service_assignments"][0].update({"operations": ()}),
            lambda raw: raw["host_resolver_policy"].update({"port": 53.0}),
            lambda raw: raw["host_resolver_policy"].update({"worker_direct_dns": 0}),
            lambda raw: raw["application_network_edges"][0].update({"proxy_only": 1.0}),
            lambda raw: raw["service_assignments"][1].update(
                {"operations": [Object(raw["service_assignments"][1]["operations"][0])]}
            ),
        ):
            raw = copy.deepcopy(self.inputs)
            mutate(raw)
            with self.subTest(raw=repr(raw)[:120]), self.assertRaises(GcpServiceBoundaryError):
                self.build(raw)
        with self.assertRaises(GcpServiceBoundaryError):
            self.build(Object(self.inputs))

    def test_source_mutation_recreation_and_rehashed_binding_substitution_are_rejected(
        self,
    ) -> None:
        review = self.build()
        coordinates = copy.deepcopy(self.coordinates)
        coordinates["service_accounts"][0]["unique_id"] = "999999999999999999999"
        recreated = build_gcp_resource_binding_plan(coordinates, **self.sources)
        with self.assertRaisesRegex(GcpServiceBoundaryError, "exact supplied source replay"):
            self.verify(review, resource_plan=recreated)
        raw = review.to_dict()
        raw["source_bindings"]["resource_plan"] = recreated.to_dict()["source_bindings"][
            "deployment_profile"
        ]
        with self.assertRaises(GcpServiceBoundaryError):
            GcpServiceBoundaryReview.from_dict(self.rehash(raw))
        raw = review.to_dict()
        raw["source_bindings"]["resource_plan"] = {
            "id": recreated.to_dict()["plan_id"],
            "sha256": recreated.to_dict()["plan_sha256"],
        }
        rebound = GcpServiceBoundaryReview.from_dict(self.rehash(raw))
        with self.assertRaisesRegex(GcpServiceBoundaryError, "exact supplied source replay"):
            self.verify(rebound)
        object.__setattr__(
            self.resource_plan, "document_json", self.resource_plan.document_json + " "
        )
        with self.assertRaisesRegex(GcpServiceBoundaryError, "source verification failed"):
            self.verify(review)

    def test_late_profile_region_and_policy_mutation_is_not_hidden_by_old_binding(self) -> None:
        for source, field, value in (
            ("deployment_profile", "profile_sha256", "sha256:" + "0" * 64),
            ("regional_binding", "home_region", "us-west1"),
            ("policy", "scope_ref", "scoperef:other"),
            ("policy", "maximum_resolution_age_seconds", True),
        ):
            self.setUp()
            review = self.build()
            item = self.policy if source == "policy" else self.sources[source]
            object.__setattr__(item, field, value)
            with (
                self.subTest(source=source, field=field),
                self.assertRaises(GcpServiceBoundaryError),
            ):
                self.verify(review)

    def test_rehashed_type_metadata_effect_and_blocker_escalation_is_rejected(self) -> None:
        review = self.build()
        for mutate in (
            lambda raw: raw.update({"schema_version": True}),
            lambda raw: raw.update({"status": "ready"}),
            lambda raw: raw.update({"identity_assurance": "authenticated"}),
            lambda raw: raw.update({"validation_scope": "effective_iam_verified"}),
            lambda raw: raw["effects"].update({"authorization": "allowed"}),
            lambda raw: raw.update({"permanent_blocker_codes": []}),
            lambda raw: raw.update(
                {"owner_input_blocker_codes": ["host_resolver_policy_required"]}
            ),
            lambda raw: raw.update({"resource_plan_blocker_codes": ["invented"]}),
        ):
            raw = review.to_dict()
            mutate(raw)
            with self.subTest(raw=repr(raw)[:120]), self.assertRaises(GcpServiceBoundaryError):
                GcpServiceBoundaryReview.from_dict(self.rehash(raw))
        raw = review.to_dict()
        raw["host_resolver_policy"]["port"] = 53.0
        with self.assertRaises(GcpServiceBoundaryError):
            GcpServiceBoundaryReview.from_dict(raw)
        raw = review.to_dict()
        raw["resource_plan_blocker_codes"] = []
        rebound = GcpServiceBoundaryReview.from_dict(self.rehash(raw))
        with self.assertRaisesRegex(GcpServiceBoundaryError, "source replay"):
            self.verify(rebound)

    def test_detached_exports_immutable_record_and_wrapper_mutation(self) -> None:
        review = self.build()
        before = review.document_json
        exported = review.to_dict()
        exported["effects"]["network"] = "allowed"
        exported["service_assignments"][0]["operations"].clear()
        self.inputs["host_resolver_policy"]["addresses"].append("192.0.2.1")
        self.assertEqual(review.document_json, before)
        self.assertEqual(set(review.to_dict()["effects"].values()), {"none"})
        self.verify(review)
        with self.assertRaises(FrozenInstanceError):
            review.document_json = before + " "
        object.__setattr__(review, "document_json", before + " ")
        with self.assertRaises(GcpServiceBoundaryError):
            review.to_dict()

    def test_exact_collection_bound_and_overlimit_inputs(self) -> None:
        raw = copy.deepcopy(self.inputs)
        raw["service_assignments"].extend(
            {
                "service_ref": f"componentref:synthetic-ingress-{index}",
                "role": "tls_ingress_proxy",
                "service_identity_ref": "principalref:synthetic-verifier",
                "operations": [],
            }
            for index in range(MAX_ITEMS - len(raw["service_assignments"]))
        )
        self.assertEqual(len(self.build(raw).to_dict()["service_assignments"]), MAX_ITEMS)
        raw["service_assignments"].append(copy.deepcopy(raw["service_assignments"][-1]))
        with self.assertRaises(GcpServiceBoundaryError):
            self.build(raw)
        with self.assertRaises(GcpServiceBoundaryError):
            self.build(egress_policies=(self.policy,) * (MAX_ITEMS + 1))
        oversized = copy.deepcopy(self.inputs)
        oversized["service_assignments"][0]["role"] = "x" * MAX_REVIEW_BYTES
        with self.assertRaisesRegex(GcpServiceBoundaryError, "byte bound"):
            self.build(oversized)
        oversized["service_assignments"][0]["role"] += "x"
        with self.assertRaisesRegex(GcpServiceBoundaryError, "byte bound"):
            self.build(oversized)
        with self.assertRaisesRegex(GcpServiceBoundaryError, "field bound"):
            self.build({f"extra{index}": None for index in range(MAX_ITEMS + 1)})

    def test_aggregate_native_dag_budget_rejects_before_json_encoding(self) -> None:
        shared = ["x"] * 128
        for _ in range(7):
            shared = [shared] * 128
        raw = copy.deepcopy(self.inputs)
        raw["service_assignments"] = shared
        with patch("sunderkey.gcp_service_boundaries.json.dumps") as encoder:
            with self.assertRaisesRegex(GcpServiceBoundaryError, "aggregate byte"):
                self.build(raw)
            encoder.assert_not_called()

    def test_native_cycles_huge_ints_and_strings_reject_before_encoding(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        oversized_int = 1 << (MAX_REVIEW_BYTES * 4)
        for value in (cyclic, oversized_int, -oversized_int, "x" * MAX_REVIEW_BYTES):
            with self.subTest(family=type(value).__name__):
                with patch("sunderkey.gcp_service_boundaries.json.dumps") as encoder:
                    with self.assertRaises(GcpServiceBoundaryError):
                        boundary._canonical(value)
                    encoder.assert_not_called()

    def test_aggregate_size_counts_escaping_punctuation_and_preserves_valid_bytes(self) -> None:
        samples = (
            {"quoted\"key": [None, True, False, -123, "\\\""]},
            [[], {}, {"": ""}],
            [["shared"], ["shared"]],
        )
        for value in samples:
            expected = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            with self.subTest(value=value):
                self.assertEqual(boundary._canonical(value), expected)
                with patch("sunderkey.gcp_service_boundaries.MAX_REVIEW_BYTES", len(expected)):
                    self.assertEqual(boundary._canonical(value), expected)
                with patch("sunderkey.gcp_service_boundaries.MAX_REVIEW_BYTES", len(expected) - 1):
                    with patch("sunderkey.gcp_service_boundaries.json.dumps") as encoder:
                        with self.assertRaisesRegex(GcpServiceBoundaryError, "aggregate byte"):
                            boundary._canonical(value)
                        encoder.assert_not_called()
        with patch("sunderkey.gcp_service_boundaries.MAX_REVIEW_BYTES", 64):
            self.assertEqual(len(boundary._canonical("\\" * 31)), 64)
            with patch("sunderkey.gcp_service_boundaries.json.dumps") as encoder:
                with self.assertRaisesRegex(GcpServiceBoundaryError, "aggregate byte"):
                    boundary._canonical("\\" * 32)
                encoder.assert_not_called()
        shared = ["shared"]
        self.assertEqual(boundary._canonical([shared, shared]), '[["shared"],["shared"]]')


    def test_duplicate_nonfinite_unicode_and_noncanonical_json_are_rejected(self) -> None:
        for text in (
            '{"schema_version":1,"schema_version":1}',
            '{"value":NaN}',
            '{"value":1.0}',
            '{"value":"\\ud800"}',
            "{" + " " * MAX_REVIEW_BYTES + "}",
        ):
            with self.subTest(text=text[:50]), self.assertRaises(GcpServiceBoundaryError):
                GcpServiceBoundaryReview.from_json(text)
        review = self.build()
        with self.assertRaises(GcpServiceBoundaryError):
            GcpServiceBoundaryReview(json.dumps(review.to_dict(), indent=2))

    def test_source_has_no_transport_provisioning_file_or_signing_clients(self) -> None:
        source = (ROOT / "src/sunderkey/gcp_service_boundaries.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            item.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for item in node.names
        }
        self.assertEqual(imports, {"hashlib", "ipaddress", "json", "re"})
        calls = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
        }
        self.assertFalse(
            calls.intersection(
                {"open", "connect", "request", "urlopen", "sign", "generate_private_key", "execute"}
            )
        )
        for path in (
            ROOT / "src/sunderkey/gcp_service_boundaries.py",
            Path(__file__),
            ROOT / "docs/gcp-service-boundaries-offline.md",
        ):
            self.assertTrue(path.read_text(encoding="utf-8").isascii())


if __name__ == "__main__":
    unittest.main()
