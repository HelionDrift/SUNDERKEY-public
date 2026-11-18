"""Inert same-VPC packet predicates, independent oracles and exact source replay."""

from __future__ import annotations

import itertools
import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from sunderkey import aws_vpc_flow_analysis as module
from sunderkey.aws_vpc_flow_analysis import (
    AwsVpcFlowAnalysis,
    AwsVpcFlowAnalysisError,
    analyze_supplied_aws_vpc_flow,
    analyze_supplied_aws_vpc_flow_bytes,
    verify_supplied_aws_vpc_flow_analysis,
)


def sg_rule(rule_id="rule", cidr="10.0.0.0/16", protocol="TCP", first=443, last=443):
    return {
        "rule_id": rule_id,
        "protocol": protocol,
        "cidr": cidr,
        "from_port": first,
        "to_port": last,
    }


def acl_rule(number=100, action="allow", cidr="10.0.0.0/16", protocol="ALL", first=None, last=None):
    return {
        "rule_number": number,
        "action": action,
        "protocol": protocol,
        "cidr": cidr,
        "from_port": first,
        "to_port": last,
    }


def component_fixture() -> dict:
    """Fresh public synthetic declarations with no callbacks, targets or credentials."""
    return {
        "schema_version": 1,
        "vpc": {"vpc_id": "vpc.synthetic", "cidr": "10.0.0.0/16"},
        "subnets": [
            {"subnet_id": "front", "cidr": "10.0.1.0/24", "network_acl_id": "front-acl"},
            {"subnet_id": "back", "cidr": "10.0.2.0/24", "network_acl_id": "back-acl"},
        ],
        "endpoints": [
            {
                "endpoint_id": "client",
                "eni_id": "eni.client",
                "subnet_id": "front",
                "address": "10.0.1.10",
                "security_group_ids": ["client-sg"],
                "security_groups_complete": True,
            },
            {
                "endpoint_id": "server",
                "eni_id": "eni.server",
                "subnet_id": "back",
                "address": "10.0.2.20",
                "security_group_ids": ["server-sg"],
                "security_groups_complete": True,
            },
        ],
        "security_groups": [
            {
                "security_group_id": "client-sg",
                "ingress_complete": True,
                "egress_complete": True,
                "ingress": [],
                "egress": [sg_rule("client-out", "10.0.2.0/24")],
            },
            {
                "security_group_id": "server-sg",
                "ingress_complete": True,
                "egress_complete": True,
                "ingress": [sg_rule("server-in", "10.0.1.0/24")],
                "egress": [],
            },
        ],
        "network_acls": [
            {
                "network_acl_id": "front-acl",
                "ingress_complete": True,
                "egress_complete": True,
                "ingress": [acl_rule(cidr="10.0.2.0/24", protocol="TCP", first=50000, last=50000)],
                "egress": [acl_rule(cidr="10.0.2.0/24", protocol="TCP", first=443, last=443)],
            },
            {
                "network_acl_id": "back-acl",
                "ingress_complete": True,
                "egress_complete": True,
                "ingress": [acl_rule(cidr="10.0.1.0/24", protocol="TCP", first=443, last=443)],
                "egress": [acl_rule(cidr="10.0.1.0/24", protocol="TCP", first=50000, last=50000)],
            },
        ],
        "flows": [
            {
                "flow_id": "https",
                "source_endpoint_id": "client",
                "destination_endpoint_id": "server",
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 443,
                "traffic_class": "ordinary_eni_to_eni",
                "return_mode": "assumed_tracked_response",
            }
        ],
    }


def readdress(document: dict) -> dict:
    body = deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = module._hash(module.DOMAIN, body)
    return {"analysis_id": "VFA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


class AwsVpcFlowAnalysisTests(unittest.TestCase):
    def document(self, model=None):
        return analyze_supplied_aws_vpc_flow(
            component_fixture() if model is None else model
        ).to_dict()

    def row(self, model=None):
        return self.document(model)["flow_results"][0]

    def invalid(self, model):
        with self.assertRaises(AwsVpcFlowAnalysisError):
            analyze_supplied_aws_vpc_flow(model)

    def permissive_acls(self, model):
        for acl in model["network_acls"]:
            acl["ingress"] = [acl_rule()]
            acl["egress"] = [acl_rule()]
        return model

    def test_literal_fixture_and_all_public_roundtrips(self):
        model = component_fixture()
        record = analyze_supplied_aws_vpc_flow(model)
        doc = record.to_dict()
        self.assertEqual(doc["analysis_id"], "VFA-0B99E2C511BA522BAD6565B25D6FE4F8")
        self.assertEqual(
            doc["analysis_sha256"],
            "sha256:0b99e2c511ba522bad6565b25d6fe4f8334d9fc111c5b6baf3af6b39652c9946",
        )
        self.assertEqual(
            doc["source_model_sha256"],
            "sha256:a1edd13e6c795cce9661bd009385998d1b381be530c47f9e4582f1e7580e43fa",
        )
        self.assertEqual(AwsVpcFlowAnalysis.from_dict(doc).to_json(), record.to_json())
        self.assertEqual(AwsVpcFlowAnalysis.from_json(record.to_json()).to_json(), record.to_json())
        self.assertEqual(
            analyze_supplied_aws_vpc_flow_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_json(),
            record.to_json(),
        )
        self.assertEqual(
            verify_supplied_aws_vpc_flow_analysis(record, model=model).to_json(), record.to_json()
        )
        self.assertEqual(doc["component_id"], "aws_supplied_vpc_flow_predicates")
        self.assertEqual(doc["wave_id"], "IW2-006")
        self.assertEqual(
            doc["flow_results"][0]["forward"]["outcome"], "allowed_in_supplied_policy_model"
        )
        self.assertEqual(
            doc["flow_results"][0]["reverse"]["outcome"],
            "conditionally_allowed_in_supplied_policy_model",
        )

    def test_all_effects_and_proof_flags_remain_none_or_false(self):
        doc = self.document()
        for field in module._FLAGS:
            self.assertIs(doc[field], False)
        self.assertEqual(set(doc["effects"].values()), {"none"})
        self.assertEqual(doc["input_provenance"], "operator_supplied_unverified")

    def test_forward_sg_union_and_empty_complete_denial(self):
        for source_allow, destination_allow in itertools.product((False, True), repeat=2):
            model = self.permissive_acls(component_fixture())
            if not source_allow:
                model["security_groups"][0]["egress"] = []
            if not destination_allow:
                model["security_groups"][1]["ingress"] = []
            with self.subTest(source=source_allow, destination=destination_allow):
                row = self.row(model)
                self.assertEqual(
                    row["forward"]["outcome"],
                    "allowed_in_supplied_policy_model"
                    if source_allow and destination_allow
                    else "blocked_in_supplied_policy_model",
                )
                if not (source_allow and destination_allow):
                    self.assertEqual(row["reverse"]["outcome"], "unassessed")

    def test_additional_group_allow_unions_without_default_invention(self):
        model = self.permissive_acls(component_fixture())
        model["security_groups"][0]["egress"] = []
        model["security_groups"].append(
            {
                "security_group_id": "allow-more",
                "ingress_complete": True,
                "egress_complete": True,
                "ingress": [],
                "egress": [sg_rule("extra")],
            }
        )
        model["endpoints"][0]["security_group_ids"].append("allow-more")
        self.assertEqual(self.row(model)["forward"]["outcome"], "allowed_in_supplied_policy_model")
        model["endpoints"][0]["security_group_ids"].remove("allow-more")
        self.assertEqual(self.row(model)["forward"]["outcome"], "blocked_in_supplied_policy_model")

    def test_known_sg_allow_survives_partial_additive_sources(self):
        for membership, rules in itertools.product((False, True), repeat=2):
            model = component_fixture()
            model["endpoints"][0]["security_groups_complete"] = membership
            model["security_groups"][0]["egress_complete"] = rules
            self.assertIs(
                self.row(model)["forward"]["gates"]["source_security_group_egress"]["allowed"], True
            )

    def test_sg_absence_is_unknown_unless_membership_and_rules_complete(self):
        for membership, rules in itertools.product((False, True), repeat=2):
            model = component_fixture()
            model["security_groups"][0]["egress"] = []
            model["endpoints"][0]["security_groups_complete"] = membership
            model["security_groups"][0]["egress_complete"] = rules
            gate = self.row(model)["forward"]["gates"]["source_security_group_egress"]
            self.assertIs(gate["allowed"], False if membership and rules else None)

    def test_independent_small_ipv4_cidr_and_range_oracle(self):
        for address_suffix, prefix_bits, first, last, destination in itertools.product(
            (10, 130), (24, 25), (400, 443), (443, 500), (399, 443, 501)
        ):
            model = self.permissive_acls(component_fixture())
            model["endpoints"][0]["address"] = f"10.0.1.{address_suffix}"
            model["flows"][0]["destination_port"] = destination
            model["security_groups"][0]["egress"] = [
                sg_rule("out", protocol="ALL", first=None, last=None)
            ]
            model["security_groups"][1]["ingress"] = [
                sg_rule("in", f"10.0.1.0/{prefix_bits}", first=first, last=last)
            ]
            member = address_suffix < (256 if prefix_bits == 24 else 128)
            expected = member and first <= destination <= last
            with self.subTest(
                address=address_suffix, prefix=prefix_bits, ports=(first, last, destination)
            ):
                self.assertIs(
                    self.row(model)["forward"]["gates"]["destination_security_group_ingress"][
                        "allowed"
                    ],
                    expected,
                )

    def test_acl_sorted_first_match_independent_rule_oracle(self):
        for actions in itertools.product(("allow", "deny"), repeat=3):
            for order in itertools.permutations((30, 10, 20)):
                model = self.permissive_acls(component_fixture())
                by_number = dict(zip((10, 20, 30), actions, strict=True))
                model["network_acls"][1]["ingress"] = [
                    acl_rule(number, by_number[number]) for number in order
                ]
                gate = self.row(model)["forward"]["gates"]["destination_network_acl_ingress"]
                self.assertIs(gate["allowed"], by_number[10] == "allow")
                self.assertEqual(gate["witness"]["rule_number"], 10)
                self.assertEqual(gate["witness"]["source_rule_index"], order.index(10))

    def test_acl_earlier_nonmatching_rules_do_not_shadow_match(self):
        model = self.permissive_acls(component_fixture())
        model["network_acls"][1]["ingress"] = [
            acl_rule(5, "deny", cidr="192.0.2.0/24"),
            acl_rule(10, "allow"),
            acl_rule(20, "deny"),
        ]
        gate = self.row(model)["forward"]["gates"]["destination_network_acl_ingress"]
        self.assertIs(gate["allowed"], True)
        self.assertEqual(gate["witness"]["rule_number"], 10)

    def test_incomplete_acl_never_uses_supplied_allow_or_deny_match(self):
        for action in ("allow", "deny"):
            model = self.permissive_acls(component_fixture())
            model["network_acls"][1]["ingress"] = [acl_rule(action=action)]
            model["network_acls"][1]["ingress_complete"] = False
            gate = self.row(model)["forward"]["gates"]["destination_network_acl_ingress"]
            self.assertIsNone(gate["allowed"])
            self.assertIsNone(gate["witness"])
            self.assertEqual(gate["basis"], "incomplete_network_acl_rules")

    def test_complete_empty_acl_derives_implicit_deny_without_rule_fabrication(self):
        model = component_fixture()
        model["network_acls"][1]["ingress"] = []
        gate = self.row(model)["forward"]["gates"]["destination_network_acl_ingress"]
        self.assertIs(gate["allowed"], False)
        self.assertIsNone(gate["witness"])
        self.assertEqual(gate["basis"], "complete_network_acl_default_deny")

    def test_forward_denial_never_fabricates_tracked_reverse(self):
        for field in (
            "source_security_group_egress",
            "destination_security_group_ingress",
            "source_network_acl_egress",
            "destination_network_acl_ingress",
        ):
            model = component_fixture()
            if field == "source_security_group_egress":
                model["security_groups"][0]["egress"] = []
            elif field == "destination_security_group_ingress":
                model["security_groups"][1]["ingress"] = []
            elif field == "source_network_acl_egress":
                model["network_acls"][0]["egress"] = []
            else:
                model["network_acls"][1]["ingress"] = []
            with self.subTest(gate=field):
                row = self.row(model)
                self.assertEqual(row["reverse"]["outcome"], "unassessed")
                self.assertTrue(
                    all(gate["allowed"] is None for gate in row["reverse"]["gates"].values())
                )
                self.assertTrue(
                    all(
                        gate["basis"] == "forward_premise_not_satisfied"
                        for gate in row["reverse"]["gates"].values()
                    )
                )

    def test_forward_unknown_never_fabricates_tracked_reverse(self):
        model = component_fixture()
        model["network_acls"][0]["egress_complete"] = False
        row = self.row(model)
        self.assertEqual(row["forward"]["outcome"], "unknown_in_supplied_policy_model")
        self.assertEqual(row["reverse"]["outcome"], "unassessed")

    def test_reverse_acl_requires_explicit_original_source_port(self):
        for source_port in (49999, 50000, 50001):
            model = component_fixture()
            model["flows"][0]["source_port"] = source_port
            row = self.row(model)
            self.assertEqual(row["reverse"]["packet"]["destination_port"], source_port)
            self.assertEqual(
                row["reverse"]["outcome"],
                "conditionally_allowed_in_supplied_policy_model"
                if source_port == 50000
                else "blocked_in_supplied_policy_model",
            )

    def test_stateful_return_does_not_invent_reverse_sg_rule(self):
        row = self.row()
        for field in ("source_security_group_egress", "destination_security_group_ingress"):
            self.assertEqual(
                row["reverse"]["gates"][field]["basis"], "conditional_stateful_response"
            )
            self.assertIsNone(row["reverse"]["gates"][field]["witness"])
        self.assertTrue(row["reverse"]["conditional"])

    def test_independent_reverse_can_allow_despite_forward_denial(self):
        model = self.permissive_acls(component_fixture())
        model["flows"][0]["return_mode"] = "independent_reverse_packet"
        model["security_groups"][0]["egress"] = []
        model["security_groups"][0]["ingress"] = [
            sg_rule("independent-in", first=50000, last=50000)
        ]
        model["security_groups"][1]["egress"] = [
            sg_rule("independent-out", first=50000, last=50000)
        ]
        row = self.row(model)
        self.assertEqual(row["forward"]["outcome"], "blocked_in_supplied_policy_model")
        self.assertEqual(row["reverse"]["outcome"], "allowed_in_supplied_policy_model")
        self.assertFalse(row["reverse"]["conditional"])

    def test_unknown_return_mode_never_guesses_response_allowance(self):
        model = component_fixture()
        model["flows"][0]["return_mode"] = "unknown"
        row = self.row(model)
        self.assertEqual(row["forward"]["outcome"], "allowed_in_supplied_policy_model")
        self.assertEqual(row["reverse"]["outcome"], "unassessed")

    def test_same_subnet_acl_exemption_preserves_security_group_denial(self):
        model = component_fixture()
        model["endpoints"][1]["subnet_id"] = "front"
        model["endpoints"][1]["address"] = "10.0.1.20"
        for acl in model["network_acls"]:
            acl["ingress"] = []
            acl["egress"] = []
        model["security_groups"][0]["egress"] = [sg_rule("out")]
        row = self.row(model)
        self.assertEqual(row["forward"]["outcome"], "allowed_in_supplied_policy_model")
        for field in ("source_network_acl_egress", "destination_network_acl_ingress"):
            self.assertIs(row["forward"]["gates"][field]["applies"], False)
            self.assertEqual(row["forward"]["gates"][field]["basis"], "not_applied_same_subnet")
        model["security_groups"][0]["egress"] = []
        self.assertEqual(self.row(model)["forward"]["outcome"], "blocked_in_supplied_policy_model")

    def test_same_acl_on_different_subnets_does_not_bypass_filter(self):
        model = component_fixture()
        model["subnets"][1]["network_acl_id"] = "front-acl"
        model["network_acls"][0]["ingress"] = []
        row = self.row(model)
        self.assertTrue(row["forward"]["gates"]["destination_network_acl_ingress"]["applies"])
        self.assertEqual(row["forward"]["outcome"], "blocked_in_supplied_policy_model")

    def test_provider_exempt_unknown_and_reserved_endpoints_are_unassessed(self):
        for traffic in ("provider_exempt", "unknown"):
            model = component_fixture()
            model["flows"][0]["traffic_class"] = traffic
            model["security_groups"][0]["egress"] = []
            row = self.row(model)
            self.assertEqual(row["forward"]["outcome"], "unassessed")
            self.assertEqual(row["reverse"]["outcome"], "unassessed")
        for address in ("10.0.1.0", "10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.255"):
            model = component_fixture()
            model["endpoints"][0]["address"] = address
            self.assertEqual(self.row(model)["forward"]["outcome"], "unassessed")

    def test_same_endpoint_stays_unassessed(self):
        model = component_fixture()
        model["flows"][0]["destination_endpoint_id"] = "client"
        self.assertEqual(self.row(model)["forward"]["outcome"], "unassessed")

    def test_tcp_udp_all_ranges_and_zero_bound_are_exact(self):
        for packet_protocol, rule_protocol, port in itertools.product(
            ("TCP", "UDP"), ("TCP", "UDP", "ALL"), (0, 1, 65535)
        ):
            model = self.permissive_acls(component_fixture())
            model["flows"][0]["protocol"] = packet_protocol
            model["flows"][0]["destination_port"] = port
            for index, direction in ((0, "egress"), (1, "ingress")):
                model["security_groups"][index][direction] = [
                    sg_rule(
                        "permit",
                        protocol=rule_protocol,
                        first=None if rule_protocol == "ALL" else 0,
                        last=None if rule_protocol == "ALL" else 65535,
                    )
                ]
            expected = rule_protocol == "ALL" or rule_protocol == packet_protocol
            self.assertEqual(
                self.row(model)["forward"]["outcome"],
                "allowed_in_supplied_policy_model"
                if expected
                else "blocked_in_supplied_policy_model",
            )

    def test_ipv6_canonical_same_family_predicates(self):
        model = self.permissive_acls(component_fixture())
        model["vpc"]["cidr"] = "2001:db8::/48"
        for index, subnet in enumerate(model["subnets"], 1):
            subnet["cidr"] = f"2001:db8:0:{index}::/64"
        model["endpoints"][0]["address"] = "2001:db8:0:1::10"
        model["endpoints"][1]["address"] = "2001:db8:0:2::20"
        for policy in model["security_groups"] + model["network_acls"]:
            for direction in ("ingress", "egress"):
                for rule in policy[direction]:
                    rule["cidr"] = "2001:db8::/48"
        self.assertEqual(self.row(model)["forward"]["outcome"], "allowed_in_supplied_policy_model")
        model["endpoints"][0]["address"] = "2001:db8:0:1::2"
        self.assertEqual(self.row(model)["forward"]["outcome"], "unassessed")

    def test_canonical_cidr_and_address_no_silent_normalization(self):
        for value in ("10.0.1.1/24", "10.0.1.0/024", "010.0.1.0/24", "::ffff:10.0.1.0/120"):
            model = component_fixture()
            model["subnets"][0]["cidr"] = value
            self.invalid(model)
        for value in ("010.0.1.10", "10.0.1.10%scope", "2001:db8::10"):
            model = component_fixture()
            model["endpoints"][0]["address"] = value
            self.invalid(model)

    def test_missing_joins_duplicates_and_overlapping_subnets_reject(self):
        variants = []
        model = component_fixture()
        model["endpoints"][0]["security_group_ids"] = ["missing"]
        variants.append(model)
        model = component_fixture()
        model["subnets"][0]["network_acl_id"] = "missing"
        variants.append(model)
        model = component_fixture()
        model["endpoints"][0]["subnet_id"] = "missing"
        variants.append(model)
        model = component_fixture()
        model["flows"][0]["source_endpoint_id"] = "missing"
        variants.append(model)
        model = component_fixture()
        model["subnets"][1]["cidr"] = model["subnets"][0]["cidr"]
        variants.append(model)
        model = component_fixture()
        model["endpoints"][1]["eni_id"] = model["endpoints"][0]["eni_id"]
        variants.append(model)
        for collection in ("subnets", "endpoints", "security_groups", "network_acls", "flows"):
            model = component_fixture()
            model[collection].append(deepcopy(model[collection][0]))
            variants.append(model)
        for model in variants:
            self.invalid(model)

    def test_missing_complete_flags_and_unknown_fields_do_not_gain_defaults(self):
        for target in ("membership", "sg", "acl", "root"):
            model = component_fixture()
            if target == "membership":
                del model["endpoints"][0]["security_groups_complete"]
            elif target == "sg":
                del model["security_groups"][0]["egress_complete"]
            elif target == "acl":
                del model["network_acls"][0]["ingress_complete"]
            else:
                model["default_route"] = True
            self.invalid(model)

    def test_bad_rule_ports_numbers_action_and_unsupported_reference_reject(self):
        for changes in (
            {"from_port": 500, "to_port": 400},
            {"from_port": -1},
            {"to_port": 65536},
            {"from_port": True},
            {"protocol": "ALL"},
            {"cidr": "sg-other"},
            {"protocol": "ICMP"},
            {"security_group_ref": "other"},
        ):
            model = component_fixture()
            model["security_groups"][0]["egress"][0].update(changes)
            self.invalid(model)
        for changes in (
            {"rule_number": 0},
            {"rule_number": 32767},
            {"rule_number": True},
            {"action": "permit"},
        ):
            model = component_fixture()
            model["network_acls"][0]["egress"][0].update(changes)
            self.invalid(model)
        model = component_fixture()
        model["network_acls"][0]["egress"].append(deepcopy(model["network_acls"][0]["egress"][0]))
        self.invalid(model)

    def test_unhashable_native_enum_substitutions_raise_only_domain_error(self):
        for field in ("protocol", "traffic_class", "return_mode"):
            for value in ([], {}, 1, True):
                model = component_fixture()
                model["flows"][0][field] = value
                self.invalid(model)

    def test_native_input_aliases_and_subclasses_fail_before_hash(self):
        class Alias(dict):
            pass

        variants = [Alias(component_fixture())]
        for field, value in (("schema_version", True), ("schema_version", 1.0)):
            model = component_fixture()
            model[field] = value
            variants.append(model)
        for value in (1, 1.0, None):
            model = component_fixture()
            model["endpoints"][0]["security_groups_complete"] = value
            variants.append(model)
        for value in (True, 443.0, "443"):
            model = component_fixture()
            model["flows"][0]["destination_port"] = value
            variants.append(model)
        for model in variants:
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                self.invalid(model)

    def test_false_results_and_effects_cannot_be_cohashed(self):
        original = self.document()
        variants = []
        doc = deepcopy(original)
        doc["conntrack_verified"] = True
        variants.append(doc)
        doc = deepcopy(original)
        doc["effects"]["network"] = "allowed"
        variants.append(doc)
        doc = deepcopy(original)
        doc["flow_results"][0]["forward"]["outcome"] = "blocked_in_supplied_policy_model"
        variants.append(doc)
        doc = deepcopy(original)
        doc["flow_results"][0]["forward"]["gates"]["source_security_group_egress"]["witness"][
            "rule_id"
        ] = "unrelated"
        variants.append(doc)
        doc = deepcopy(original)
        doc["flow_results"][0]["reverse"]["packet"]["destination_port"] = 50001
        variants.append(doc)
        for document in variants:
            with self.assertRaises(AwsVpcFlowAnalysisError):
                AwsVpcFlowAnalysis.from_dict(readdress(document))

    def test_native_result_aliases_fail_before_hash(self):
        original = self.document()
        variants = []
        doc = deepcopy(original)
        doc["schema_version"] = True
        variants.append(doc)
        doc = deepcopy(original)
        doc["conntrack_verified"] = 0
        variants.append(doc)
        doc = deepcopy(original)
        doc["bounds"]["flows"] = 64.0
        variants.append(doc)
        doc = deepcopy(original)
        doc["flow_results"][0]["forward"]["gates"]["source_security_group_egress"]["allowed"] = 1
        variants.append(doc)
        doc = deepcopy(original)
        doc["flow_results"][0]["forward"]["gates"]["source_security_group_egress"]["witness"][
            "source_rule_index"
        ] = False
        variants.append(doc)
        for doc in variants:
            with (
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
                self.assertRaises(AwsVpcFlowAnalysisError),
            ):
                AwsVpcFlowAnalysis.from_dict(doc)

    def test_original_model_separate_replay_rejects_truthful_substitution(self):
        original = component_fixture()
        changed = deepcopy(original)
        changed["flows"][0]["source_port"] = 50001
        alternate = analyze_supplied_aws_vpc_flow(changed)
        self.assertEqual(
            AwsVpcFlowAnalysis.from_json(alternate.to_json()).to_json(), alternate.to_json()
        )
        with self.assertRaises(AwsVpcFlowAnalysisError):
            verify_supplied_aws_vpc_flow_analysis(alternate, model=original)

    def test_wrapper_source_and_exports_are_detached(self):
        model = component_fixture()
        record = analyze_supplied_aws_vpc_flow(model)
        original = record.to_json()
        model["network_acls"][0]["ingress"] = []
        exported = record.to_dict()
        exported["source_model"]["endpoints"][0]["address"] = "10.0.1.99"
        exported["flow_results"][0]["forward"]["gates"]["source_security_group_egress"][
            "policy_refs"
        ].clear()
        self.assertEqual(record.to_json(), original)
        forged = object.__new__(AwsVpcFlowAnalysis)
        with self.assertRaises(AwsVpcFlowAnalysisError):
            forged.to_dict()
        object.__setattr__(
            forged,
            "document_json",
            original.replace('"conntrack_verified":false', '"conntrack_verified":true'),
        )
        with self.assertRaises(AwsVpcFlowAnalysisError):
            forged.to_dict()

    def test_bytes_duplicate_keys_signs_and_nonfinite_are_bounded(self):
        raw = json.dumps(component_fixture(), separators=(",", ":"))
        for token in ("--1", "---1", "+1", "01", "-01", "NaN", "1.0", "1e100", "9" * 1000):
            candidate = raw.replace('"schema_version":1', '"schema_version":' + token, 1)
            with self.assertRaises(AwsVpcFlowAnalysisError):
                analyze_supplied_aws_vpc_flow_bytes(model_bytes=candidate.encode("ascii"))
        with self.assertRaises(AwsVpcFlowAnalysisError):
            analyze_supplied_aws_vpc_flow_bytes(
                model_bytes=raw.replace(
                    '"schema_version":1', '"schema_version":1,"schema_version":1', 1
                ).encode("ascii")
            )
        for value in (
            bytearray(raw.encode("ascii")),
            memoryview(raw.encode("ascii")),
            b"\xff",
            b"",
            b" " * (module.MAX_DOCUMENT_BYTES + 1),
        ):
            with self.assertRaises(AwsVpcFlowAnalysisError):
                analyze_supplied_aws_vpc_flow_bytes(model_bytes=value)

    def test_raw_depth_nodes_strings_and_bytes_reject_before_decoder(self):
        for text in (
            "[" * 16 + "0" + "]" * 16,
            "[" * 16 + '"a"' + "]" * 16,
            '"' + "a" * 513 + '"',
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES)) + "]",
            " " * (module.MAX_DOCUMENT_BYTES + 1),
        ):
            with (
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(AwsVpcFlowAnalysisError),
            ):
                AwsVpcFlowAnalysis.from_json(text)

    def test_native_graph_string_integer_and_depth_reject_before_hash(self):
        graph = ["a"]
        for _ in range(16):
            graph = [graph, graph]
        cyclic = []
        cyclic.append(cyclic)
        for extra in (graph, cyclic, "a" * 513, 1 << 20000, [[[[[[]]]]]]):
            model = component_fixture()
            model["extra"] = extra
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                self.invalid(model)

    def test_output_work_and_witness_limits_fail_before_hash(self):
        for name, limit in (("MAX_WORK", 0), ("MAX_WITNESSES", 0), ("MAX_DOCUMENT_BYTES", 6000)):
            with (
                patch.object(module, name, limit),
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.invalid(component_fixture())

    def test_rule_and_reference_ceiling_rejects_without_truncation(self):
        model = component_fixture()
        model["security_groups"][0]["egress"] = [sg_rule(f"r{i}") for i in range(65)]
        self.invalid(model)
        model = component_fixture()
        model["endpoints"][0]["security_group_ids"] *= 17
        self.invalid(model)
        for field, maximum in (
            ("subnets", 32),
            ("endpoints", 64),
            ("security_groups", 64),
            ("network_acls", 32),
            ("flows", 64),
        ):
            model = component_fixture()
            model[field] = [deepcopy(model[field][0]) for _ in range(maximum + 1)]
            self.invalid(model)

    def test_exact_ports_rule_numbers_and_cost_boundaries(self):
        for number in (1, 32766):
            model = self.permissive_acls(component_fixture())
            model["network_acls"][0]["egress"][0]["rule_number"] = number
            self.assertEqual(
                self.row(model)["forward"]["gates"]["source_network_acl_egress"]["witness"][
                    "rule_number"
                ],
                number,
            )
        with patch.object(module, "MAX_DOCUMENT_BYTES", 6):
            self.assertEqual(module._capture('\\"'), '\\"')
            with self.assertRaises(AwsVpcFlowAnalysisError):
                module._capture('\\"x')
        with patch.object(module, "MAX_NATIVE_NODES", 3):
            self.assertEqual(module._capture([0, 1]), [0, 1])
            with self.assertRaises(AwsVpcFlowAnalysisError):
                module._capture([0, 1, 2])

    def test_special_ipv6_service_coordinates_never_become_ordinary_denials(self):
        for address in ("fd00:ec2::123", "fd00:ec2::253", "fd00:ec2::254"):
            model = self.permissive_acls(component_fixture())
            model["vpc"]["cidr"] = "fd00:ec2::/48"
            model["subnets"][0]["cidr"] = "fd00:ec2::/64"
            model["subnets"][1]["cidr"] = "fd00:ec2:0:1::/64"
            model["endpoints"][0]["address"] = address
            model["endpoints"][1]["address"] = "fd00:ec2:0:1::20"
            for policy in model["security_groups"] + model["network_acls"]:
                for direction in ("ingress", "egress"):
                    for rule in policy[direction]:
                        rule["cidr"] = "fd00:ec2::/48"
            model["security_groups"][0]["egress"] = []
            self.assertEqual(self.row(model)["forward"]["outcome"], "unassessed")

    def test_empty_declared_snapshot_never_claims_actual_completeness(self):
        model = component_fixture()
        for field in ("subnets", "endpoints", "security_groups", "network_acls", "flows"):
            model[field] = []
        doc = self.document(model)
        self.assertEqual(doc["flow_results"], [])
        self.assertEqual(doc["analysis_status"], "complete_declared_subset")
        self.assertIs(doc["snapshot_complete"], False)
        self.assertIs(doc["reachability_proven"], False)

    def test_scalar_subclasses_and_bytes_subclasses_fail_before_construction(self):
        class Integer(int):
            pass

        class String(str):
            pass

        class Bytes(bytes):
            pass

        for field, value in (("schema_version", Integer(1)),):
            model = component_fixture()
            model[field] = value
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                self.invalid(model)
        model = component_fixture()
        model["flows"][0]["protocol"] = String("TCP")
        with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
            self.invalid(model)
        with (
            patch.object(module, "_json", side_effect=AssertionError("decoder reached")),
            self.assertRaises(AwsVpcFlowAnalysisError),
        ):
            analyze_supplied_aws_vpc_flow_bytes(model_bytes=Bytes(b"{}"))

    def test_total_rule_guard_and_exact_matching_work_boundary(self):
        with (
            patch.object(module, "MAX_TOTAL_RULES", 5),
            patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
        ):
            self.invalid(component_fixture())
        model = component_fixture()
        prepared = module._prepare(model)
        matcher = module._Matching(*prepared[1:5])
        packet = {field: model["flows"][0][field] for field in module._PACKET_FIELDS}
        matcher.direction(packet)
        exact = matcher.work
        with patch.object(module, "MAX_WORK", exact):
            current = module._Matching(*prepared[1:5])
            current.direction(packet)
            self.assertEqual(current.work, exact)
        with (
            patch.object(module, "MAX_WORK", exact - 1),
            self.assertRaises(AwsVpcFlowAnalysisError),
        ):
            module._Matching(*prepared[1:5]).direction(packet)

    def test_cohashed_native_counters_and_unknown_output_fields_are_denied(self):
        original = self.document()
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("live_use_approved", 0),
        ):
            doc = deepcopy(original)
            doc[field] = value
            with self.assertRaises(AwsVpcFlowAnalysisError):
                AwsVpcFlowAnalysis.from_dict(readdress(doc))
        doc = deepcopy(original)
        doc["provider_verified"] = True
        with (
            patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
            self.assertRaises(AwsVpcFlowAnalysisError),
        ):
            AwsVpcFlowAnalysis.from_dict(doc)


if __name__ == "__main__":
    unittest.main()
