"""Synthetic mathematical and source-replay controls without a cluster or CNI."""

from __future__ import annotations

import itertools
import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from sunderkey import kubernetes_network_policy_analysis as module
from sunderkey.kubernetes_network_policy_analysis import (
    KubernetesNetworkPolicyAnalysis,
    KubernetesNetworkPolicyAnalysisError,
    analyze_supplied_kubernetes_network_policy,
    verify_supplied_kubernetes_network_policy_analysis,
)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "namespaces": [
            {"name": "front", "labels": {"team": "client", "kubernetes.io/metadata.name": "front"}},
            {"name": "back", "labels": {"team": "data", "kubernetes.io/metadata.name": "back"}},
        ],
        "pods": [
            {
                "namespace": "front",
                "name": "client",
                "labels": {"role": "client"},
                "host_network": False,
            },
            {"namespace": "back", "name": "db", "labels": {"role": "db"}, "host_network": False},
        ],
        "network_policies": [
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"namespace": "back", "name": "database"},
                "spec": {
                    "podSelector": {"matchLabels": {"role": "db"}},
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {"matchLabels": {"team": "client"}},
                                    "podSelector": {"matchLabels": {"role": "client"}},
                                }
                            ],
                            "ports": [{"port": 5432}],
                        }
                    ],
                },
            }
        ],
        "flows": [
            {
                "flow_id": "database",
                "source_pod": {"namespace": "front", "name": "client"},
                "destination_pod": {"namespace": "back", "name": "db"},
                "protocol": "TCP",
                "destination_port": 5432,
            },
            {
                "flow_id": "other-port",
                "source_pod": {"namespace": "front", "name": "client"},
                "destination_pod": {"namespace": "back", "name": "db"},
                "protocol": "TCP",
                "destination_port": 5433,
            },
        ],
    }


def policy(namespace: str, name: str, direction: str, rules: list) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"namespace": namespace, "name": name},
        "spec": {"podSelector": {}, "policyTypes": [direction], direction.lower(): rules},
    }


def readdress(value: dict) -> dict:
    document = deepcopy(value)
    document.pop("analysis_id", None)
    document.pop("analysis_sha256", None)
    digest = module._hash(module.DOMAIN, document)
    return {"analysis_id": "KNP-" + digest[7:39].upper(), "analysis_sha256": digest, **document}


class KubernetesNetworkPolicyAnalysisTests(unittest.TestCase):
    def rows(self, model: dict) -> dict:
        return {
            row["flow_id"]: row
            for row in analyze_supplied_kubernetes_network_policy(model).to_dict()["flow_results"]
        }

    def one_flow(self) -> dict:
        model = component_fixture()
        model["flows"] = model["flows"][:1]
        return model

    def assert_invalid(self, model: object) -> None:
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            analyze_supplied_kubernetes_network_policy(model)

    def test_literal_golden_and_canonical_roundtrip(self):
        model = component_fixture()
        report = analyze_supplied_kubernetes_network_policy(model)
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "KNP-7781425C8DD3E876D4459CCC949A0A21")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:7781425c8dd3e876d4459ccc949a0a2124253cd67c9ab360e171a70c8584dfb0",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:236a6375e8830b3467facbe83106ed30d5f663b534151e0ed3ed666744a9f136",
        )
        self.assertEqual(
            KubernetesNetworkPolicyAnalysis.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            KubernetesNetworkPolicyAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_kubernetes_network_policy_analysis(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(document["component_id"], "kubernetes_supplied_network_policy_flows")
        self.assertEqual(document["capability_id"], "army.gc.d15.s07")
        rows = self.rows(model)
        self.assertEqual(rows["database"]["outcome"], "allowed_in_supplied_policy_model")
        self.assertEqual(rows["other-port"]["outcome"], "blocked_in_supplied_policy_model")
        self.assertFalse(rows["database"]["egress"]["isolated"])
        self.assertTrue(rows["database"]["ingress"]["isolated"])
        witness = rows["database"]["ingress"]["matching_rules"][0]
        self.assertEqual(
            (witness["rule_index"], witness["peer_index"], witness["port_index"]), (0, 0, 0)
        )

    def test_all_proof_flags_false_and_effects_none(self):
        document = analyze_supplied_kubernetes_network_policy(component_fixture()).to_dict()
        for field in module._FLAGS:
            self.assertIs(document[field], False)
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(document["input_provenance"], "operator_supplied_unverified")

    def test_independent_small_selector_truth_table_including_empty_values(self):
        states = ({}, {"k": ""}, {"k": "a"}, {"k": "b"})
        cases = [
            (operator, values)
            for operator in ("In", "NotIn")
            for values in ([""], ["a"], ["", "a"])
        ]
        cases += [("Exists", []), ("DoesNotExist", [])]
        for labels, (operator, values) in itertools.product(states, cases):
            model = self.one_flow()
            model["pods"][1]["labels"] = labels
            selector = {"matchExpressions": [{"key": "k", "operator": operator, "values": values}]}
            model["network_policies"] = [policy("back", "deny", "Ingress", [])]
            model["network_policies"][0]["spec"]["podSelector"] = selector
            if operator == "In":
                selected = any(("k", candidate) in labels.items() for candidate in values)
            elif operator == "NotIn":
                selected = not any(("k", candidate) in labels.items() for candidate in values)
            elif operator == "Exists":
                selected = "k" in labels
            else:
                selected = "k" not in labels
            with self.subTest(labels=labels, operator=operator, values=values):
                row = self.rows(model)["database"]
                self.assertEqual(row["ingress"]["isolated"], selected)
                self.assertEqual(row["ingress"]["allowed"], not selected)

    def test_match_labels_and_expressions_are_all_conjunctive(self):
        for value, missing in itertools.product(("", "a", "b"), (True, False)):
            model = self.one_flow()
            model["pods"][1]["labels"] = {"k": value, **({} if missing else {"other": "present"})}
            selected = value == "a" and missing
            model["network_policies"] = [policy("back", "deny", "Ingress", [])]
            model["network_policies"][0]["spec"]["podSelector"] = {
                "matchLabels": {"k": "a"},
                "matchExpressions": [{"key": "other", "operator": "DoesNotExist"}],
            }
            self.assertEqual(self.rows(model)["database"]["ingress"]["isolated"], selected)

    def test_independent_additive_direction_truth_table(self):
        # Each subset consists of a deny-all policy, a matching allow, and a wrong-port allow.
        for incoming, outgoing in itertools.product(range(8), repeat=2):
            model = self.one_flow()
            declarations = []
            for direction, namespace, bits in (
                ("Ingress", "back", incoming),
                ("Egress", "front", outgoing),
            ):
                for index, rules in enumerate(
                    ([], [{"ports": [{"port": 5432}]}], [{"ports": [{"port": 5433}]}])
                ):
                    if bits & (1 << index):
                        declarations.append(policy(namespace, f"p-{index}", direction, rules))
            model["network_policies"] = declarations
            ingress_allow = incoming == 0 or bool(incoming & 2)
            egress_allow = outgoing == 0 or bool(outgoing & 2)
            with self.subTest(incoming=incoming, outgoing=outgoing):
                row = self.rows(model)["database"]
                self.assertEqual(row["ingress"]["allowed"], ingress_allow)
                self.assertEqual(row["egress"]["allowed"], egress_allow)
                self.assertEqual(
                    row["outcome"] == "allowed_in_supplied_policy_model",
                    ingress_allow and egress_allow,
                )

    def test_deny_all_does_not_override_additive_allow_and_order_is_irrelevant(self):
        model = self.one_flow()
        model["network_policies"] = [
            policy("back", "deny", "Ingress", []),
            policy("back", "allow", "Ingress", [{}]),
        ]
        original = analyze_supplied_kubernetes_network_policy(model)
        reversed_model = deepcopy(model)
        reversed_model["network_policies"].reverse()
        changed = analyze_supplied_kubernetes_network_policy(reversed_model)
        self.assertEqual(original.to_dict()["flow_results"], changed.to_dict()["flow_results"])
        self.assertNotEqual(original.to_json(), changed.to_json())

    def test_policy_type_defaults_distinguish_empty_egress_from_one_empty_rule(self):
        for types in (None, []):
            for rules in (None, [], [{}]):
                model = self.one_flow()
                spec = {"podSelector": {}}
                if types is not None:
                    spec["policyTypes"] = types
                if rules is not None:
                    spec["egress"] = rules
                source_policy = policy("front", "source", "Ingress", [])
                source_policy["spec"] = spec
                model["network_policies"] = [source_policy]
                row = self.rows(model)["database"]
                self.assertEqual(row["egress"]["isolated"], rules == [{}])
                self.assertTrue(row["egress"]["allowed"])
        model = self.one_flow()
        model["network_policies"] = [policy("front", "deny", "Egress", [])]
        self.assertEqual(
            self.rows(model)["database"]["outcome"], "blocked_in_supplied_policy_model"
        )

    def test_omitted_policy_selector_matches_all_pods_in_own_namespace(self):
        model = self.one_flow()
        model["network_policies"] = [policy("back", "deny", "Ingress", [])]
        del model["network_policies"][0]["spec"]["podSelector"]
        self.assertTrue(self.rows(model)["database"]["ingress"]["isolated"])
        model["network_policies"][0]["metadata"]["namespace"] = "front"
        self.assertFalse(self.rows(model)["database"]["ingress"]["isolated"])

    def test_empty_rules_and_empty_or_missing_peer_port_lists_are_unrestricted(self):
        for rule in ({}, {"from": []}, {"ports": []}, {"from": [], "ports": []}):
            model = self.one_flow()
            model["network_policies"] = [policy("back", "allow", "Ingress", [rule])]
            self.assertTrue(self.rows(model)["database"]["ingress"]["allowed"])
        for rule in ({}, {"to": []}, {"ports": []}, {"to": [], "ports": []}):
            model = self.one_flow()
            model["network_policies"] = [policy("front", "allow", "Egress", [rule])]
            self.assertTrue(self.rows(model)["database"]["egress"]["allowed"])

    def test_peer_pod_selector_without_namespace_selector_is_namespace_confined(self):
        model = self.one_flow()
        model["network_policies"][0]["spec"]["ingress"][0]["from"] = [{"podSelector": {}}]
        self.assertFalse(self.rows(model)["database"]["ingress"]["allowed"])
        model["pods"][0]["namespace"] = "back"
        model["flows"][0]["source_pod"]["namespace"] = "back"
        self.assertTrue(self.rows(model)["database"]["ingress"]["allowed"])

    def test_namespace_and_pod_selector_same_peer_and_separate_peers_or(self):
        for namespace_ok, pod_ok in itertools.product((False, True), repeat=2):
            model = self.one_flow()
            model["namespaces"][0]["labels"]["team"] = "client" if namespace_ok else "other"
            model["pods"][0]["labels"]["role"] = "client" if pod_ok else "other"
            self.assertEqual(
                self.rows(model)["database"]["ingress"]["allowed"], namespace_ok and pod_ok
            )
        model = self.one_flow()
        model["network_policies"][0]["spec"]["ingress"][0]["from"] = [
            {"namespaceSelector": {"matchLabels": {"team": "other"}}},
            {"namespaceSelector": {"matchLabels": {"team": "client"}}},
        ]
        self.assertTrue(self.rows(model)["database"]["ingress"]["allowed"])

    def test_empty_namespace_selector_selects_all_supplied_namespaces(self):
        model = self.one_flow()
        model["network_policies"][0]["spec"]["ingress"][0]["from"] = [{"namespaceSelector": {}}]
        self.assertTrue(self.rows(model)["database"]["ingress"]["allowed"])

    def test_namespace_name_labels_are_never_invented(self):
        model = self.one_flow()
        model["namespaces"][0]["labels"] = {}
        model["network_policies"][0]["spec"]["ingress"][0]["from"] = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "front"}}}
        ]
        self.assertFalse(self.rows(model)["database"]["ingress"]["allowed"])
        model["namespaces"][0]["labels"]["kubernetes.io/metadata.name"] = "back"
        self.assert_invalid(model)

    def test_default_protocol_and_missing_port_differ_from_unrestricted_port_list(self):
        for protocol in ("TCP", "UDP", "SCTP"):
            model = self.one_flow()
            model["flows"][0]["protocol"] = protocol
            model["network_policies"][0]["spec"]["ingress"][0]["ports"] = [{}]
            self.assertEqual(self.rows(model)["database"]["ingress"]["allowed"], protocol == "TCP")
            model["network_policies"][0]["spec"]["ingress"][0]["ports"] = []
            self.assertTrue(self.rows(model)["database"]["ingress"]["allowed"])

    def test_protocol_alternatives_and_compact_inclusive_end_port_boundaries(self):
        for port in (1, 1999, 2000, 2001, 65535):
            model = self.one_flow()
            model["flows"][0]["destination_port"] = port
            model["network_policies"][0]["spec"]["ingress"][0]["ports"] = [
                {"protocol": "TCP", "port": 2000, "endPort": 65535}
            ]
            self.assertEqual(self.rows(model)["database"]["ingress"]["allowed"], port >= 2000)
        for protocol in ("TCP", "UDP", "SCTP"):
            model = self.one_flow()
            model["flows"][0]["protocol"] = protocol
            model["network_policies"][0]["spec"]["ingress"][0]["ports"] = [
                {"protocol": "UDP"},
                {"protocol": "SCTP"},
            ]
            self.assertEqual(self.rows(model)["database"]["ingress"]["allowed"], protocol != "TCP")

    def test_end_port_missing_named_or_invalid_numeric_base_rejects(self):
        bad_ports = [
            {"endPort": 5433},
            {"port": "database", "endPort": 5433},
            {"port": True, "endPort": 5433},
            {"port": 5432, "endPort": 5431},
            {"port": 5432, "endPort": 5433.0},
            {"port": 0},
            {"port": 65536},
        ]
        for port in bad_ports:
            model = self.one_flow()
            model["network_policies"][0]["spec"]["ingress"][0]["ports"] = [port]
            with self.subTest(port=port):
                self.assert_invalid(model)

    def test_recognized_unsupported_anywhere_globally_withholds_conclusions(self):
        cases = []
        named = self.one_flow()
        named["network_policies"].append(
            policy("front", "irrelevant", "Ingress", [{"ports": [{"port": "http"}]}])
        )
        cases.append((named, "named_port_outside_subset"))
        block = self.one_flow()
        block["network_policies"].append(
            policy(
                "front",
                "irrelevant",
                "Ingress",
                [{"from": [{"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}}]}],
            )
        )
        cases.append((block, "ip_block_outside_subset"))
        host = self.one_flow()
        host["pods"].append(
            {"namespace": "front", "name": "unused", "labels": {}, "host_network": True}
        )
        cases.append((host, "host_network_outside_subset"))
        for model, code in cases:
            document = analyze_supplied_kubernetes_network_policy(model).to_dict()
            with self.subTest(code=code):
                self.assertEqual(document["analysis_status"], "incomplete")
                self.assertIn(code, [issue["code"] for issue in document["incomplete_reasons"]])
                for row in document["flow_results"]:
                    self.assertEqual(row["outcome"], "unassessed")
                    self.assertIsNone(row["ingress"]["allowed"])
                    self.assertEqual(row["ingress"]["matching_rules"], [])
                verify_supplied_kubernetes_network_policy_analysis(
                    KubernetesNetworkPolicyAnalysis.from_dict(document), model=model
                )

    def test_same_pod_exception_is_unassessed_not_falsely_blocked(self):
        model = self.one_flow()
        model["flows"][0]["source_pod"] = deepcopy(model["flows"][0]["destination_pod"])
        model["network_policies"] = [policy("back", "deny", "Ingress", [])]
        row = self.rows(model)["database"]
        self.assertEqual(row["outcome"], "unassessed")
        self.assertEqual(row["ingress"]["reason"], "same_pod_exception_outside_subset")

    def test_empty_snapshot_and_no_policy_have_no_manufactured_cluster_completeness(self):
        empty = {
            "schema_version": 1,
            "namespaces": [],
            "pods": [],
            "network_policies": [],
            "flows": [],
        }
        self.assertEqual(
            analyze_supplied_kubernetes_network_policy(empty).to_dict()["flow_results"], []
        )
        model = self.one_flow()
        model["network_policies"] = []
        row = self.rows(model)["database"]
        self.assertEqual(row["outcome"], "allowed_in_supplied_policy_model")
        self.assertEqual(row["ingress"]["reason"], "not_isolated_by_supplied_policies")

    def test_duplicate_identities_and_missing_namespace_pod_refs_reject(self):
        for collection in ("namespaces", "pods", "network_policies", "flows"):
            model = component_fixture()
            model[collection].append(deepcopy(model[collection][0]))
            self.assert_invalid(model)
        for collection in ("pods", "network_policies"):
            model = self.one_flow()
            if collection == "pods":
                model[collection][0]["namespace"] = "missing"
            else:
                model[collection][0]["metadata"]["namespace"] = "missing"
            self.assert_invalid(model)
        model = self.one_flow()
        model["flows"][0]["source_pod"]["name"] = "missing"
        self.assert_invalid(model)

    def test_closed_fields_and_malformed_selectors_peers_are_not_silently_ignored(self):
        cases = [
            {},
            {"podSelector": None},
            {"ipBlock": {"cidr": "192.0.2.0/24"}, "podSelector": {}},
        ]
        for peer in cases:
            model = self.one_flow()
            model["network_policies"][0]["spec"]["ingress"][0]["from"] = [peer]
            self.assert_invalid(model)
        selectors = [
            {"matchLabels": {"bad/key/again": "v"}},
            {"matchLabels": {"key": "a" * 64}},
            {"matchExpressions": [{"key": "key", "operator": "In", "values": []}]},
            {"matchExpressions": [{"key": "key", "operator": "Exists", "values": [""]}]},
            {"matchExpressions": [{"key": "key", "operator": "Unknown"}]},
            {"unknown": {}},
        ]
        for selector in selectors:
            model = self.one_flow()
            model["network_policies"][0]["spec"]["podSelector"] = selector
            self.assert_invalid(model)
        for section in ("root", "spec", "flow", "metadata"):
            model = self.one_flow()
            selected = (
                model
                if section == "root"
                else model["network_policies"][0]["spec"]
                if section == "spec"
                else model["flows"][0]
                if section == "flow"
                else model["network_policies"][0]["metadata"]
            )
            selected["undeclared"] = None
            self.assert_invalid(model)

    def test_native_aliases_subclasses_reject_before_hash_or_serialization(self):
        class ForeignString(str):
            def __eq__(self, other):
                raise AssertionError("custom equality reached")

            __hash__ = str.__hash__

        class ForeignInt(int):
            pass

        class ForeignList(list):
            pass

        class ForeignDict(dict):
            pass

        cases = []
        for alias in (True, 1.0, ForeignInt(1)):
            value = self.one_flow()
            value["schema_version"] = alias
            cases.append(value)
        for alias in (True, 5432.0, ForeignInt(5432)):
            value = self.one_flow()
            value["flows"][0]["destination_port"] = alias
            cases.append(value)
        value = self.one_flow()
        value["pods"][0]["host_network"] = 0
        cases.append(value)
        value = self.one_flow()
        value["flows"][0]["protocol"] = ForeignString("TCP")
        cases.append(value)
        value = self.one_flow()
        value["pods"] = ForeignList(value["pods"])
        cases.append(value)
        cases.append(ForeignDict(self.one_flow()))
        value = self.one_flow()
        value[ForeignString("extra")] = None
        cases.append(value)
        for value in cases:
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                self.assert_invalid(value)

    def test_rehashed_false_outcomes_witnesses_flags_bounds_and_native_aliases_reject(self):
        document = analyze_supplied_kubernetes_network_policy(component_fixture()).to_dict()
        variants = []
        wrong = deepcopy(document)
        wrong["flow_results"][1]["outcome"] = "allowed_in_supplied_policy_model"
        variants.append(wrong)
        wrong = deepcopy(document)
        wrong["flow_results"][0]["ingress"]["matching_rules"][0]["rule_index"] = 1
        variants.append(wrong)
        for field in module._FLAGS:
            wrong = deepcopy(document)
            wrong[field] = True
            variants.append(wrong)
        for alias in (True, 1.0):
            wrong = deepcopy(document)
            wrong["schema_version"] = alias
            variants.append(wrong)
        wrong = deepcopy(document)
        wrong["flow_results"][0]["ingress"]["isolated"] = 1
        variants.append(wrong)
        wrong = deepcopy(document)
        wrong["bounds"]["flows"] = 65
        variants.append(wrong)
        wrong = deepcopy(document)
        wrong["undeclared"] = None
        variants.append(wrong)
        for wrong in variants:
            with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
                KubernetesNetworkPolicyAnalysis.from_dict(readdress(wrong))

    def test_coherent_foreign_model_parser_is_unsigned_but_original_replay_rejects(self):
        original = self.one_flow()
        foreign = deepcopy(original)
        foreign["network_policies"][0]["spec"]["ingress"] = []
        report = analyze_supplied_kubernetes_network_policy(foreign)
        self.assertEqual(
            KubernetesNetworkPolicyAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            verify_supplied_kubernetes_network_policy_analysis(report, model=original)

    def test_inputs_and_outputs_detached_and_array_order_source_bound(self):
        original = component_fixture()
        source = deepcopy(original)
        report = analyze_supplied_kubernetes_network_policy(source)
        raw = report.to_json()
        source["pods"][0]["labels"]["role"] = "changed"
        document = report.to_dict()
        document["source_model"]["namespaces"][0]["labels"].clear()
        document["flow_results"][0]["ingress"]["matching_rules"].clear()
        self.assertEqual(report.to_json(), raw)
        verify_supplied_kubernetes_network_policy_analysis(report, model=original)
        changed = deepcopy(original)
        changed["namespaces"].reverse()
        changed["pods"].reverse()
        changed["flows"].reverse()
        other = analyze_supplied_kubernetes_network_policy(changed)
        self.assertEqual(report.to_dict()["flow_results"], other.to_dict()["flow_results"])
        self.assertNotEqual(raw, other.to_json())

    def test_public_forged_incomplete_or_foreign_wrapper_is_not_trusted(self):
        incomplete = object.__new__(KubernetesNetworkPolicyAnalysis)
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            incomplete.to_dict()
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            verify_supplied_kubernetes_network_policy_analysis(
                incomplete, model=component_fixture()
            )
        genuine = analyze_supplied_kubernetes_network_policy(component_fixture())
        forged = object.__new__(KubernetesNetworkPolicyAnalysis)
        wrong = genuine.to_dict()
        wrong["reachability_proven"] = True
        object.__setattr__(forged, "document_json", module._canonical(readdress(wrong)))
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            verify_supplied_kubernetes_network_policy_analysis(forged, model=component_fixture())
        for wrong_family in (genuine.to_dict(), genuine.to_json(), None):
            with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
                verify_supplied_kubernetes_network_policy_analysis(
                    wrong_family, model=component_fixture()
                )

    def test_raw_duplicate_keys_and_malformed_integer_lexicals_return_leaf_error(self):
        raw = analyze_supplied_kubernetes_network_policy(component_fixture()).to_json()
        duplicate = raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
        with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
            KubernetesNetworkPolicyAnalysis.from_json(duplicate)
        for token in (
            "--1",
            "---1",
            "-",
            "+1",
            "01",
            "-01",
            "1.0",
            "1e0",
            "NaN",
            "9223372036854775808",
            "9" * 1000,
        ):
            with (
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
                self.assertRaises(KubernetesNetworkPolicyAnalysisError),
            ):
                KubernetesNetworkPolicyAnalysis.from_json(
                    raw.replace('"schema_version":1', '"schema_version":' + token, 1)
                )

    def test_raw_depth_nodes_strings_bytes_are_bounded_before_decoder(self):
        documents = [
            "[" * 17 + "0" + "]" * 17,
            "[" * 16 + "0" + "]" * 16,
            "[" * 16 + '"x"' + "]" * 16,
            "[" * 16 + "true" + "]" * 16,
            "[" * 16 + "null" + "]" * 16,
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES)) + "]",
            '"' + "a" * 513 + '"',
            '"' + r"\u0061" * 513 + '"',
            r'"\ud800"',
            r'"\u0080"',
            " " * (module.MAX_DOCUMENT_BYTES + 1),
        ]
        for raw in documents:
            with (
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(KubernetesNetworkPolicyAnalysisError),
            ):
                KubernetesNetworkPolicyAnalysis.from_json(raw)
        for raw in (None, b"{}", {}, 1, "", "{", "[}"):
            with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
                KubernetesNetworkPolicyAnalysis.from_json(raw)
        expected = 0
        for _ in range(15):
            expected = [expected]
        self.assertEqual(module._decode("[" * 15 + "0" + "]" * 15), expected)

    def test_native_shared_graph_cost_depth_cycles_precede_serialization_and_hash(self):
        quoted = '\\"' * 256
        shared = [quoted] * 1024
        cyclic = []
        cyclic.append(cyclic)
        deep = 0
        for _ in range(17):
            deep = [deep]
        for value in (shared, cyclic, deep, {"n": 1 << 100000}, [0] * module.MAX_NATIVE_NODES):
            with (
                patch.object(
                    module.json, "dumps", side_effect=AssertionError("serialization reached")
                ),
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.assert_invalid(value)

    def test_exact_native_byte_depth_node_and_integer_boundaries(self):
        value = {"quoted": ['\\"', '\\"']}
        size = len(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
        with patch.object(module, "MAX_DOCUMENT_BYTES", size):
            self.assertEqual(module._capture(value), value)
        with (
            patch.object(module, "MAX_DOCUMENT_BYTES", size - 1),
            patch.object(module.json, "dumps", side_effect=AssertionError("serialization reached")),
            self.assertRaises(KubernetesNetworkPolicyAnalysisError),
        ):
            module._capture(value)
        self.assertEqual(module._capture([2**63 - 1, -(2**63 - 1)]), [2**63 - 1, -(2**63 - 1)])
        with (
            patch.object(module, "MAX_NATIVE_DEPTH", 2),
            patch.object(module, "MAX_NATIVE_NODES", 3),
        ):
            self.assertEqual(module._capture([0, 1]), [0, 1])
            with self.assertRaises(KubernetesNetworkPolicyAnalysisError):
                module._capture([[0]])

    def test_matching_and_witness_limits_precede_hash_without_truncation(self):
        model = self.one_flow()
        with (
            patch.object(module, "MAX_MATCH_WORK", 0),
            patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
        ):
            self.assert_invalid(model)
        model["network_policies"] = [policy("back", "allow", "Ingress", [{}, {}])]
        with (
            patch.object(module, "MAX_WITNESSES", 1),
            patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
        ):
            self.assert_invalid(model)
        model["network_policies"][0]["spec"]["ingress"] = [{}]
        with patch.object(module, "MAX_WITNESSES", 1):
            self.assertEqual(len(self.rows(model)["database"]["ingress"]["matching_rules"]), 1)

    def test_repeated_flows_cache_selector_evaluations_and_charge_work(self):
        model = self.one_flow()
        model["flows"] = [{**model["flows"][0], "flow_id": f"flow-{i}"} for i in range(64)]
        original = module._Matching.selector
        missed: dict = {}

        def observe(instance, selector, kind, identity, labels):
            key = (selector.index, kind, identity)
            if key not in instance.cache:
                missed[instance] = missed.get(instance, 0) + 1
            return original(instance, selector, kind, identity, labels)

        with (
            patch.object(module._Matching, "selector", observe),
            patch.object(module, "MAX_MATCH_WORK", 400),
        ):
            result = analyze_supplied_kubernetes_network_policy(model).to_dict()
        self.assertEqual(len(result["flow_results"]), 64)
        self.assertTrue(missed)
        self.assertEqual(set(missed.values()), {3})
        self.assertTrue(
            all(
                row["outcome"] == "allowed_in_supplied_policy_model"
                for row in result["flow_results"]
            )
        )

    def test_collection_ceilings_reject_before_hash(self):
        cases = []
        for field, maximum in (
            ("namespaces", 64),
            ("pods", 256),
            ("network_policies", 128),
            ("flows", 64),
        ):
            value = self.one_flow()
            value[field] = [deepcopy(value[field][0]) for _ in range(maximum + 1)]
            cases.append(value)
        value = self.one_flow()
        value["pods"][0]["labels"] = {f"label-{i}": "" for i in range(65)}
        cases.append(value)
        value = self.one_flow()
        value["network_policies"][0]["spec"]["ingress"][0]["from"] = [
            {"namespaceSelector": {}}
        ] * 65
        cases.append(value)
        value = self.one_flow()
        value["network_policies"][0]["spec"]["ingress"] = [{}] * 513
        cases.append(value)
        value = self.one_flow()
        value["network_policies"][0]["spec"]["ingress"][0]["ports"] = [{}] * 65
        cases.append(value)
        value = self.one_flow()
        value["network_policies"][0]["spec"]["podSelector"] = {
            "matchExpressions": [{"key": "k", "operator": "Exists"}] * 65
        }
        cases.append(value)
        value = self.one_flow()
        value["network_policies"][0]["spec"]["podSelector"] = {
            "matchExpressions": [{"key": "k", "operator": "In", "values": ["a"] * 65}]
        }
        cases.append(value)
        for value in cases:
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                self.assert_invalid(value)

    def test_supported_count_boundaries_with_valid_unique_objects(self):
        namespaces = self.one_flow()
        namespaces["namespaces"] += [{"name": f"ns-{i}", "labels": {}} for i in range(62)]
        self.assertEqual(
            len(
                analyze_supplied_kubernetes_network_policy(namespaces).to_dict()["source_model"][
                    "namespaces"
                ]
            ),
            64,
        )
        pods = self.one_flow()
        pods["pods"] += [
            {"namespace": "front", "name": f"pod-{i}", "labels": {}, "host_network": False}
            for i in range(254)
        ]
        self.assertEqual(
            len(analyze_supplied_kubernetes_network_policy(pods).to_dict()["source_model"]["pods"]),
            256,
        )
        policies = self.one_flow()
        policies["network_policies"] = [policy("back", f"p-{i}", "Ingress", []) for i in range(128)]
        self.assertEqual(
            len(self.rows(policies)["database"]["ingress"]["applicable_policies"]), 128
        )
        rules = self.one_flow()
        rules["network_policies"] = [policy("back", "allows", "Ingress", [{}] * 512)]
        self.assertEqual(len(self.rows(rules)["database"]["ingress"]["matching_rules"]), 512)

    def test_selector_and_label_boundaries_preserve_empty_values(self):
        model = self.one_flow()
        labels = {f"k-{i}": "" for i in range(64)}
        model["pods"][1]["labels"] = labels
        model["network_policies"] = [policy("back", "deny", "Ingress", [])]
        model["network_policies"][0]["spec"]["podSelector"] = {
            "matchLabels": labels,
            "matchExpressions": [{"key": f"k-{i}", "operator": "Exists"} for i in range(64)],
        }
        self.assertTrue(self.rows(model)["database"]["ingress"]["isolated"])
        model["network_policies"][0]["spec"]["podSelector"] = {
            "matchExpressions": [
                {"key": "k-0", "operator": "In", "values": [""] + [f"v-{i}" for i in range(63)]}
            ]
        }
        self.assertTrue(self.rows(model)["database"]["ingress"]["isolated"])

    def test_invalid_native_names_labels_protocols_and_policy_types_are_controlled(self):
        cases = []
        for value in ("", "Front", "a.b", "x" * 64):
            model = self.one_flow()
            model["namespaces"][0]["name"] = value
            cases.append(model)
        for value in ("", "x" * 64, "bad value", None, False):
            model = self.one_flow()
            model["pods"][0]["labels"] = {"valid": value}
            if value == "":
                continue
            cases.append(model)
        for value in (None, [], False, "ICMP"):
            model = self.one_flow()
            model["flows"][0]["protocol"] = value
            cases.append(model)
        for value in ([True], ["Other"], ["Ingress", "Egress", "Ingress"], None):
            model = self.one_flow()
            model["network_policies"][0]["spec"]["policyTypes"] = value
            cases.append(model)
        for value in cases:
            self.assert_invalid(value)


if __name__ == "__main__":
    unittest.main()
