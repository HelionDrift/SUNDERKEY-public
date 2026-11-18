"""Independent small packet grids, uncertainty and original-source NSG controls."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_azure_nsg_analysis as nsg

ERROR = nsg.AzureNsgAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def predicate(**changes):
    return {
        "kind": "cidr_ports",
        "protocol": "Any",
        "source_cidrs": ["0.0.0.0/0"],
        "destination_cidrs": ["0.0.0.0/0"],
        "source_ports": [[0, 65535]],
        "destination_ports": [[0, 65535]],
        **changes,
    }


def rule(identifier="allow", priority=100, access="Allow", direction="Inbound", **changes):
    return {
        "rule_id": identifier,
        "priority": priority,
        "access": access,
        "direction": direction,
        "predicate": predicate(),
        **changes,
    }


def group(identifier="subnet", rules=None, *, complete=True):
    return {
        "nsg_id": identifier,
        "rules_complete": complete,
        "rules": [rule()] if rules is None else rules,
    }


def flow(identifier="packet", **changes):
    return {
        "flow_id": identifier,
        "direction": "Inbound",
        "protocol": "TCP",
        "source_ip": "10.0.0.1",
        "source_port": 1000,
        "destination_ip": "10.0.1.2",
        "destination_port": 443,
        **changes,
    }


def model(groups=None, flows=None, **attachments):
    return {
        "schema_version": 1,
        "nsgs": [group()] if groups is None else groups,
        "attachments": {
            "complete": True,
            "subnet_nsg_id": "subnet",
            "nic_nsg_id": None,
            **attachments,
        },
        "flows": [flow()] if flows is None else flows,
    }


def component_fixture():
    return nsg.component_fixture()


def document(value=None):
    return nsg.analyze_supplied_azure_nsg(model() if value is None else value).to_dict()


def outcome(value):
    return document(value)["flow_observations"][0]


def readdress(value):
    body = copy.deepcopy(value)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-azure-nsg-analysis.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "NSGA-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class AzureNsgAnalysisTests(unittest.TestCase):
    def deny_before_hash(self, value):
        with patch.object(nsg, "_address") as address:
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg(value)
            address.assert_not_called()

    def deny_before_decoder(self, text):
        with patch.object(nsg.json, "loads") as decoder, patch.object(nsg, "_address") as address:
            with self.assertRaises(ERROR):
                nsg.AzureNsgAnalysis.from_json(text)
            decoder.assert_not_called()
            address.assert_not_called()

    def test_fixture_literal_source_report_and_independent_digests(self):
        value = component_fixture()
        result = document(value)
        self.assertEqual(result["analysis_id"], "NSGA-6757B2E65C44905F4C8812CFC956D390")
        self.assertEqual(
            result["analysis_sha256"],
            "sha256:6757b2e65c44905f4c8812cfc956d39009e76531303ab5bb638b000eb65bde95",
        )
        self.assertEqual(
            result["source_model_sha256"],
            "sha256:5b86106d482a0ab104104c983cc0554addc26651b8d1d34bd743d3249438cbad",
        )
        source = hashlib.sha256(
            b"sunderkey.offline-azure-nsg-model.v1\n" + canonical(value).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["source_model_sha256"], "sha256:" + source)
        self.assertEqual(readdress(result), result)
        self.assertNotEqual(result["analysis_sha256"], result["source_model_sha256"])
        rows = result["flow_observations"]
        self.assertEqual(
            [row["decision"] for row in rows],
            ["allow_under_supplied_nsg_predicates", "unassessed"],
        )
        self.assertEqual(rows[0]["layer_order"], ["subnet", "nic"])
        self.assertEqual(rows[1]["layer_order"], ["nic", "subnet"])
        self.assertEqual(rows[1]["layers"][1]["candidate_rule_id"], "outbound-unknown-tag")
        self.assertEqual(
            result["summary"],
            {"flows": 2, "allow": 1, "deny": 0, "not_filtered": 0, "unassessed": 1},
        )

    def test_independent_small_grid_priority_and_protocol_oracle(self):
        # Independent finite membership sets, not the production CIDR/port predicates.
        rules = [
            rule("catchall", 300, "Deny"),
            rule(
                "udp-small",
                100,
                predicate=predicate(
                    protocol="UDP",
                    source_cidrs=["10.0.0.0/30"],
                    destination_ports=[[2, 3]],
                ),
            ),
            rule(
                "tcp-endpoint",
                200,
                predicate=predicate(
                    protocol="TCP",
                    destination_cidrs=["10.0.1.2/32"],
                    source_ports=[[1, 2]],
                    destination_ports=[[3, 3]],
                ),
            ),
        ]
        controls = 0
        for proto, source, destination, sport, dport in itertools.product(
            ("TCP", "UDP"),
            (1, 3, 4),
            (1, 2),
            range(4),
            range(4),
        ):
            if proto == "UDP" and source in {0, 1, 2, 3} and dport in {2, 3}:
                expected = "udp-small"
            elif proto == "TCP" and destination == 2 and sport in {1, 2} and dport == 3:
                expected = "tcp-endpoint"
            else:
                expected = "catchall"
            packet = flow(
                protocol=proto,
                source_ip=f"10.0.0.{source}",
                destination_ip=f"10.0.1.{destination}",
                source_port=sport,
                destination_port=dport,
            )
            row = outcome(model([group(rules=rules)], [packet]))
            self.assertEqual(row["layers"][0]["candidate_rule_id"], expected)
            expected_action = "deny" if expected == "catchall" else "allow"
            self.assertEqual(row["decision"], expected_action + "_under_supplied_nsg_predicates")
            controls += 1
        self.assertEqual(controls, 192)

    def test_independent_layer_conjunction_truth_table(self):
        definitions = {
            "allow": group(rules=[rule()]),
            "deny": group(rules=[rule(access="Deny")]),
            "unknown": group(rules=[]),
            "absent": None,
        }
        for left, right in itertools.product(definitions, repeat=2):
            groups = []
            for name, key in (("subnet", left), ("nic", right)):
                if definitions[key] is not None:
                    item = copy.deepcopy(definitions[key])
                    item["nsg_id"] = name
                    groups.append(item)
            value = model(
                groups,
                subnet_nsg_id=None if left == "absent" else "subnet",
                nic_nsg_id=None if right == "absent" else "nic",
            )
            row = outcome(value)
            if "deny" in (left, right):
                expected = "deny_under_supplied_nsg_predicates"
            elif "unknown" in (left, right):
                expected = "unassessed"
            elif left == right == "absent":
                expected = "not_filtered_by_declared_nsgs"
            else:
                expected = "allow_under_supplied_nsg_predicates"
            self.assertEqual(row["decision"], expected)
            self.assertEqual(len(row["uncertainty"]), (left == "unknown") + (right == "unknown"))

    def test_rule_order_does_not_override_priority(self):
        rows = [rule("late", 4096, "Deny"), rule("first", 100), rule("middle", 200, "Deny")]
        for permutation in itertools.permutations(rows):
            result = outcome(model([group(rules=list(permutation))]))
            self.assertEqual(result["layers"][0]["candidate_rule_id"], "first")

    def test_directions_and_no_automatic_stateful_return(self):
        value = model(flows=[flow(), flow("reverse", direction="Outbound")])
        rows = document(value)["flow_observations"]
        self.assertEqual(rows[0]["decision"], "allow_under_supplied_nsg_predicates")
        self.assertEqual(rows[1]["decision"], "unassessed")
        self.assertEqual(rows[1]["layers"][1]["reason"], "no_supplied_match")

    def test_both_nsg_layers_must_allow_and_direction_order_is_exact(self):
        groups = [group(), group("nic", [rule(access="Deny")])]
        inbound = outcome(model(groups, nic_nsg_id="nic"))
        self.assertEqual(inbound["decision"], "deny_under_supplied_nsg_predicates")
        self.assertEqual([item["layer"] for item in inbound["layers"]], ["subnet", "nic"])
        for item in groups:
            item["rules"][0]["direction"] = "Outbound"
        outbound = outcome(model(groups, [flow(direction="Outbound")], nic_nsg_id="nic"))
        self.assertEqual([item["layer"] for item in outbound["layers"]], ["nic", "subnet"])
        self.assertEqual(outbound["decision"], "deny_under_supplied_nsg_predicates")

    def test_unknown_earlier_rule_blocks_later_allow_and_deny(self):
        for reason, access in itertools.product(
            sorted(nsg._UNSUPPORTED_REASONS), ("Allow", "Deny")
        ):
            rules = [
                rule("unknown", 100, predicate={"kind": "unsupported", "reason": reason}),
                rule("later", 200, access),
            ]
            result = outcome(model([group(rules=rules)]))
            self.assertEqual(result["decision"], "unassessed")
            self.assertEqual(result["layers"][0]["candidate_rule_id"], "unknown")
            self.assertEqual(result["layers"][0]["reason"], "unsupported_earlier_predicate")

    def test_later_unsupported_default_does_not_override_known_first_match(self):
        for priority in (65000, 65001, 65500):
            rules = [
                rule("first", 4096),
                rule("tag", priority, predicate={"kind": "unsupported", "reason": "service_tag"}),
            ]
            result = outcome(model([group(rules=rules)]))
            self.assertEqual(result["decision"], "allow_under_supplied_nsg_predicates")
            self.assertEqual(result["layers"][0]["candidate_priority"], 4096)

    def test_incomplete_rule_sets_never_claim_a_layer_allow_or_deny(self):
        for access in ("Allow", "Deny"):
            result = outcome(model([group(rules=[rule(access=access)], complete=False)]))
            self.assertEqual(result["decision"], "unassessed")
            self.assertEqual(result["layers"][0]["reason"], "rules_incomplete")
            self.assertIsNone(result["layers"][0]["candidate_rule_id"])

    def test_attachment_incompleteness_withholds_all_final_results(self):
        for access in ("Allow", "Deny"):
            result = outcome(model([group(rules=[rule(access=access)])], complete=False))
            self.assertEqual(result["decision"], "unassessed")
            self.assertTrue(
                all(
                    item["reason"] == "attachment_projection_incomplete"
                    for item in result["layers"]
                )
            )

    def test_known_deny_retains_other_layer_uncertainty(self):
        result = outcome(
            model(
                [group(rules=[rule(access="Deny")]), group("nic", [], complete=False)],
                nic_nsg_id="nic",
            )
        )
        self.assertEqual(result["decision"], "deny_under_supplied_nsg_predicates")
        self.assertEqual(result["uncertainty"], ["nic:rules_incomplete"])

    def test_absent_nsgs_and_no_match_do_not_invent_network_permission_or_denial(self):
        absent = outcome(model([], subnet_nsg_id=None))
        self.assertEqual(absent["decision"], "not_filtered_by_declared_nsgs")
        empty = outcome(model([group(rules=[])]))
        self.assertEqual(empty["decision"], "unassessed")
        self.assertEqual(empty["layers"][0]["reason"], "no_supplied_match")

    def test_cidr_dimension_or_and_port_range_inclusive_edges(self):
        pred = predicate(
            source_cidrs=["10.0.0.1/32", "10.0.0.4/32"],
            source_ports=[[0, 0], [2, 3]],
            destination_ports=[[443, 444]],
        )
        rules = [rule(predicate=pred), rule("fallback", 200, "Deny")]
        for source, sport, dport in itertools.product(
            (1, 2, 4), (0, 1, 2, 3, 4, 65535), (442, 443, 444, 445)
        ):
            packet = flow(source_ip=f"10.0.0.{source}", source_port=sport, destination_port=dport)
            expected = source in {1, 4} and sport in {0, 2, 3} and dport in {443, 444}
            actual = outcome(model([group(rules=rules)], [packet]))["decision"]
            self.assertEqual(
                actual, ("allow" if expected else "deny") + "_under_supplied_nsg_predicates"
            )

    def test_ipv6_and_different_family_predicates(self):
        pred = predicate(
            source_cidrs=["2001:db8::/64", "10.0.0.0/24"], destination_cidrs=["2001:db8:1::/64"]
        )
        packet = flow(source_ip="2001:db8::1", destination_ip="2001:db8:1::2")
        self.assertEqual(
            outcome(model([group(rules=[rule(predicate=pred)])], [packet]))["decision"],
            "allow_under_supplied_nsg_predicates",
        )
        pred["destination_cidrs"] = ["10.0.1.0/24"]
        self.assertEqual(
            outcome(model([group(rules=[rule(predicate=pred)])], [packet]))["decision"],
            "unassessed",
        )

    def test_supported_priority_boundaries_and_opposite_direction_reuse(self):
        for priority in (100, 4096, 65000, 65001, 65500):
            self.assertEqual(
                outcome(model([group(rules=[rule(priority=priority)])]))["layers"][0][
                    "candidate_priority"
                ],
                priority,
            )
        rules = [rule(), rule("out", direction="Outbound")]
        self.assertEqual(document(model([group(rules=rules)]))["summary"]["allow"], 1)
        for priority in (99, 4097, 64999, 65501, True, 100.0, "100"):
            self.deny_before_hash(model([group(rules=[rule(priority=priority)])]))

    def test_duplicate_nsg_rule_direction_priority_and_flow_ids_are_denied(self):
        values = [
            model([group(), group()]),
            model([group(rules=[rule(), rule(priority=200)])]),
            model([group(rules=[rule(), rule("other")])]),
            model(flows=[flow(), flow()]),
        ]
        for value in values:
            self.deny_before_hash(value)

    def test_unjoined_attachment_and_invalid_tagged_shapes_are_denied(self):
        self.deny_before_hash(model(nic_nsg_id="foreign"))
        for value in (
            None,
            {},
            {"kind": "other"},
            {"kind": "unsupported", "reason": "invented"},
            {"kind": "unsupported", "reason": "service_tag", "resolved": True},
        ):
            self.deny_before_hash(model([group(rules=[rule(predicate=value)])]))

    def test_noncanonical_addresses_and_cidrs_are_not_silently_normalized(self):
        for address in ("010.0.0.1", "2001:DB8::1", "fe80::1%2", "hostname.test", "10.0.0.1/32"):
            self.deny_before_hash(model(flows=[flow(source_ip=address)]))
        for cidr in (
            "10.0.0.1/24",
            "10.0.0.0/255.255.255.0",
            "2001:DB8::/64",
            "0.0.0.0",
            "*",
            "VirtualNetwork",
        ):
            self.deny_before_hash(
                model([group(rules=[rule(predicate=predicate(source_cidrs=[cidr]))])])
            )
        self.deny_before_hash(model(flows=[flow(destination_ip="2001:db8::1")]))

    def test_range_shapes_reversal_duplicates_and_port_aliases_are_denied(self):
        for ranges in (
            [],
            [[2, 1]],
            [[0, 65536]],
            [[True, 2]],
            [[1.0, 2]],
            [[1, 2, 3]],
            [[1, 2], [1, 2]],
            [(1, 2)],
        ):
            self.deny_before_hash(
                model([group(rules=[rule(predicate=predicate(source_ports=ranges))])])
            )
        for port in (-1, 65536, True, 1.0, "1", None):
            self.deny_before_hash(model(flows=[flow(source_port=port)]))

    def test_native_schema_bool_and_completeness_int_aliases_fail(self):
        for version in (True, 1.0, "1", 2):
            value = model()
            value["schema_version"] = version
            self.deny_before_hash(value)
        for flag in (0, 1, "true", None):
            self.deny_before_hash(model(complete=flag))
            self.deny_before_hash(model([group(complete=flag)]))

    def test_native_subclasses_and_unsupported_collections_are_denied_before_copy(self):
        class DictAlias(dict):
            def items(self):
                raise AssertionError("Subclass hook must not run")

        class StringAlias(str):
            pass

        class IntegerAlias(int):
            pass

        for value in (
            DictAlias(model()),
            {**model(), "flows": tuple(model()["flows"])},
            {**model(), "schema_version": IntegerAlias(1)},
            model(flows=[flow(flow_id=StringAlias("packet"))]),
        ):
            with patch.object(nsg, "_clone") as clone:
                self.deny_before_hash(value)
                clone.assert_not_called()

    def test_unknown_fields_float_and_nonfinite_inputs_fail_before_hash(self):
        for field in ("credential", "endpoint", "clock", "provider", "callback"):
            self.deny_before_hash({**model(), field: "not-used"})
        for bad in (float("inf"), float("nan"), 0.0):
            self.deny_before_hash({**model(), "schema_version": bad})

    def test_cycles_shared_graphs_and_pending_children_deny_before_serialization(self):
        cyclic = []
        cyclic.append(cyclic)
        shared = [0]
        for _ in range(16):
            shared = [shared, shared]
        for value in (cyclic, shared, [None] * nsg.MAX_MODEL_NODES):
            with patch.object(nsg.json, "dumps") as encoder:
                self.deny_before_hash(value)
                encoder.assert_not_called()

    def test_native_exact_depth_nodes_strings_and_escaping_measure(self):
        budget = nsg._Budget()
        escaped = {"x": 'a"\\b'}
        size, nodes = nsg._measure(escaped, budget)
        self.assertEqual(size, len(canonical(escaped)))
        self.assertEqual(nodes, 3)
        with patch.object(nsg, "MAX_MODEL_NODES", 3), patch.object(nsg, "MAX_NATIVE_DEPTH", 2):
            nsg._measure(escaped, nsg._Budget())
        with patch.object(nsg, "MAX_MODEL_NODES", 2), self.assertRaises(ERROR):
            nsg._measure(escaped, nsg._Budget())
        with patch.object(nsg, "MAX_NATIVE_DEPTH", 1), self.assertRaises(ERROR):
            nsg._measure(escaped, nsg._Budget())
        value = "a" * nsg.MAX_STRING_BYTES
        nsg._measure(value, nsg._Budget())
        with self.assertRaises(ERROR):
            nsg._measure(value + "a", nsg._Budget())
        with patch.object(nsg, "MAX_MODEL_BYTES", size):
            nsg._measure(escaped, nsg._Budget())
        with patch.object(nsg, "MAX_MODEL_BYTES", size - 1), self.assertRaises(ERROR):
            nsg._measure(escaped, nsg._Budget())

    def test_count_and_atom_ceiling_controls(self):
        rules = [rule(str(index), 100 + index) for index in range(nsg.MAX_RULES_PER_NSG)]
        self.assertEqual(
            outcome(model([group(rules=rules)]))["layers"][0]["candidate_priority"], 100
        )
        self.deny_before_hash(model([group(rules=[*rules, rule("extra", 1000)])]))
        atoms = [f"10.0.0.{index}/32" for index in range(nsg.MAX_PREDICATE_ATOMS)]
        self.assertEqual(
            outcome(model([group(rules=[rule(predicate=predicate(source_cidrs=atoms))])]))[
                "decision"
            ],
            "allow_under_supplied_nsg_predicates",
        )
        self.deny_before_hash(
            model([group(rules=[rule(predicate=predicate(source_cidrs=[*atoms, "10.0.0.64/32"]))])])
        )
        with patch.object(nsg, "MAX_TOTAL_RULES", 1):
            self.deny_before_hash(model([group(rules=[rule(), rule("other", 200)])]))
        self.deny_before_hash(
            model([group(str(index)) for index in range(nsg.MAX_NSGS + 1)], subnet_nsg_id="0")
        )
        self.deny_before_hash(model(flows=[flow(str(index)) for index in range(nsg.MAX_FLOWS + 1)]))

    def test_raw_native_bytes_whitespace_and_roundtrip_are_equivalent(self):
        value = model()
        expected = document(value)
        for raw in (canonical(value).encode("ascii"), json.dumps(value, indent=2).encode("ascii")):
            self.assertEqual(
                nsg.analyze_supplied_azure_nsg_bytes(model_bytes=raw).to_dict(), expected
            )
        record = nsg.AzureNsgAnalysis.from_json(json.dumps(expected, indent=2))
        self.assertEqual(record.to_dict(), expected)
        self.assertEqual(nsg.AzureNsgAnalysis.from_dict(expected).to_json(), canonical(expected))

    def test_raw_duplicate_fields_are_denied_in_model_and_report(self):
        for raw in (
            '{"schema_version":1,"schema_version":1,"nsgs":[],"attachments":{},"flows":[]}',
            '{"x":{"a":1,"a":2}}',
        ):
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg_bytes(model_bytes=raw.encode("ascii"))
        report = canonical(document())
        report = report.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
        with self.assertRaises(ERROR):
            nsg.AzureNsgAnalysis.from_json(report)

    def test_raw_malformed_integers_floats_escapes_and_magnitude_predecoder(self):
        for token in (
            "--1",
            "---1",
            "+1",
            "01",
            "1.0",
            "1e2",
            "NaN",
            "Infinity",
            str(2**63),
            str(-(2**63) - 1),
            "9" * 100,
        ):
            self.deny_before_decoder('{"schema_version":' + token + "}")
        for raw in (
            '{"x":"\\u0000"}',
            '{"x":"\\ud800"}',
            '{"x":"\\n"}',
            '{"x":"\\u002"}',
            '{"x":"\\z"}',
            '{"x":"' + "a" * (nsg.MAX_STRING_BYTES + 1) + '"}',
        ):
            self.deny_before_decoder(raw)

    def test_raw_depth_nodes_and_byte_limits_before_decoder(self):
        self.deny_before_decoder("[" * nsg.MAX_NATIVE_DEPTH + "0" + "]" * nsg.MAX_NATIVE_DEPTH)
        with patch.object(nsg, "MAX_REPORT_NODES", 2):
            self.deny_before_decoder('{"x":0}')
        with patch.object(nsg, "MAX_REPORT_BYTES", 2):
            self.deny_before_decoder("[0]")
        for raw in (b"\xff", bytearray(b"{}"), memoryview(b"{}"), b"", "{}"):
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg_bytes(model_bytes=raw)

    def test_raw_work_is_reserved_before_decode_or_copy(self):
        with (
            patch.object(nsg, "MAX_WORK", 1),
            patch.object(nsg.json, "loads") as decoder,
            patch.object(nsg, "_address") as address,
        ):
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg_bytes(model_bytes=canonical(model()).encode("ascii"))
            decoder.assert_not_called()
            address.assert_not_called()

    def test_signed64_magnitude_denied_before_integer_conversion(self):
        class ProbeInteger(int):
            def __str__(self):
                raise AssertionError("Subclass conversion must not run")

        for value in (2**100000, -(2**100000), ProbeInteger(1)):
            with patch.object(nsg, "_clone") as clone:
                self.deny_before_hash({"schema_version": value})
                clone.assert_not_called()

    def test_cohashed_false_decision_candidate_order_or_summary_denied(self):
        original = document()
        for change in ("decision", "candidate", "order", "summary", "uncertainty"):
            altered = copy.deepcopy(original)
            row = altered["flow_observations"][0]
            if change == "decision":
                row["decision"] = "deny_under_supplied_nsg_predicates"
            elif change == "candidate":
                row["layers"][0]["candidate_rule_id"] = "foreign"
            elif change == "order":
                row["layer_order"] = ["nic", "subnet"]
            elif change == "summary":
                altered["summary"]["allow"] = 0
            else:
                row["uncertainty"] = ["nic:rules_incomplete"]
            with self.assertRaises(ERROR):
                nsg.AzureNsgAnalysis.from_dict(readdress(altered))

    def test_cohashed_effect_and_native_false_alias_promotions_deny_before_hash(self):
        original = document()
        for category, key, bad in (
            ("flags", "reachability_proven", True),
            ("flags", "authorization_granted", 0),
            ("effects", "network", "allowed"),
            ("summary", "allow", True),
            ("bounds", "model_bytes", float(nsg.MAX_MODEL_BYTES)),
        ):
            altered = copy.deepcopy(original)
            altered[category][key] = bad
            altered = readdress(altered)
            with patch.object(nsg, "_address") as address:
                with self.assertRaises(ERROR):
                    nsg.AzureNsgAnalysis.from_dict(altered)
                address.assert_not_called()

    def test_coherent_changed_source_cannot_verify_against_original_model(self):
        original = model()
        changed = model(flows=[flow(destination_port=80)])
        report = nsg.analyze_supplied_azure_nsg(changed)
        self.assertEqual(
            nsg.AzureNsgAnalysis.from_json(report.to_json()).to_dict(), report.to_dict()
        )
        with self.assertRaises(ERROR):
            nsg.verify_supplied_azure_nsg_analysis(report, model=original)
        self.assertEqual(
            nsg.verify_supplied_azure_nsg_analysis(report, model=changed).to_dict(),
            report.to_dict(),
        )

    def test_source_and_exported_records_are_detached(self):
        original = model()
        report = nsg.analyze_supplied_azure_nsg(original)
        expected = report.to_json()
        original["nsgs"][0]["rules"][0]["access"] = "Deny"
        exported = report.to_dict()
        exported["source_model"]["nsgs"][0]["rules"][0]["access"] = "Deny"
        exported["flow_observations"][0]["decision"] = "unassessed"
        self.assertEqual(report.to_json(), expected)
        self.assertIsNot(component_fixture(), component_fixture())
        first, second = component_fixture(), component_fixture()
        first["nsgs"][0]["rules"][0]["predicate"]["source_cidrs"].clear()
        self.assertEqual(
            second["nsgs"][0]["rules"][0]["predicate"]["source_cidrs"], ["10.0.0.0/24"]
        )

    def test_forged_missing_or_mutated_wrapper_storage_fails_full_replay(self):
        for value in (None, {}, "not-json", object()):
            forged = object.__new__(nsg.AzureNsgAnalysis)
            if value is not None:
                object.__setattr__(forged, "_document_json", value)
            with self.assertRaises(ERROR):
                forged.to_dict()
        record = nsg.analyze_supplied_azure_nsg(model())
        altered = record.to_dict()
        altered["flow_observations"][0]["decision"] = "deny_under_supplied_nsg_predicates"
        object.__setattr__(record, "_document_json", canonical(readdress(altered)))
        for operation in (record.to_dict, record.to_json, lambda: record.analysis_id):
            with self.assertRaises(ERROR):
                operation()

    def test_wrong_family_and_unknown_report_fields_are_denied(self):
        with self.assertRaises(ERROR):
            nsg.verify_supplied_azure_nsg_analysis(document(), model=model())
        altered = document()
        altered["extra"] = False
        with self.assertRaises(ERROR):
            nsg.AzureNsgAnalysis.from_dict(readdress(altered))

    def test_full_output_and_work_budget_fail_before_first_digest(self):
        value = model()
        budget = nsg._Budget()
        plan = nsg._prepare(value, budget)
        nsg._seal([plan], budget, [None])
        needed = budget.used
        charge = nsg._Budget.charge

        def one_below(instance, amount):
            if instance.used + amount > needed - 1:
                raise ERROR("Test operation work ceiling exhausted")
            charge(instance, amount)

        with (
            patch.object(nsg._Budget, "charge", one_below),
            patch.object(nsg, "_address") as address,
        ):
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg(value)
            address.assert_not_called()
        report_size = len(canonical(document(value)))
        # Lowering the declared constant also shortens the report's bounds metadata.
        # The 100-byte margin exercises final output refusal without a moving one-byte target.
        with (
            patch.object(nsg, "MAX_REPORT_BYTES", report_size - 100),
            patch.object(nsg, "_address") as address,
        ):
            with self.assertRaises(ERROR):
                nsg.analyze_supplied_azure_nsg(value)
            address.assert_not_called()

    def test_replay_export_and_separate_verification_share_one_budget(self):
        value = model()
        record = nsg.analyze_supplied_azure_nsg(value)
        original_document = document(value)
        samples = []
        actual = nsg._Budget.charge

        def counted(instance, amount):
            actual(instance, amount)
            samples.append(instance)

        for operation in (
            lambda: nsg.AzureNsgAnalysis.from_dict(original_document),
            record.to_dict,
            record.to_json,
            lambda: nsg.verify_supplied_azure_nsg_analysis(record, model=value),
        ):
            samples.clear()
            with patch.object(nsg._Budget, "charge", counted):
                operation()
            self.assertEqual(len({id(sample) for sample in samples}), 1)
        samples.clear()
        with patch.object(nsg._Budget, "charge", counted):
            nsg.verify_supplied_azure_nsg_analysis(record, model=value)
        self.assertEqual(len({id(sample) for sample in samples}), 1)

    def test_each_public_replay_cost_ceiling_is_reserved_before_any_hash(self):
        value = model()
        record = nsg.analyze_supplied_azure_nsg(value)
        original_document = record.to_dict()
        original_text = canonical(original_document)
        raw_model = canonical(value).encode("ascii")
        charge = nsg._Budget.charge
        for operation in (
            lambda: nsg.analyze_supplied_azure_nsg_bytes(model_bytes=raw_model),
            lambda: nsg.AzureNsgAnalysis.from_dict(original_document),
            lambda: nsg.AzureNsgAnalysis.from_json(original_text),
            record.to_dict,
            record.to_json,
            lambda: nsg.verify_supplied_azure_nsg_analysis(record, model=value),
        ):
            samples = []

            def counted(instance, amount, target=samples):
                charge(instance, amount)
                target.append(instance)

            with patch.object(nsg._Budget, "charge", counted):
                operation()
            self.assertEqual(len({id(sample) for sample in samples}), 1)
            needed = samples[0].used

            def one_below(instance, amount, ceiling=needed - 1):
                if instance.used + amount > ceiling:
                    raise ERROR("Test operation work ceiling exhausted")
                charge(instance, amount)

            with (
                patch.object(nsg._Budget, "charge", one_below),
                patch.object(nsg, "_address") as address,
                self.assertRaises(ERROR),
            ):
                operation()
            address.assert_not_called()

    def test_separate_original_cost_and_output_rejected_before_any_hash(self):
        record = nsg.analyze_supplied_azure_nsg(model())
        oversized = model(flows=[flow(str(index)) for index in range(nsg.MAX_FLOWS + 1)])
        with patch.object(nsg, "_address") as address:
            with self.assertRaises(ERROR):
                nsg.verify_supplied_azure_nsg_analysis(record, model=oversized)
            address.assert_not_called()

    def test_all_proof_flags_false_effects_none_and_existing_ownership(self):
        result = document()
        self.assertTrue(
            all(type(value) is bool and value is False for value in result["flags"].values())
        )
        self.assertTrue(
            all(type(value) is str and value == "none" for value in result["effects"].values())
        )
        self.assertEqual(result["profile_id"], "AOE-GC-D14-S05")
        self.assertEqual(result["capability_id"], "army.gc.d14.s05")
        self.assertEqual(result["vector_id"], "AV-GC-D14-S05-01")
        self.assertEqual(result["work_package_id"], "IWP2-AOE-GC-D14-S05")
        self.assertEqual(result["wave_id"], "IW2-008")
        self.assertEqual(result["commander_id"], "AOE-GC-D14-CMD")
        self.assertEqual(result["group_owner_id"], "AOE-HQ-05")
        self.assertEqual(result["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(
            result["blueprint_sha256"],
            "sha256:8e08953c3b08ca3bbf9eafee8f429ff727ec444c8104d2bf11141d8d6f492ec9",
        )


if __name__ == "__main__":
    unittest.main()
