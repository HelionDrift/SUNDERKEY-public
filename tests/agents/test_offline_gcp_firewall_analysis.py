"""Independent supplied-rule worlds, packet grids, bounded costs and exact replay."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_gcp_firewall_analysis as gcp

ERROR = gcp.GcpFirewallAnalysisError
ALLOW = "allow_under_supplied_vpc_predicates"
DENY = "deny_under_supplied_vpc_predicates"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def predicate(**changes):
    return {
        "kind": "cidr_protocol_ports",
        "protocol": "all",
        "source_cidrs": ["0.0.0.0/0"],
        "destination_cidrs": ["0.0.0.0/0"],
        "destination_ports": [],
        **changes,
    }


def rule(identifier="allow", priority=100, action="allow", direction="INGRESS", **changes):
    return {
        "rule_id": identifier,
        "network_id": "network",
        "direction": direction,
        "disabled": False,
        "priority": priority,
        "action": action,
        "targets": {"kind": "all"},
        "predicate": predicate(),
        **changes,
    }


def flow(identifier="query", **changes):
    return {
        "flow_id": identifier,
        "network_id": "network",
        "target_id": "nic",
        "direction": "INGRESS",
        "protocol": "tcp",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.1.2",
        "destination_port": 443,
        **changes,
    }


def model(rules=None, flows=None, **changes):
    return {
        "schema_version": 1,
        "network_id": "network",
        "rules_complete": True,
        "traffic_kind": "new_flow",
        "rules": [rule()] if rules is None else rules,
        "flows": [flow()] if flows is None else flows,
        **changes,
    }


def document(value=None):
    return gcp.analyze_supplied_gcp_firewall(model() if value is None else value).to_dict()


def observe(value):
    return document(value)["flow_observations"][0]


def readdress(value):
    body = copy.deepcopy(value)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-gcp-firewall-analysis.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "GCFA-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


def world_result(known, uncertain, switches):
    present = known + [item for item, enabled in zip(uncertain, switches, strict=True) if enabled]
    if not present:
        return None, set()
    priority = min(item["priority"] for item in present)
    tied = [item for item in present if item["priority"] == priority]
    action = "deny" if any(item["action"] == "deny" for item in tied) else "allow"
    return action, {item["rule_id"] for item in tied if item["action"] == action}


class GcpFirewallAnalysisTests(unittest.TestCase):
    def deny_before_hash(self, value):
        with (
            patch.object(gcp, "_address") as address,
            patch.object(gcp.hashlib, "sha256") as digest,
        ):
            with self.assertRaises(ERROR):
                gcp.analyze_supplied_gcp_firewall(value)
            address.assert_not_called()
            digest.assert_not_called()

    def deny_before_decoder(self, text):
        with patch.object(gcp.json, "loads") as decoder, patch.object(gcp, "_address") as address:
            with self.assertRaises(ERROR):
                gcp.GcpFirewallAnalysis.from_json(text)
            decoder.assert_not_called()
            address.assert_not_called()

    def test_fixture_matches_independent_source_and_report_address_oracles(self):
        value = gcp.component_fixture()
        result = document(value)
        self.assertEqual(result["analysis_id"], "GCFA-8E3869008A986AF8D276431ADA36B8A3")
        self.assertEqual(
            result["analysis_sha256"],
            "sha256:8e3869008a986af8d276431ada36b8a39dc0929f593c8abd7bf1edad3543fe86",
        )
        self.assertEqual(
            result["source_model_sha256"],
            "sha256:5c9cfab6bd6d73292c098d1e5440967ac6ff73a48964e9c557c4e8b26e8c9806",
        )
        self.assertEqual(readdress(result), result)
        source = hashlib.sha256(
            b"sunderkey.offline-gcp-firewall-model.v1\n" + canonical(value).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["source_model_sha256"], "sha256:" + source)
        self.assertNotEqual(result["source_model_sha256"], result["analysis_sha256"])
        self.assertEqual(
            [row["decision"] for row in result["flow_observations"]], [ALLOW, "unassessed"]
        )
        self.assertEqual(
            result["flow_observations"][0]["winning_rule_ids"], ["ingress-one", "ingress-two"]
        )
        self.assertTrue(result["flow_observations"][0]["winning_witnesses_complete"])
        self.assertEqual(
            result["flow_observations"][1]["possible_rules"][0]["reasons"], ["target_tag"]
        )
        self.assertEqual(result["summary"], {"flows": 2, "allow": 1, "deny": 0, "unassessed": 1})

    def test_lowest_priority_not_deny_overrides_or_array_order(self):
        for first, second in (("allow", "deny"), ("deny", "allow")):
            for rules in (
                [rule("earlier", 0, first), rule("later", 65535, second)],
                [rule("later", 65535, second), rule("earlier", 0, first)],
            ):
                row = observe(model(rules))
                self.assertEqual(row["decision"], first + "_under_supplied_vpc_predicates")
                self.assertEqual(row["candidate_priority"], 0)
                self.assertEqual(row["winning_rule_ids"], ["earlier"])

    def test_equal_priority_deny_and_all_known_witnesses(self):
        rules = [
            rule("allow-z", action="allow"),
            rule("deny-z", action="deny"),
            rule("deny-a", action="deny"),
            rule("allow-a", action="allow"),
        ]
        for permutation in itertools.permutations(rules):
            row = observe(model(list(permutation)))
            self.assertEqual(row["decision"], DENY)
            self.assertEqual(row["winning_rule_ids"], ["deny-a", "deny-z"])
            self.assertEqual(
                [item["rule_id"] for item in row["matched_rules"]],
                ["allow-a", "allow-z", "deny-a", "deny-z"],
            )
            self.assertTrue(row["winning_witnesses_complete"])

    def test_equal_same_action_retains_every_winner(self):
        for action in ("allow", "deny"):
            row = observe(model([rule("z", action=action), rule("a", action=action)]))
            self.assertEqual(row["winning_rule_ids"], ["a", "z"])
            self.assertTrue(row["winning_witnesses_complete"])

    def test_independent_unknown_world_oracle_and_witness_completeness(self):
        for known_action, first, second, priority in itertools.product(
            (None, "allow", "deny"),
            (None, "allow", "deny"),
            (None, "allow", "deny"),
            (50, 100, 150),
        ):
            known = [] if known_action is None else [rule("known", 100, known_action)]
            uncertain = [
                rule(
                    identifier,
                    priority,
                    action,
                    predicate={"kind": "unsupported", "reason": "protocol"},
                )
                for identifier, action in (("unknown-a", first), ("unknown-b", second))
                if action is not None
            ]
            row = observe(model(known + uncertain))
            worlds = [
                world_result(known, uncertain, switches)
                for switches in itertools.product((False, True), repeat=len(uncertain))
            ]
            if row["decision"] != "unassessed":
                reported = row["decision"].split("_", 1)[0]
                self.assertTrue(all(action == reported for action, _ in worlds))
                self.assertTrue(all(set(row["winning_rule_ids"]) <= ids for _, ids in worlds))
                if row["winning_witnesses_complete"]:
                    self.assertTrue(all(set(row["winning_rule_ids"]) == ids for _, ids in worlds))
            else:
                self.assertEqual(row["winning_rule_ids"], [])
                self.assertFalse(row["winning_witnesses_complete"])

    def test_unknown_tie_deny_certainty_is_not_witness_completeness(self):
        for uncertain_action in ("allow", "deny"):
            unknown = rule(
                "unknown",
                action=uncertain_action,
                targets={"kind": "unsupported", "reason": "target_tag"},
            )
            row = observe(model([unknown, rule("known", action="deny")]))
            self.assertEqual(row["decision"], DENY)
            self.assertEqual(row["winning_rule_ids"], ["known"])
            self.assertEqual(row["winning_witnesses_complete"], uncertain_action == "allow")
            self.assertEqual(row["possible_rules"][0]["rule_id"], "unknown")

    def test_unknown_allow_tie_and_native_witness_completeness_are_exact(self):
        for action, expected in (("allow", ALLOW), ("deny", "unassessed")):
            row = observe(
                model(
                    [
                        rule("known"),
                        rule(
                            "unknown",
                            action=action,
                            targets={"kind": "unsupported", "reason": "target_service_account"},
                        ),
                    ]
                )
            )
            self.assertEqual(row["decision"], expected)
            self.assertFalse(row["winning_witnesses_complete"])
            self.assertEqual(row["winning_rule_ids"], ["known"] if action == "allow" else [])
        original = document()
        for bad in (0, 1, 0.0, "true", None):
            changed = copy.deepcopy(original)
            changed["flow_observations"][0]["winning_witnesses_complete"] = bad
            changed = readdress(changed)
            with patch.object(gcp, "_address") as address:
                with self.assertRaises(ERROR):
                    gcp.GcpFirewallAnalysis.from_dict(changed)
                address.assert_not_called()

    def test_unknown_earlier_withholds_even_if_later_same_action(self):
        for action in ("allow", "deny"):
            row = observe(
                model(
                    [
                        rule(
                            "unknown",
                            1,
                            action,
                            predicate={"kind": "unsupported", "reason": "source_tag"},
                        ),
                        rule("known", 2, action),
                    ]
                )
            )
            self.assertEqual(row["decision"], "unassessed")
            self.assertEqual(row["candidate_priority"], 1)
            self.assertEqual(row["matched_rules"], [])

    def test_unknown_target_or_predicate_can_have_known_nonmatch(self):
        for known_part in ("target", "protocol", "source", "destination", "port"):
            unknown = rule("unknown", 0, predicate={"kind": "unsupported", "reason": "protocol"})
            if known_part == "target":
                unknown["targets"] = {"kind": "declared_ids", "target_ids": ["other"]}
            else:
                unknown["targets"] = {"kind": "unsupported", "reason": "target_tag"}
                changes = {
                    "protocol": {"protocol": "udp"},
                    "source": {"source_cidrs": ["192.0.2.0/24"]},
                    "destination": {"destination_cidrs": ["192.0.2.0/24"]},
                    "port": {"protocol": "tcp", "destination_ports": [[80, 80]]},
                }
                unknown["predicate"] = predicate(**changes[known_part])
            row = observe(model([unknown, rule("known", 100)]))
            self.assertEqual(row["decision"], ALLOW)
            self.assertEqual(row["winning_rule_ids"], ["known"])

    def test_disabled_and_other_direction_rules_do_not_create_uncertainty(self):
        for changes in ({"disabled": True}, {"direction": "EGRESS"}):
            unknown = rule(
                "unknown", 0, predicate={"kind": "unsupported", "reason": "protocol"}, **changes
            )
            self.assertEqual(observe(model([unknown, rule()]))["decision"], ALLOW)
        self.assertEqual(
            observe(model([rule(direction="EGRESS")], [flow(direction="EGRESS")]))["decision"],
            ALLOW,
        )

    def test_incomplete_projection_withholds_all_conclusions(self):
        for action in ("allow", "deny"):
            row = observe(model([rule(action=action)], rules_complete=False))
            self.assertEqual(row["decision"], "unassessed")
            self.assertEqual(row["reason"], "rule_projection_incomplete")
            self.assertEqual(row["matched_rules"], [])
            self.assertEqual(row["possible_rules"], [])
            self.assertIsNone(row["candidate_priority"])

    def test_no_match_or_empty_rules_does_not_invent_implied_actions(self):
        for direction in ("INGRESS", "EGRESS"):
            for rules in ([], [rule(disabled=True)]):
                row = observe(model(rules, [flow(direction=direction)]))
                self.assertEqual(row["decision"], "unassessed")
                self.assertEqual(row["reason"], "no_supplied_match")

    def test_packet_set_oracle_source_destination_in_both_directions(self):
        allowed_sources = {"10.0.0.0", "10.0.0.255", "192.0.2.1"}
        allowed_destinations = {"10.0.1.0", "10.0.1.255"}
        for direction in ("INGRESS", "EGRESS"):
            pred = predicate(
                protocol="tcp",
                source_cidrs=["10.0.0.0/24", "192.0.2.1/32"],
                destination_cidrs=["10.0.1.0/24"],
                destination_ports=[[80, 81], [443, 443]],
            )
            rules = [
                rule("specific", 100, direction=direction, predicate=pred),
                rule("fallback", 200, "deny", direction),
            ]
            packets = [
                flow(
                    "f-" + str(i),
                    direction=direction,
                    protocol=protocol,
                    source_ip=source,
                    destination_ip=destination,
                    destination_port=port,
                )
                for i, (protocol, source, destination, port) in enumerate(
                    itertools.product(
                        ("tcp", "udp"),
                        ("10.0.0.0", "10.0.0.255", "10.0.2.1", "192.0.2.1"),
                        ("10.0.1.0", "10.0.1.255", "10.0.2.1"),
                        (79, 80, 81, 443),
                    )
                )
            ]
            for start in range(0, len(packets), 64):
                part = packets[start : start + 64]
                rows = document(model(rules, part))["flow_observations"]
                for packet, row in zip(part, rows, strict=True):
                    allowed = (
                        packet["protocol"] == "tcp"
                        and packet["source_ip"] in allowed_sources
                        and packet["destination_ip"] in allowed_destinations
                        and packet["destination_port"] in {80, 81, 443}
                    )
                    self.assertEqual(row["decision"], ALLOW if allowed else DENY)

    def test_ipv6_family_coherence_and_literal_boundary_controls(self):
        pred = predicate(source_cidrs=["2001:db8::/32"], destination_cidrs=["2001:db8:1::/64"])
        for source, destination, expected in (
            ("2001:db8::", "2001:db8:1::", ALLOW),
            ("2001:db8:ffff::", "2001:db8:1::ffff", ALLOW),
            ("2001:db9::", "2001:db8:1::", "unassessed"),
            ("2001:db8::", "2001:db8:2::", "unassessed"),
        ):
            self.assertEqual(
                observe(
                    model(
                        [rule(predicate=pred)], [flow(source_ip=source, destination_ip=destination)]
                    )
                )["decision"],
                expected,
            )
        self.deny_before_hash(model([rule(predicate=predicate(source_cidrs=["::/0"]))]))
        self.deny_before_hash(
            model([rule(predicate=predicate(source_cidrs=["0.0.0.0/0", "::/0"]))])
        )
        self.deny_before_hash(model(flows=[flow(destination_ip="::1")]))

    def test_declared_target_set_is_not_a_tag_or_nic_resolver(self):
        for target, expected in (("nic", ALLOW), ("other", "unassessed")):
            row = observe(
                model(
                    [rule(targets={"kind": "declared_ids", "target_ids": ["nic"]})],
                    [flow(target_id=target)],
                )
            )
            self.assertEqual(row["decision"], expected)
        for reason in ("target_tag", "target_service_account", "other_target"):
            row = observe(model([rule(targets={"kind": "unsupported", "reason": reason})]))
            self.assertEqual(row["possible_rules"][0]["reasons"], [reason])

    def test_destination_port_inclusive_boundaries_and_empty_any(self):
        for protocol in ("tcp", "udp"):
            for port in (0, 79, 80, 81, 82, 65535):
                pred = predicate(protocol=protocol, destination_ports=[[80, 81]])
                self.assertEqual(
                    observe(
                        model(
                            [rule(predicate=pred)], [flow(protocol=protocol, destination_port=port)]
                        )
                    )["decision"],
                    ALLOW if 80 <= port <= 81 else "unassessed",
                )
                self.assertEqual(
                    observe(
                        model(
                            [rule(predicate=predicate(protocol=protocol))],
                            [flow(protocol=protocol, destination_port=port)],
                        )
                    )["decision"],
                    ALLOW,
                )
        self.deny_before_hash(model([rule(predicate=predicate(destination_ports=[[80, 80]]))]))
        bad = model()
        bad["rules"][0]["predicate"]["source_ports"] = [[0, 65535]]
        self.deny_before_hash(bad)

    def test_priority_integer_and_native_bool_boundaries(self):
        for priority in (0, 1, 65534, 65535):
            self.assertEqual(
                observe(model([rule(priority=priority)]))["candidate_priority"], priority
            )
        for priority in (-1, 65536, True, 1.0, None):
            self.deny_before_hash(model([rule(priority=priority)]))
        for disabled in (0, 1, None, "false"):
            self.deny_before_hash(model([rule(disabled=disabled)]))
        for complete in (0, 1, None):
            self.deny_before_hash(model(rules_complete=complete))

    def test_duplicate_rule_flow_and_network_rebinding_denied(self):
        self.deny_before_hash(model([rule(), rule()]))
        self.deny_before_hash(model(flows=[flow(), flow()]))
        self.deny_before_hash(model([rule(network_id="foreign")]))
        self.deny_before_hash(model(flows=[flow(network_id="foreign")]))
        self.deny_before_hash(model(traffic_kind="existing_connection"))

    def test_malformed_native_arrays_and_scalar_membership_fail_domain(self):
        for bad in (None, {}, "rules", (rule(),)):
            value = model()
            value["rules"] = bad
            self.deny_before_hash(value)
        for field in ("action", "direction"):
            for bad in ([], {}, True, None):
                self.deny_before_hash(model([rule(**{field: bad})]))
        for field in ("kind", "protocol"):
            for bad in ([], {}, True, None):
                self.deny_before_hash(model([rule(predicate=predicate(**{field: bad}))]))
        for bad in (None, [], {}, {"kind": []}, {"kind": "all", "target_ids": []}):
            self.deny_before_hash(model([rule(targets=bad)]))

    def test_empty_duplicate_and_overlimit_atoms_reject(self):
        for targets in ([], ["nic", "nic"], ["x" + str(i) for i in range(65)]):
            self.deny_before_hash(
                model([rule(targets={"kind": "declared_ids", "target_ids": targets})])
            )
        for ranges in ([], ["0.0.0.0/0", "0.0.0.0/0"], ["10.0.0.0/24"] * 65):
            self.deny_before_hash(model([rule(predicate=predicate(source_cidrs=ranges))]))
        for ports in ([[1, 0]], [[True, 1]], [[0, 65536]], [[1, 1.0]], [[1, 1], [1, 1]]):
            self.deny_before_hash(
                model([rule(predicate=predicate(protocol="tcp", destination_ports=ports))])
            )

    def test_noncanonical_ips_cidrs_ids_and_unsupported_shapes_reject(self):
        for source in ("10.0.0.01", "2001:DB8::1", "::1%nic", "host.invalid"):
            self.deny_before_hash(model(flows=[flow(source_ip=source)]))
        for source in ("10.0.0.1/24", "10.0.0.0/255.255.255.0", "2001:DB8::/32"):
            self.deny_before_hash(model([rule(predicate=predicate(source_cidrs=[source]))]))
        self.deny_before_hash(model([rule("x" * 65)]))
        self.deny_before_hash(model([rule(predicate={"kind": "unsupported", "reason": "guessed"})]))
        self.deny_before_hash(model([rule(predicate=predicate(protocol="icmp"))]))
        self.deny_before_hash(model(flows=[flow(protocol="icmp")]))

    def test_unknown_fields_and_schema_numeric_aliases_reject(self):
        for version in (True, 1.0, "1", None):
            self.deny_before_hash(model(schema_version=version))
        value = model()
        value["metadata"] = {}
        self.deny_before_hash(value)
        value = model()
        value["flows"][0]["source_port"] = 1234
        self.deny_before_hash(value)

    def test_native_aliases_do_not_enter_clone_or_conversion_hooks(self):
        class StringAlias(str):
            def __str__(self):
                raise AssertionError("Alias hook must not run")

        class IntegerAlias(int):
            def __str__(self):
                raise AssertionError("Alias hook must not run")

        class DictAlias(dict):
            pass

        class ListAlias(list):
            pass

        for value in (
            DictAlias(model()),
            model(network_id=StringAlias("network")),
            model(schema_version=IntegerAlias(1)),
            model(flows=ListAlias([flow()])),
        ):
            with patch.object(gcp, "_clone") as clone:
                self.deny_before_hash(value)
                clone.assert_not_called()

    def test_native_cycles_repeated_subtrees_depth_escaping_and_pending_nodes(self):
        cyclic = model()
        cyclic["flows"].append(cyclic)
        self.deny_before_hash(cyclic)
        for value in (2**100000, -(2**100000), float("nan")):
            with patch.object(gcp, "_clone") as clone:
                self.deny_before_hash({"schema_version": value})
                clone.assert_not_called()
        shared = ["x" * 512] * 64
        with patch.object(gcp, "MAX_MODEL_BYTES", 1024), patch.object(gcp.json, "dumps") as encoder:
            self.deny_before_hash([shared] * 4)
            encoder.assert_not_called()
        with patch.object(gcp, "MAX_MODEL_NODES", 4), patch.object(gcp, "_clone") as clone:
            self.deny_before_hash([0] * 4)
            clone.assert_not_called()
        deep = "x"
        for _ in range(16):
            deep = [deep]
        self.deny_before_hash(deep)
        budget = gcp._Budget()
        self.assertEqual(gcp._measure(['a\\"'], budget)[0], len(canonical(['a\\"'])))
        for text in (chr(127), "\n", "\u00a0"):
            self.deny_before_hash({"x": text})

    def test_rule_flow_and_atom_caps_are_software_not_negative_findings(self):
        self.deny_before_hash(model([rule("r" + str(i)) for i in range(257)]))
        self.deny_before_hash(model(flows=[flow("f" + str(i)) for i in range(129)]))
        rules = [rule("r" + str(i), 100, "deny") for i in range(256)]
        row = observe(model(rules))
        self.assertEqual(len(row["winning_rule_ids"]), 256)

    def test_raw_native_canonical_whitespace_and_ascii_escapes_match(self):
        value = model()
        expected = document(value)
        for text in (
            canonical(value),
            json.dumps(value, indent=2),
            canonical(value).replace("network", "\\u006eetwork"),
        ):
            result = gcp.analyze_supplied_gcp_firewall_bytes(model_bytes=text.encode("ascii"))
            self.assertEqual(result.to_dict(), expected)
        report = gcp.GcpFirewallAnalysis.from_json(json.dumps(expected, indent=2))
        self.assertEqual(report.to_dict(), expected)

    def test_raw_duplicate_members_and_exact_bytes_intake(self):
        for text in ('{"schema_version":1,"schema_version":1}', '{"x":{"a":0,"a":0}}'):
            with patch.object(gcp, "_address") as address:
                with self.assertRaises(ERROR):
                    gcp.GcpFirewallAnalysis.from_json(text)
                address.assert_not_called()
        for value in (b"", b"\xff", bytearray(b"{}"), memoryview(b"{}"), "{}"):
            with self.assertRaises(ERROR):
                gcp.analyze_supplied_gcp_firewall_bytes(model_bytes=value)

    def test_raw_integer_grammar_magnitude_and_alias_controls_predecoder(self):
        for token in (
            "--1",
            "---1",
            "00",
            "01",
            "-01",
            "+1",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "1" * 10000,
        ):
            self.deny_before_decoder('{"schema_version":' + token + "}")
        for integer in (-(2**63), 2**63 - 1):
            self.assertEqual(gcp._integer(str(integer)), integer)
        for token in ("true", "1"):
            with patch.object(gcp, "_address") as address:
                with self.assertRaises(ERROR):
                    gcp.GcpFirewallAnalysis.from_json('{"schema_version":' + token + "}")
                address.assert_not_called()

    def test_raw_string_depth_pending_nodes_and_bytes_before_decoder(self):
        for text in (
            '{"x":"\\u007f"}',
            '{"x":"\\ud800"}',
            '{"x":"\\n"}',
            '{"x":"\\u002"}',
            '{"x":"' + "a" * 513 + '"}',
            "[" * 16 + "0" + "]" * 16,
        ):
            self.deny_before_decoder(text)
        with patch.object(gcp, "MAX_REPORT_NODES", 2):
            self.deny_before_decoder('{"x":0}')
        with patch.object(gcp, "MAX_REPORT_BYTES", 2):
            self.deny_before_decoder("[0]")

    def test_raw_decode_copy_work_is_reserved_before_decoder_or_hash(self):
        with (
            patch.object(gcp, "MAX_WORK", 1),
            patch.object(gcp.json, "loads") as decoder,
            patch.object(gcp, "_address") as address,
        ):
            with self.assertRaises(ERROR):
                gcp.analyze_supplied_gcp_firewall_bytes(
                    model_bytes=canonical(model()).encode("ascii")
                )
            decoder.assert_not_called()
            address.assert_not_called()

    def test_cohashed_false_decision_witness_priority_uncertainty_or_summary_rejects(self):
        original = document(gcp.component_fixture())
        for name in (
            "decision",
            "witness",
            "priority",
            "winning",
            "certainty",
            "uncertainty",
            "summary",
        ):
            changed = copy.deepcopy(original)
            row = changed["flow_observations"][0]
            if name == "decision":
                row["decision"] = DENY
            elif name == "witness":
                row["matched_rules"][0]["rule_id"] = "foreign"
            elif name == "priority":
                row["candidate_priority"] = 0
            elif name == "winning":
                row["winning_rule_ids"] = ["ingress-one"]
            elif name == "certainty":
                row["winning_witnesses_complete"] = False
            elif name == "uncertainty":
                changed["flow_observations"][1]["possible_rules"] = []
            else:
                changed["summary"]["deny"] = 1
            changed = readdress(changed)
            with self.assertRaises(ERROR):
                gcp.GcpFirewallAnalysis.from_dict(changed)
            with self.assertRaises(ERROR):
                gcp.GcpFirewallAnalysis.from_json(canonical(changed))

    def test_cohashed_promotions_effects_bounds_native_aliases_reject_before_hash(self):
        original = document()
        for name, key, bad in (
            ("flags", "reachability_proven", True),
            ("flags", "authorization_granted", 0),
            ("effects", "network", "allowed"),
            ("summary", "allow", True),
            ("bounds", "model_bytes", float(gcp.MAX_MODEL_BYTES)),
        ):
            changed = copy.deepcopy(original)
            changed[name][key] = bad
            changed = readdress(changed)
            with patch.object(gcp, "_address") as address:
                with self.assertRaises(ERROR):
                    gcp.GcpFirewallAnalysis.from_dict(changed)
                address.assert_not_called()

    def test_source_permutation_changes_address_not_equal_winners(self):
        rules = [rule("z"), rule("a")]
        first, second = document(model(rules)), document(model(list(reversed(rules))))
        self.assertEqual(first["flow_observations"], second["flow_observations"])
        self.assertNotEqual(first["source_model_sha256"], second["source_model_sha256"])
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])

    def test_coherent_other_source_replays_only_against_its_separate_original(self):
        original = model()
        changed = model(flows=[flow(destination_port=444)])
        report = gcp.analyze_supplied_gcp_firewall(changed)
        self.assertEqual(
            gcp.GcpFirewallAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(ERROR):
            gcp.verify_supplied_gcp_firewall_analysis(report, model=original)
        self.assertEqual(
            gcp.verify_supplied_gcp_firewall_analysis(report, model=changed).to_json(),
            report.to_json(),
        )

    def test_original_and_export_are_detached_and_fixture_fresh(self):
        original = model()
        report = gcp.analyze_supplied_gcp_firewall(original)
        expected = report.to_json()
        original["rules"][0]["action"] = "deny"
        exported = report.to_dict()
        exported["source_model"]["rules"][0]["action"] = "deny"
        exported["flow_observations"][0]["winning_rule_ids"].clear()
        self.assertEqual(report.to_json(), expected)
        first, second = gcp.component_fixture(), gcp.component_fixture()
        first["rules"][0]["predicate"]["source_cidrs"].clear()
        self.assertEqual(second["rules"][0]["predicate"]["source_cidrs"], ["10.0.0.0/24"])

    def test_forged_missing_alias_wrapper_storage_rejects_full_replay(self):
        for value in (None, {}, "not-json", "[]"):
            fake = object.__new__(gcp.GcpFirewallAnalysis)
            if value is not None:
                object.__setattr__(fake, "_document_json", value)
            with self.assertRaises(ERROR):
                fake.to_dict()
        report = gcp.analyze_supplied_gcp_firewall(model())
        changed = report.to_dict()
        changed["flow_observations"][0]["decision"] = DENY
        object.__setattr__(report, "_document_json", canonical(readdress(changed)))
        for operation in (report.to_dict, report.to_json, lambda: report.analysis_id):
            with self.assertRaises(ERROR):
                operation()

    def test_wrong_report_family_subclasses_unknown_fields_and_roundtrips(self):
        original = document()
        with self.assertRaises(ERROR):
            gcp.verify_supplied_gcp_firewall_analysis(original, model=model())

        class Subclass(gcp.GcpFirewallAnalysis):
            pass

        for operation in (
            lambda: Subclass(original),
            lambda: Subclass.from_dict(original),
            lambda: Subclass.from_json(canonical(original)),
        ):
            with self.assertRaises(ERROR):
                operation()
        changed = copy.deepcopy(original)
        changed["extra"] = None
        with self.assertRaises(ERROR):
            gcp.GcpFirewallAnalysis.from_dict(readdress(changed))
        self.assertEqual(gcp.GcpFirewallAnalysis(original).to_dict(), original)
        self.assertEqual(gcp.GcpFirewallAnalysis.from_json(canonical(original)).to_dict(), original)

    def test_all_public_passes_use_one_budget_and_reserve_exact_work_before_any_hash(self):
        value = model()
        report = gcp.analyze_supplied_gcp_firewall(value)
        original = report.to_dict()
        text = canonical(original)
        charge = gcp._Budget.charge
        for operation in (
            lambda: gcp.analyze_supplied_gcp_firewall(value),
            lambda: gcp.analyze_supplied_gcp_firewall_bytes(
                model_bytes=canonical(value).encode("ascii")
            ),
            lambda: gcp.GcpFirewallAnalysis(original),
            lambda: gcp.GcpFirewallAnalysis.from_dict(original),
            lambda: gcp.GcpFirewallAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: gcp.verify_supplied_gcp_firewall_analysis(report, model=value),
        ):
            samples = []

            def counted(instance, amount, target=samples):
                charge(instance, amount)
                target.append(instance)

            with patch.object(gcp._Budget, "charge", counted):
                operation()
            self.assertEqual(len({id(instance) for instance in samples}), 1)
            needed = samples[0].used

            def one_below(instance, amount, ceiling=needed - 1):
                if instance.used + amount > ceiling:
                    raise ERROR("Independent lowered whole-operation ceiling")
                charge(instance, amount)

            with (
                patch.object(gcp._Budget, "charge", one_below),
                patch.object(gcp, "_address") as address,
            ):
                with self.assertRaises(ERROR):
                    operation()
                address.assert_not_called()

    def test_cumulative_many_tie_outputs_deny_before_hash_not_as_rule_verdict(self):
        value = model(
            [rule("r" + str(i)) for i in range(256)], [flow("f" + str(i)) for i in range(128)]
        )
        self.assertLess(len(canonical(value)), gcp.MAX_MODEL_BYTES)
        self.assertLess(gcp._measure(value, None)[1], gcp.MAX_MODEL_NODES)
        self.deny_before_hash(value)
        smaller = model(
            [rule("r" + str(i)) for i in range(8)], [flow("f" + str(i)) for i in range(8)]
        )
        result = document(smaller)
        size, nodes = gcp._measure(result, None, report=True)
        with patch.object(gcp, "MAX_REPORT_BYTES", size - 100):
            self.deny_before_hash(smaller)
        with patch.object(gcp, "MAX_REPORT_NODES", nodes - 100):
            self.deny_before_hash(smaller)

    def test_separate_original_intake_cost_fails_before_embedded_digest(self):
        report = gcp.analyze_supplied_gcp_firewall(model())
        huge = model(flows=[flow()] * 4000)
        with patch.object(gcp, "_address") as address:
            with self.assertRaises(ERROR):
                gcp.verify_supplied_gcp_firewall_analysis(report, model=huge)
            address.assert_not_called()

    def test_platform_exempt_coordinates_are_only_predicates_not_effective_access(self):
        value = model([rule(action="deny")], [flow(destination_ip="169.254.169.254")])
        result = document(value)
        self.assertEqual(result["flow_observations"][0]["decision"], DENY)
        self.assertFalse(result["flags"]["effective_firewall_verdict_proven"])
        self.assertTrue(any("VM-self/metadata" in text for text in result["limitations"]))

    def test_exact_existing_lane_and_no_authority_or_effect_promotions(self):
        result = document()
        self.assertEqual(result["profile_id"], "AOE-GC-D14-S07")
        self.assertEqual(result["capability_id"], "army.gc.d14.s07")
        self.assertEqual(result["wave_id"], "IW2-010")
        self.assertEqual(result["commander_id"], "AOE-GC-D14-CMD")
        self.assertEqual(result["group_owner_id"], "AOE-HQ-05")
        self.assertEqual(result["independent_validator_id"], "AOE-HQ-19")
        self.assertTrue(
            all(type(value) is bool and value is False for value in result["flags"].values())
        )
        self.assertTrue(all(value == "none" for value in result["effects"].values()))


if __name__ == "__main__":
    unittest.main()
