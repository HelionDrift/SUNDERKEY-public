"""Independent name-set oracle and hostile intake for the supplied DNS subset."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_dns_zone_analysis as m


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(domain, value):
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id")
    body.pop("analysis_sha256")
    digest = _digest("sunderkey.offline-dns-zone-analysis.v1", body)
    body["analysis_id"] = "DZA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _rr(owner, rrtype="A", values=None):
    return {
        "owner": owner,
        "rrtype": rrtype,
        "rdata": ["192.0.2.10"] if values is None else values,
    }


def _query(name, rrtype="A", query_id="query:one"):
    return {"query_id": query_id, "qname": name, "qtype": rrtype}


def _model(rrsets=None, *, ordinary=None, cuts=None, queries=None, complete=True):
    return {
        "schema_version": 1,
        "semantics_profile": "single-declared-zone-lookup-v1",
        "zone": {
            "apex": "example.test.",
            "complete": complete,
            "rrsets": [] if rrsets is None else rrsets,
            "ordinary_data_owners": [] if ordinary is None else ordinary,
            "delegations": [] if cuts is None else cuts,
        },
        "queries": [_query("example.test.")] if queries is None else queries,
    }


def component_fixture():
    """Fresh public synthetic names and documentation-only addresses, no real DNS I/O."""
    return _model(
        [
            _rr("api.example.test."),
            _rr("alias.example.test.", "CNAME", ["api.example.test."]),
            _rr("*.example.test.", values=["192.0.2.20"]),
            _rr("child.example.test.", values=["192.0.2.99"]),
        ],
        ordinary=[
            {"owner": "example.test.", "rrtypes": ["SOA", "NS"]},
            {"owner": "owned.example.test.", "rrtypes": ["TXT"]},
        ],
        cuts=[{"owner": "child.example.test.", "nameservers": ["ns.child.example.test."]}],
        queries=[
            _query("alias.example.test.", query_id="query:alias"),
            _query("ghost.example.test.", query_id="query:wildcard"),
            _query("child.example.test.", query_id="query:cut"),
            _query("owned.example.test.", "AAAA", "query:ordinary"),
        ],
    )


def _is_below(name, parent):
    return name == parent or name.endswith("." + parent)


def _ancestors(name, apex):
    result = []
    labels = name[:-1].split(".")
    while labels:
        current = ".".join(labels) + "."
        result.append(current)
        if current == apex:
            return result
        labels = labels[1:]
    raise AssertionError("Oracle received an off-zone owner")


def _set_oracle(model, question):
    """Independent suffix-set lookup, with no production trie or helper reuse."""
    zone = model["zone"]
    if not zone["complete"]:
        return "incomplete", question["qname"], [], []
    cut_names = {cut["owner"] for cut in zone["delegations"]}
    data = {
        (row["owner"], row["rrtype"]): row["rdata"]
        for row in zone["rrsets"]
        if not any(_is_below(row["owner"], cut) for cut in cut_names)
    }
    owners = {owner for owner, _ in data}
    owners.update(
        row["owner"]
        for row in zone["ordinary_data_owners"]
        if not any(_is_below(row["owner"], cut) for cut in cut_names)
    )
    owners.update(cut_names)
    existing = {zone["apex"]}
    for owner in owners:
        existing.update(_ancestors(owner, zone["apex"]))
    current = question["qname"]
    seen = set()
    targets = []
    while True:
        if not _is_below(current, zone["apex"]) or current in seen:
            return "incomplete", current, [], targets
        seen.add(current)
        if any(_is_below(current, cut) for cut in cut_names):
            return "referral_in_supplied_projection", current, [], targets
        if current in existing:
            selected = current
        else:
            ancestry = _ancestors(current, zone["apex"])
            encloser = next(name for name in ancestry if name in existing)
            selected = "*." + encloser
            if selected not in existing:
                return "name_absent_in_supplied_projection", current, [], targets
        values = data.get((selected, question["qtype"]))
        if values is not None:
            return "answer_in_supplied_projection", current, values, targets
        alias = data.get((selected, "CNAME"))
        if alias is None or question["qtype"] == "CNAME":
            return "no_data_in_supplied_projection", current, [], targets
        if len(targets) == 32:
            return "incomplete", current, [], targets
        current = alias[0]
        targets.append(current)


class DnsZoneAnalysisTests(unittest.TestCase):
    def _results(self, model):
        return m.analyze_supplied_dns_zone(model).to_dict()["query_results"]

    def _one(self, model):
        return self._results(model)[0]

    def _denied(self, model):
        with self.assertRaises(m.DnsZoneAnalysisError):
            m.analyze_supplied_dns_zone(model)

    def test_fixture_literal_identity_and_independent_canonical_digest(self):
        report = m.analyze_supplied_dns_zone(component_fixture())
        document = report.to_dict()
        self.assertEqual("DZA-EF85B60D02D64FDBD374544598A749B5", document["analysis_id"])
        self.assertEqual(
            "sha256:ef85b60d02d64fdbd374544598a749b5d8815ebb52f2b4c862acbe5284f37525",
            document["analysis_sha256"],
        )
        self.assertEqual(
            "sha256:556fdad94a0961a4b53bcf6be061124aa4c66854c9c9351dfedfed543e535479",
            document["source_model_sha256"],
        )
        self.assertEqual(6, document["tree_node_count"])
        self.assertEqual(32, document["work_steps"])
        self.assertEqual(_readdress(document), document)
        self.assertEqual(
            _digest("sunderkey.offline-dns-zone-model.v1", component_fixture()),
            document["source_model_sha256"],
        )

    def test_exact_answers_rrset_order_and_qtype_are_preserved(self):
        model = _model(
            [
                _rr("api.example.test.", values=["192.0.2.2", "192.0.2.1"]),
                _rr("api.example.test.", "AAAA", ["2001:db8::2", "2001:db8::1"]),
            ],
            queries=[
                _query("api.example.test.", "A", "a"),
                _query("api.example.test.", "AAAA", "aaaa"),
                _query("api.example.test.", "CNAME", "alias"),
            ],
        )
        first, second, third = self._results(model)
        self.assertEqual(["192.0.2.2", "192.0.2.1"], first["rdata"])
        self.assertEqual(["2001:db8::2", "2001:db8::1"], second["rdata"])
        self.assertEqual("no_data_in_supplied_projection", third["outcome"])
        self.assertEqual("exact", first["lookup_mode"])

    def test_exact_names_and_empty_nonterminals_suppress_upper_wildcard(self):
        model = _model(
            [_rr("*.example.test."), _rr("leaf.branch.example.test.")],
            ordinary=[{"owner": "owned.example.test.", "rrtypes": ["TXT"]}],
            queries=[
                _query("owned.example.test.", query_id="ordinary"),
                _query("branch.example.test.", query_id="empty"),
                _query("missing.branch.example.test.", query_id="blocked"),
                _query("deep.absent.example.test.", query_id="synthesized"),
            ],
        )
        ordinary, empty, blocked, synthesized = self._results(model)
        for item in (ordinary, empty):
            self.assertEqual("no_data_in_supplied_projection", item["outcome"])
            self.assertEqual("exact", item["lookup_mode"])
        self.assertEqual("name_absent_in_supplied_projection", blocked["outcome"])
        self.assertEqual("branch.example.test.", blocked["closest_encloser"])
        self.assertEqual("answer_in_supplied_projection", synthesized["outcome"])
        self.assertEqual("*.example.test.", synthesized["source_of_synthesis"])

    def test_one_closest_encloser_candidate_and_wildcard_empty_nonterminal(self):
        model = _model(
            [_rr("*.example.test."), _rr("leaf.*.branch.example.test.")],
            queries=[
                _query("missing.branch.example.test.", query_id="empty-source"),
                _query("missing.leaf.branch.example.test.", query_id="single-source"),
            ],
        )
        first, second = self._results(model)
        self.assertEqual("no_data_in_supplied_projection", first["outcome"])
        self.assertEqual("*.branch.example.test.", first["source_of_synthesis"])
        self.assertEqual("no_data_in_supplied_projection", second["outcome"])
        self.assertEqual("*.branch.example.test.", second["source_of_synthesis"])
        absent = _model(
            [_rr("*.example.test."), _rr("leaf.branch.example.test.")],
            queries=[_query("missing.branch.example.test.")],
        )
        self.assertEqual("name_absent_in_supplied_projection", self._one(absent)["outcome"])

    def test_literal_asterisk_labels_are_not_string_patterns(self):
        model = _model(
            [_rr("*.example.test."), _rr("known.*.example.test.")],
            queries=[
                _query("*.example.test.", query_id="literal"),
                _query("known.*.example.test.", query_id="noninitial"),
                _query("ghost.*.example.test.", query_id="self-blocking"),
            ],
        )
        first, second, third = self._results(model)
        self.assertEqual("exact", first["lookup_mode"])
        self.assertEqual("exact", second["lookup_mode"])
        self.assertEqual("name_absent_in_supplied_projection", third["outcome"])
        self.assertEqual("*.example.test.", third["closest_encloser"])

    def test_nested_wildcards_remain_distinct_sources(self):
        model = _model(
            [_rr("*.example.test."), _rr("*.*.example.test.", values=["192.0.2.44"])],
            queries=[_query("ghost.*.example.test.")],
        )
        answer = self._one(model)
        self.assertEqual("*.*.example.test.", answer["source_of_synthesis"])
        self.assertEqual(["192.0.2.44"], answer["rdata"])

    def test_cut_precedes_exact_glue_and_wildcards_at_every_descendant(self):
        model = _model(
            [
                _rr("*.example.test."),
                _rr("child.example.test."),
                _rr("ns.child.example.test.", "AAAA", ["2001:db8::3"]),
                _rr("*.child.example.test."),
            ],
            ordinary=[{"owner": "text.child.example.test.", "rrtypes": ["TXT"]}],
            cuts=[{"owner": "child.example.test.", "nameservers": ["ns.child.example.test."]}],
            queries=[
                _query("child.example.test.", query_id="cut"),
                _query("ns.child.example.test.", "AAAA", "glue"),
                _query("ghost.child.example.test.", query_id="wildcard"),
            ],
        )
        report = m.analyze_supplied_dns_zone(model).to_dict()
        self.assertEqual([1, 2, 3], report["ignored_below_cut_rrset_indexes"])
        self.assertEqual([0], report["ignored_below_cut_ordinary_owner_indexes"])
        self.assertEqual(3, report["tree_node_count"])
        for result in report["query_results"]:
            self.assertEqual("referral_in_supplied_projection", result["outcome"])
            self.assertEqual([], result["rdata"])
            self.assertEqual([], result["alias_trace"])
            self.assertIsNone(result["source_of_synthesis"])
            self.assertEqual("child.example.test.", result["delegation_owner"])

    def test_incomplete_projection_globally_withholds_all_query_conclusions(self):
        model = component_fixture()
        model["zone"]["complete"] = False
        report = m.analyze_supplied_dns_zone(model).to_dict()
        self.assertFalse(report["declared_projection_complete"])
        self.assertEqual([3], report["ignored_below_cut_rrset_indexes"])
        for answer in report["query_results"]:
            self.assertEqual("incomplete", answer["outcome"])
            self.assertEqual("projection_declared_incomplete", answer["basis"])
            self.assertEqual([], answer["rdata"])
            self.assertEqual([], answer["alias_trace"])
            self.assertEqual([], answer["nameservers"])

    def test_exact_and_synthesized_cname_keep_literal_targets_and_owner_trace(self):
        model = _model(
            [
                _rr("*.example.test.", "CNAME", ["api.example.test."]),
                _rr("api.example.test."),
                _rr("literal.example.test.", "CNAME", ["*.example.test."]),
            ],
            queries=[
                _query("ghost.example.test.", query_id="synthesis"),
                _query("literal.example.test.", query_id="literal-target"),
                _query("ghost.example.test.", "CNAME", "cname-question"),
            ],
        )
        synthesized, literal, direct = self._results(model)
        self.assertEqual("ghost.example.test.", synthesized["alias_trace"][0]["name"])
        self.assertEqual("*.example.test.", synthesized["alias_trace"][0]["source_of_synthesis"])
        self.assertEqual("api.example.test.", synthesized["terminal_name"])
        self.assertEqual("*.example.test.", literal["alias_trace"][0]["target"])
        self.assertEqual("exact", literal["alias_trace"][1]["lookup_mode"])
        self.assertEqual(["api.example.test."], direct["rdata"])
        self.assertEqual([], direct["alias_trace"])

    def test_external_alias_and_direct_off_zone_questions_are_unresolved(self):
        model = _model(
            [_rr("alias.example.test.", "CNAME", ["outside.invalid."])],
            queries=[
                _query("alias.example.test.", query_id="alias"),
                _query("outside.invalid.", query_id="outside"),
            ],
        )
        alias, outside = self._results(model)
        for item in (alias, outside):
            self.assertEqual("incomplete", item["outcome"])
            self.assertEqual("name_outside_supplied_zone", item["basis"])
            self.assertEqual([], item["rdata"])
        self.assertEqual(1, len(alias["alias_trace"]))
        self.assertEqual([], outside["alias_trace"])

    def test_missing_alias_target_is_not_original_alias_nonexistence(self):
        model = _model(
            [_rr("alias.example.test.", "CNAME", ["missing.example.test."])],
            queries=[_query("alias.example.test.")],
        )
        answer = self._one(model)
        self.assertEqual("name_absent_in_supplied_projection", answer["outcome"])
        self.assertEqual("missing.example.test.", answer["terminal_name"])
        self.assertEqual("alias.example.test.", answer["qname"])
        self.assertEqual(1, len(answer["alias_trace"]))

    def test_alias_loops_never_become_addresses_or_authoritative_negatives(self):
        for targets in (("a", "a"), ("b", "a")):
            with self.subTest(targets=targets):
                model = _model(
                    [
                        _rr("a.example.test.", "CNAME", [targets[0] + ".example.test."]),
                        _rr("b.example.test.", "CNAME", [targets[1] + ".example.test."]),
                    ],
                    queries=[_query("a.example.test.")],
                )
                answer = self._one(model)
                self.assertEqual("incomplete", answer["outcome"])
                self.assertEqual("alias_loop_in_supplied_projection", answer["basis"])
                self.assertEqual([], answer["rdata"])

    def test_alias_to_cut_is_referral_not_glue_address_resolution(self):
        model = _model(
            [
                _rr("alias.example.test.", "CNAME", ["host.child.example.test."]),
                _rr("host.child.example.test."),
            ],
            cuts=[{"owner": "child.example.test.", "nameservers": ["ns.invalid."]}],
            queries=[_query("alias.example.test.")],
        )
        answer = self._one(model)
        self.assertEqual("referral_in_supplied_projection", answer["outcome"])
        self.assertEqual([], answer["rdata"])
        self.assertEqual(1, len(answer["alias_trace"]))

    def test_alias_hop_ceiling_preserves_exact_boundary_and_withholds_longer_chain(self):
        for hops in (32, 33):
            with self.subTest(hops=hops):
                model = _model(
                    [
                        _rr(f"n{i}.example.test.", "CNAME", [f"n{i + 1}.example.test."])
                        for i in range(hops)
                    ]
                    + [_rr(f"n{hops}.example.test.")],
                    queries=[_query("n0.example.test.")],
                )
                answer = self._one(model)
                self.assertEqual(32, len(answer["alias_trace"]))
                self.assertEqual(
                    "answer_in_supplied_projection" if hops == 32 else "incomplete",
                    answer["outcome"],
                )
                if hops == 33:
                    self.assertEqual("alias_traversal_bound_exhausted", answer["basis"])
                    self.assertEqual([], answer["rdata"])

    def test_independent_exhaustive_owner_tree_oracle(self):
        owners = (
            "a.example.test.",
            "b.example.test.",
            "*.example.test.",
            "x.a.example.test.",
            "*.a.example.test.",
            "x.*.example.test.",
        )
        names = (
            "example.test.",
            "a.example.test.",
            "b.example.test.",
            "x.a.example.test.",
            "y.a.example.test.",
            "*.example.test.",
            "x.*.example.test.",
            "ghost.*.example.test.",
            "deep.ghost.example.test.",
        )
        questions = [
            _query(name, qtype, f"q:{index}:{qtype}")
            for index, name in enumerate(names)
            for qtype in ("A", "AAAA", "CNAME")
        ]
        checked = 0
        for presence in itertools.product((False, True), repeat=len(owners)):
            rrsets = []
            ordinary = []
            for index, (owner, present) in enumerate(zip(owners, presence, strict=True)):
                if present:
                    if index % 2 == 0:
                        rrsets.append(_rr(owner))
                    else:
                        ordinary.append({"owner": owner, "rrtypes": ["TXT"]})
            model = _model(rrsets, ordinary=ordinary, queries=questions)
            for question, answer in zip(questions, self._results(model), strict=True):
                expected = _set_oracle(model, question)
                observed = (
                    answer["outcome"],
                    answer["terminal_name"],
                    answer["rdata"],
                    [step["target"] for step in answer["alias_trace"]],
                )
                self.assertEqual(expected, observed, (presence, question))
                checked += 1
        self.assertEqual(1728, checked)

    def test_independent_small_alias_graph_oracle(self):
        names = ("a.example.test.", "b.example.test.", "c.example.test.")
        targets = (names[0], names[1], "api.example.test.", "off.invalid.")
        questions = [
            _query(name, qtype, f"q:{index}:{qtype}")
            for index, name in enumerate(names)
            for qtype in ("A", "CNAME")
        ]
        checked = 0
        for selected in itertools.product(targets, repeat=3):
            model = _model(
                [_rr(name, "CNAME", [target]) for name, target in zip(names, selected, strict=True)]
                + [_rr("api.example.test.")],
                queries=questions,
            )
            for question, answer in zip(questions, self._results(model), strict=True):
                self.assertEqual(
                    _set_oracle(model, question),
                    (
                        answer["outcome"],
                        answer["terminal_name"],
                        answer["rdata"],
                        [step["target"] for step in answer["alias_trace"]],
                    ),
                    selected,
                )
                checked += 1
        self.assertEqual(384, checked)

    def test_independent_delegation_boundary_oracle(self):
        for cut in ("child.example.test.", "deep.child.example.test."):
            model = _model(
                [
                    _rr("*.example.test."),
                    _rr("child.example.test."),
                    _rr("deep.child.example.test."),
                    _rr("host.deep.child.example.test."),
                ],
                cuts=[{"owner": cut, "nameservers": ["ns.invalid."]}],
                queries=[
                    _query(name, query_id=f"q:{index}")
                    for index, name in enumerate(
                        (
                            "child.example.test.",
                            "deep.child.example.test.",
                            "host.deep.child.example.test.",
                            "ghost.child.example.test.",
                            "ghost.example.test.",
                        )
                    )
                ],
            )
            for question, answer in zip(model["queries"], self._results(model), strict=True):
                self.assertEqual(
                    _set_oracle(model, question),
                    (answer["outcome"], answer["terminal_name"], answer["rdata"], []),
                )

    def test_cname_exclusivity_single_target_and_apex_constraints(self):
        models = [
            _model([_rr("a.example.test.", "CNAME", ["b.example.test.", "c.example.test."])]),
            _model([_rr("a.example.test.", "CNAME", ["b.example.test."]), _rr("a.example.test.")]),
            _model(
                [_rr("a.example.test.", "CNAME", ["b.example.test."])],
                ordinary=[{"owner": "a.example.test.", "rrtypes": ["TXT"]}],
            ),
            _model([_rr("example.test.", "CNAME", ["other.invalid."])]),
            _model(
                [_rr("cut.example.test.", "CNAME", ["other.invalid."])],
                cuts=[{"owner": "cut.example.test.", "nameservers": ["ns.invalid."]}],
            ),
        ]
        for model in models:
            with self.subTest(model=model):
                self._denied(model)

    def test_ordinary_owner_requires_actual_other_data_and_no_fake_empty_leaf(self):
        for owner in (
            {"owner": "leaf.example.test.", "rrtypes": []},
            {"owner": "leaf.example.test.", "rrtypes": ["EMPTY"]},
            {"owner": "leaf.example.test.", "rrtypes": ["CNAME"]},
            {"owner": "leaf.example.test.", "rrtypes": ["A"]},
            {"owner": "leaf.example.test.", "rrtypes": ["DNAME"]},
            {"owner": "leaf.example.test.", "rrtypes": ["NS"]},
            {"owner": "leaf.example.test.", "rrtypes": ["SOA"]},
        ):
            with self.subTest(owner=owner):
                self._denied(_model(ordinary=[owner]))
        for rrtype in ("TXT", "MX", "SRV", "PTR", "CAA"):
            model = _model(
                ordinary=[{"owner": "leaf.example.test.", "rrtypes": [rrtype]}],
                queries=[_query("leaf.example.test.")],
            )
            self.assertEqual("no_data_in_supplied_projection", self._one(model)["outcome"])

    def test_foreign_owners_duplicate_sets_and_overlapping_cuts_are_denied(self):
        models = [
            _model([_rr("foreign.invalid.")]),
            _model([_rr("a.example.test."), _rr("a.example.test.")]),
            _model([_rr("a.example.test.", values=["192.0.2.1", "192.0.2.1"])]),
            _model(ordinary=[{"owner": "a.example.test.", "rrtypes": ["TXT", "TXT"]}]),
            _model(ordinary=[{"owner": "a.example.test.", "rrtypes": ["TXT"]}] * 2),
            _model(cuts=[{"owner": "example.test.", "nameservers": ["ns.invalid."]}]),
            _model(cuts=[{"owner": "*.example.test.", "nameservers": ["ns.invalid."]}]),
            _model(cuts=[{"owner": "other.invalid.", "nameservers": ["ns.invalid."]}]),
            _model(cuts=[{"owner": "a.example.test.", "nameservers": ["ns.invalid."]}] * 2),
            _model(
                cuts=[
                    {"owner": "a.example.test.", "nameservers": ["ns.invalid."]},
                    {"owner": "b.a.example.test.", "nameservers": ["ns.invalid."]},
                ]
            ),
            _model(cuts=[{"owner": "a.example.test.", "nameservers": []}]),
        ]
        for model in models:
            with self.subTest(model=model):
                self._denied(model)

    def test_native_rdata_denials_are_domain_errors_not_unhashable_builtin_errors(self):
        for value in ({}, [], 1, True, None, 1.0):
            for rrtype in ("A", "AAAA", "CNAME"):
                with self.subTest(value=value, rrtype=rrtype):
                    self._denied(_model([_rr("a.example.test.", rrtype, [value])]))

    def test_address_family_canonicality_and_unsupported_types(self):
        for rrtype, value in (
            ("A", "2001:db8::1"),
            ("AAAA", "192.0.2.1"),
            ("A", "192.000.2.1"),
            ("AAAA", "2001:0db8:0:0:0:0:0:1"),
            ("AAAA", "fe80::1%1"),
            ("AAAA", "2001:DB8::1"),
            ("DNAME", "example.test."),
            ("NS", "ns.example.test."),
        ):
            with self.subTest(rrtype=rrtype, value=value):
                self._denied(_model([_rr("a.example.test.", rrtype, [value])]))
        self.assertEqual(
            ["2001:db8::1"],
            self._one(
                _model(
                    [_rr("a.example.test.", "AAAA", ["2001:db8::1"])],
                    queries=[_query("a.example.test.", "AAAA")],
                )
            )["rdata"],
        )

    def test_textual_label_wire_lengths_and_supported_absolute_spelling(self):
        for name in (
            "Example.test.",
            "relative.example.test",
            "empty..example.test.",
            "bad space.example.test.",
            "**.example.test.",
            "bad*label.example.test.",
            "-bad.example.test.",
            "bad-.example.test.",
            ".",
            "a" * 64 + ".example.test.",
            ".".join(["a"] * 31 + ["example", "test"]) + ".",
            ".".join(["a" * 63] * 4) + ".",
        ):
            with self.subTest(name=name):
                self._denied(_model(queries=[_query(name)]))
        for name in ("_service._tcp.example.test.", "9.example.test.", "*.example.test."):
            self.assertEqual(name, self._one(_model(queries=[_query(name)]))["qname"])
        apex = ".".join(["a" * 63] * 3 + ["b" * 60]) + "."
        self.assertEqual(253, len(apex))
        model = _model(queries=[_query(apex)])
        model["zone"]["apex"] = apex
        self.assertEqual("no_data_in_supplied_projection", self._one(model)["outcome"])

    def test_native_schema_completeness_types_and_subclasses_precede_hashing(self):
        class Integer(int):
            pass

        class Text(str):
            pass

        class Array(list):
            pass

        class Object(dict):
            pass

        models = []
        for value in (True, 1.0, "1", Integer(1)):
            model = _model()
            model["schema_version"] = value
            models.append(model)
        for value in (0, 1, "true", None):
            model = _model()
            model["zone"]["complete"] = value
            models.append(model)
        model = _model()
        model["zone"]["apex"] = Text("example.test.")
        models.extend((model, Object(_model()), _model(rrsets=Array())))
        with patch.object(m, "_hash", side_effect=AssertionError("Hash must not run")):
            for model in models:
                with self.subTest(model=model):
                    self._denied(model)

    def test_unknown_missing_fields_queries_and_collection_ceilings(self):
        models = []
        model = _model()
        model["network"] = True
        models.append(model)
        model = _model()
        del model["zone"]["complete"]
        models.append(model)
        models.extend((_model(queries=[]), _model(queries=[_query("example.test.")] * 2)))
        models.append(_model(queries=[_query("example.test.", "ANY")]))
        models.append(_model([_rr(f"n{i}.example.test.") for i in range(1025)]))
        models.append(
            _model(
                ordinary=[{"owner": f"n{i}.example.test.", "rrtypes": ["TXT"]} for i in range(1025)]
            )
        )
        models.append(
            _model(
                cuts=[
                    {"owner": f"n{i}.example.test.", "nameservers": ["ns.invalid."]}
                    for i in range(129)
                ]
            )
        )
        models.append(
            _model(queries=[_query("example.test.", query_id=f"q:{i}") for i in range(65)])
        )
        models.append(_model([_rr("a.example.test.", values=[f"192.0.2.{i}" for i in range(17)])]))
        for index, model in enumerate(models):
            with self.subTest(case=index):
                self._denied(model)

    def test_exact_native_collection_boundary_controls(self):
        for size in (1, 16):
            model = _model(
                [_rr("a.example.test.", values=[f"192.0.2.{i}" for i in range(size)])],
                queries=[_query("a.example.test.", query_id=f"q:{i}") for i in range(64)],
            )
            self.assertEqual(64, len(self._results(model)))
        self.assertEqual(
            1024,
            len(
                m.analyze_supplied_dns_zone(
                    _model([_rr(f"n{i}.example.test.") for i in range(1024)])
                ).to_dict()["source_model"]["zone"]["rrsets"]
            ),
        )

    def test_raw_duplicate_and_malformed_numeric_lexemes_are_domain_errors(self):
        raw = _canonical(_model())
        cases = [raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1')]
        cases.extend(
            raw.replace('"schema_version":1', '"schema_version":' + lexical)
            for lexical in (
                "true",
                "1.0",
                "1e0",
                "NaN",
                "Infinity",
                "--1",
                "---1",
                "--0",
                "+1",
                "01",
                "-01",
                "9223372036854775808",
            )
        )
        for text in cases:
            with self.subTest(text=text), self.assertRaises(m.DnsZoneAnalysisError):
                m.analyze_supplied_dns_zone_bytes(model_bytes=text.encode("ascii"))

    def test_raw_depth_nodes_integer_and_escape_bounds_precede_decoder(self):
        cases = (
            "[" * 16 + "0" + "]" * 16,
            "[" * 16 + '"x"' + "]" * 16,
            "[" + ",".join("0" for _ in range(m.MAX_NATIVE_NODES)) + "]",
            '"' + "x" * (m.MAX_STRING_BYTES + 1) + '"',
            '"' + "\\u0041" * (m.MAX_STRING_BYTES + 1) + '"',
            '"\\u0000"',
            '"\\n"',
            '"unterminated',
            "--1",
            "9" * 20000,
        )
        with patch.object(m.json, "loads", side_effect=AssertionError("Decoder must not run")):
            for raw in cases:
                with self.subTest(prefix=raw[:32]), self.assertRaises(m.DnsZoneAnalysisError):
                    m.analyze_supplied_dns_zone_bytes(model_bytes=raw.encode("ascii"))

    def test_native_aggregate_cycles_large_integer_and_strings_precede_serialization(self):
        repeated = ["x" * 512] * 1024
        dag = [repeated] * 1024
        cyclic = []
        cyclic.append(cyclic)
        nested = 1
        for _ in range(16):
            nested = [nested]
        with patch.object(m.json, "dumps", side_effect=AssertionError("Serializer must not run")):
            for value in (dag, cyclic, nested, 1 << 100000, "x" * 1000000, object()):
                with (
                    self.subTest(kind=type(value).__name__),
                    self.assertRaises(m.DnsZoneAnalysisError),
                ):
                    m.analyze_supplied_dns_zone(value)

    def test_derived_tree_node_bound_precedes_node_allocation_and_all_hashes(self):
        model = _model([_rr((f"n{i}." * 29) + "example.test.") for i in range(1024)])
        with (
            patch.object(m, "_hash", side_effect=AssertionError("Hash must not run")),
            self.assertRaisesRegex(m.DnsZoneAnalysisError, "tree node bound"),
        ):
            m.analyze_supplied_dns_zone(model)

    def test_cumulative_real_report_budget_precedes_retention_and_any_digest(self):
        suffix = ".".join(["s" * 54] * 4) + ".example.test."
        model = _model(
            [_rr(f"n{i}." + suffix, "CNAME", [f"n{i + 1}." + suffix]) for i in range(32)]
            + [_rr("n32." + suffix)],
            queries=[_query("n0." + suffix, query_id=f"q:{i}") for i in range(64)],
        )
        with (
            patch.object(m, "_hash", side_effect=AssertionError("Hash must not run")),
            self.assertRaisesRegex(m.DnsZoneAnalysisError, "Cumulative report cost"),
        ):
            m.analyze_supplied_dns_zone(model)

    def test_work_exhaustion_is_fail_closed_before_any_digest(self):
        # Reduced placement control, not a demonstrated production-limit bypass.
        with (
            patch.object(m, "MAX_WORK", 1),
            patch.object(m, "_hash", side_effect=AssertionError("Hash must not run")),
            self.assertRaisesRegex(m.DnsZoneAnalysisError, "work budget"),
        ):
            m.analyze_supplied_dns_zone(component_fixture())

    def test_raw_byte_family_oversize_nonascii_and_json_syntax(self):
        valid = _canonical(component_fixture()).encode("ascii")
        self.assertEqual(
            m.analyze_supplied_dns_zone(component_fixture()).to_dict(),
            m.analyze_supplied_dns_zone_bytes(model_bytes=valid).to_dict(),
        )
        for value in (
            None,
            "{}",
            bytearray(valid),
            memoryview(valid),
            b"",
            b"\xff",
            b"{",
            b"{} []",
            b" " * (m.MAX_DOCUMENT_BYTES + 1),
        ):
            with self.subTest(kind=type(value).__name__), self.assertRaises(m.DnsZoneAnalysisError):
                m.analyze_supplied_dns_zone_bytes(model_bytes=value)

    def test_wrapper_and_native_roundtrips_are_exact_and_detached(self):
        model = component_fixture()
        original = copy.deepcopy(model)
        report = m.analyze_supplied_dns_zone(model)
        document = report.to_dict()
        expected = copy.deepcopy(document)
        self.assertEqual(original, model)
        for restored in (
            m.DnsZoneAnalysis(document),
            m.DnsZoneAnalysis.from_dict(document),
            m.DnsZoneAnalysis.from_json(report.to_json()),
            m.verify_supplied_dns_zone_analysis(report, model=original),
        ):
            self.assertIsNot(restored, report)
            self.assertEqual(expected, restored.to_dict())
        model["zone"]["rrsets"][0]["rdata"][0] = "192.0.2.88"
        document["query_results"][0]["rdata"].append("192.0.2.77")
        document["flags"]["source_authenticated"] = True
        document["bounds"]["queries"] = 1
        document["effects"]["network"] = "enabled"
        expected["source_model"]["queries"][0]["qname"] = "changed.example.test."
        self.assertEqual(original, report.to_dict()["source_model"])
        self.assertEqual(["192.0.2.10"], report.to_dict()["query_results"][0]["rdata"])
        self.assertFalse(report.to_dict()["flags"]["source_authenticated"])
        self.assertEqual(64, report.to_dict()["bounds"]["queries"])
        self.assertEqual("none", report.to_dict()["effects"]["network"])
        self.assertEqual(
            "DZA-EF85B60D02D64FDBD374544598A749B5",
            m.analyze_supplied_dns_zone(original).analysis_id,
        )

    def test_cohashed_false_conclusions_trace_ownership_and_effect_promotion_reject(self):
        original = m.analyze_supplied_dns_zone(component_fixture()).to_dict()
        for mutate in (
            lambda d: d["query_results"][2].update(
                outcome="answer_in_supplied_projection", rdata=["192.0.2.99"]
            ),
            lambda d: d["query_results"][0]["alias_trace"][0].update(target="other.example.test."),
            lambda d: d["query_results"][1].update(source_of_synthesis="*.other.test."),
            lambda d: d["flags"].update(source_authenticated=True),
            lambda d: d["effects"].update(network="enabled"),
            lambda d: d.update(blueprint_sha256="sha256:" + "a" * 64),
            lambda d: d.update(ignored_below_cut_rrset_indexes=[]),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(m.DnsZoneAnalysisError):
                m.DnsZoneAnalysis.from_dict(_readdress(changed))

    def test_cohashed_bool_int_float_native_report_aliases_are_not_python_equality(self):
        original = m.analyze_supplied_dns_zone(component_fixture()).to_dict()
        for mutate in (
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1.0),
            lambda d: d.update(tree_node_count=float(d["tree_node_count"])),
            lambda d: d.update(declared_projection_complete=1),
            lambda d: d["flags"].update(source_authenticated=0),
            lambda d: d["bounds"].update(queries=64.0),
            lambda d: d["query_results"][0].update(rrset_index=False),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(m.DnsZoneAnalysisError):
                m.DnsZoneAnalysis.from_dict(_readdress(changed))

    def test_separate_original_source_replay_rejects_valid_different_model(self):
        original = component_fixture()
        changed = copy.deepcopy(original)
        changed["zone"]["rrsets"][0]["rdata"] = ["192.0.2.88"]
        report = m.analyze_supplied_dns_zone(changed)
        self.assertEqual(
            report.to_dict(), m.verify_supplied_dns_zone_analysis(report, model=changed).to_dict()
        )
        with self.assertRaisesRegex(m.DnsZoneAnalysisError, "separately supplied original"):
            m.verify_supplied_dns_zone_analysis(report, model=original)
        for bad in (report.to_dict(), object(), None):
            with self.assertRaises(m.DnsZoneAnalysisError):
                m.verify_supplied_dns_zone_analysis(bad, model=original)

    def test_forged_wrapper_and_mutated_private_document_are_revalidated(self):
        empty = object.__new__(m.DnsZoneAnalysis)
        with self.assertRaises(m.DnsZoneAnalysisError):
            empty.to_dict()
        report = m.analyze_supplied_dns_zone(component_fixture())
        document = report.to_dict()
        document["flags"]["source_authenticated"] = True
        object.__setattr__(report, "_document_json", _canonical(_readdress(document)))
        with self.assertRaises(m.DnsZoneAnalysisError):
            report.to_dict()
        with self.assertRaises(m.DnsZoneAnalysisError):
            m.verify_supplied_dns_zone_analysis(report, model=component_fixture())

    def test_all_registered_bindings_and_nonqualifying_effects_are_fixed(self):
        document = m.analyze_supplied_dns_zone(component_fixture()).to_dict()
        self.assertEqual("dns_supplied_zone_lookup", document["component_id"])
        self.assertEqual("AOE-GA-D01-S03", document["profile_id"])
        self.assertEqual("army.ga.d01.s03", document["capability_id"])
        self.assertEqual("AV-GA-D01-S03-01", document["vector_id"])
        self.assertEqual("IWP2-AOE-GA-D01-S03", document["work_package_id"])
        self.assertEqual("IW2-003", document["wave_id"])
        self.assertEqual("AOE-GA-D01-CMD", document["commander_id"])
        self.assertEqual("AOE-HQ-03", document["group_owner_id"])
        self.assertEqual("AOE-HQ-19", document["independent_validator_id"])
        self.assertEqual(
            "sha256:d242f5ad785667eda0f2669fef8f3e92f75e473fb39ac939fdc8aedd324f6dae",
            document["blueprint_sha256"],
        )
        self.assertTrue(
            all(type(value) is bool and value is False for value in document["flags"].values())
        )
        self.assertEqual({"none"}, set(document["effects"].values()))


if __name__ == "__main__":
    unittest.main()
