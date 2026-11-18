"""Pure supplied CSP predicates, exact replay and independent finite matching tables."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_csp_fetch_analysis as s


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def component_fixture():
    return s.component_fixture()


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256((s.DOMAIN + "\n" + canonical(body)).encode("ascii")).hexdigest()
    document["analysis_id"] = "CFA-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest


def model_for(
    expression,
    *,
    origin_scheme="http",
    origin_port=None,
    scheme="https",
    port=None,
    host="app.example.test",
    destination="image",
):
    return {
        "schema_version": 1,
        "protected_origin": {
            "scheme": origin_scheme,
            "host": "app.example.test",
            "port": origin_port,
        },
        "policy_list_complete": True,
        "policies": [
            {
                "policy_id": "policy.one",
                "disposition": "enforce",
                "serialized_policy": "img-src " + expression,
            }
        ],
        "queries": [
            {
                "query_id": "query.one",
                "destination": destination,
                "redirect_count": 0,
                "url": {"scheme": scheme, "host": host, "port": port},
            }
        ],
    }


class CspFetchAnalysisTests(unittest.TestCase):
    def analyze(self, model=None):
        return s.analyze_supplied_csp_fetch(component_fixture() if model is None else model)

    def decision(self, model):
        return self.analyze(model).to_dict()["query_observations"][0]["decision"]

    def denied_before_hash(self, call):
        with (
            patch.object(s, "_digest", side_effect=AssertionError("digest reached")) as digest,
            self.assertRaises(s.CspFetchAnalysisError),
        ):
            call()
        self.assertEqual(digest.call_count, 0)

    def test_literal_fixture_addresses_and_supplied_query_facts(self):
        model = component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "CFA-E502807486A313E8A1834D615A80C434")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:e502807486a313e8a1834d615a80c434f802a41c8f3d8109414dde8af4d0c4c1",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:ae6c29b1acf4531b3ad5ea399ab4351275f0dfce254e66e5793d17cf92c6ed20",
        )
        self.assertEqual(
            [row["decision"] for row in document["query_observations"]],
            ["allowed_supplied_subset", "blocked_supplied_subset", "allowed_supplied_subset"],
        )
        self.assertEqual(
            document["summary"],
            {
                "query_count": 3,
                "allowed_supplied_subset": 2,
                "blocked_supplied_subset": 1,
                "unassessed": 0,
            },
        )
        self.assertEqual(s.CspFetchAnalysis(report.to_json()).to_json(), report.to_json())
        self.assertEqual(s.CspFetchAnalysis.from_dict(document).to_json(), report.to_json())
        self.assertEqual(s.CspFetchAnalysis.from_json(report.to_json()).to_json(), report.to_json())
        self.assertEqual(
            s.analyze_supplied_csp_fetch_bytes(
                model_bytes=canonical(model).encode("ascii")
            ).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            s.verify_supplied_csp_fetch_analysis(report, model=model).to_json(), report.to_json()
        )

    def test_self_upgrade_and_explicit_source_ports_follow_distinct_current_tables(self):
        # Current algorithms, not the draft introduction's older port example.
        tables = (
            ("'self'", "http", None, "https", None, True),
            ("'self'", "http", None, "https", 80, False),
            ("'self'", "http", 8000, "https", 8000, True),
            ("'self'", "http", 8000, "https", None, False),
            ("'self'", "https", None, "http", None, False),
            ("'self'", "https", 8000, "http", 8000, False),
            ("'self'", "https", 8000, "https", 8000, True),
            ("http://app.example.test", "http", None, "https", None, True),
            ("http://app.example.test:80", "http", None, "https", None, False),
            ("http://app.example.test:80", "http", None, "http", None, True),
            ("http://app.example.test:00080", "http", None, "http", None, True),
            ("http://app.example.test:443", "http", None, "https", None, True),
            ("http://app.example.test:80", "http", None, "https", 80, True),
            ("https://app.example.test:80", "http", None, "http", None, False),
        )
        for expression, original, op, target, tp, expected in tables:
            with self.subTest(
                expression=expression, original=original, target=target, op=op, tp=tp
            ):
                model = model_for(
                    expression, origin_scheme=original, origin_port=op, scheme=target, port=tp
                )
                self.assertEqual(
                    self.decision(model),
                    "allowed_supplied_subset" if expected else "blocked_supplied_subset",
                )

    def test_independent_origin_tuple_truth_table_for_self(self):
        tuples = [(scheme, port) for scheme in ("http", "https") for port in (None, 81, 8443)]
        count = 0
        for origin, target, same_host in itertools.product(tuples, tuples, (False, True)):
            # Oracle: concrete effective network ports and a finite allowed-scheme table.
            effective_origin = (
                origin[1] if origin[1] is not None else {"http": 80, "https": 443}[origin[0]]
            )
            effective_target = (
                target[1] if target[1] is not None else {"http": 80, "https": 443}[target[0]]
            )
            permitted_scheme_pairs = {("http", "http"), ("http", "https"), ("https", "https")}
            defaults = origin[1] is None and target[1] is None
            expected = (
                same_host
                and (origin[0], target[0]) in permitted_scheme_pairs
                and (effective_origin == effective_target or defaults)
            )
            model = model_for(
                "'self'",
                origin_scheme=origin[0],
                origin_port=origin[1],
                scheme=target[0],
                port=target[1],
                host="app.example.test" if same_host else "other.test",
            )
            self.assertEqual(
                self.decision(model),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )
            count += 1
        self.assertEqual(count, 72)

    def test_scheme_upgrade_is_asymmetric_and_source_case_insensitive(self):
        for expression, scheme, expected in (
            ("HTTP:", "http", True),
            ("HTTP:", "https", True),
            ("HTTPS:", "http", False),
            ("HTTPS:", "https", True),
            ("HTTP://APP.EXAMPLE.TEST", "https", True),
            ("'SeLf'", "https", True),
        ):
            self.assertEqual(
                self.decision(model_for(expression, scheme=scheme)),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )

    def test_dns_wildcard_subdomain_requires_dot_boundary_and_excludes_apex(self):
        for host, expected in (
            ("example.test", False),
            ("x.example.test", True),
            ("deep.x.example.test", True),
            ("notexample.test", False),
            ("example.test.other", False),
        ):
            self.assertEqual(
                self.decision(model_for("https://*.EXAMPLE.TEST", host=host)),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )

    def test_schemeless_host_inherits_origin_scheme_not_origin_port(self):
        for oscheme, op, scheme, port, expected in (
            ("http", 8000, "https", None, True),
            ("https", 8000, "http", None, False),
            ("https", 8000, "https", None, True),
            ("http", 8000, "http", 8000, False),
        ):
            self.assertEqual(
                self.decision(
                    model_for(
                        "app.example.test",
                        origin_scheme=oscheme,
                        origin_port=op,
                        scheme=scheme,
                        port=port,
                    )
                ),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )

    def test_explicit_host_and_port_wildcards_are_independent(self):
        for expression, host, port, expected in (
            ("https://*:*", "other.test", 8443, True),
            ("https://*", "other.test", 8443, False),
            ("https://app.example.test:*", "app.example.test", 8443, True),
            ("https://app.example.test:*", "other.test", 8443, False),
        ):
            self.assertEqual(
                self.decision(model_for(expression, host=host, port=port)),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )

    def test_bare_wildcard_matches_declared_http_schemes_and_any_supported_port(self):
        for scheme, port in itertools.product(("http", "https"), (None, 81, 8443)):
            self.assertEqual(
                self.decision(model_for("*", scheme=scheme, port=port, host="unrelated.test")),
                "allowed_supplied_subset",
            )

    def test_none_empty_and_none_with_other_sources(self):
        for expression, expected in (
            ("", False),
            ("'none'", False),
            ("'NoNe'", False),
            ("'none' https:", True),
            ("https: 'none'", True),
        ):
            self.assertEqual(
                self.decision(model_for(expression)),
                "allowed_supplied_subset" if expected else "blocked_supplied_subset",
            )

    def test_first_duplicate_directive_wins_after_ascii_case_and_whitespace(self):
        model = model_for("https:")
        model["policies"][0]["serialized_policy"] = (
            " ;\tImG-SrC\n'none'\f; IMG-SRC https://example.test/path; "
        )
        document = self.analyze(model).to_dict()
        self.assertEqual(document["query_observations"][0]["decision"], "blocked_supplied_subset")
        self.assertEqual(
            document["policy_observations"][0]["ignored_duplicate_directives"], ["img-src"]
        )
        self.assertEqual(
            document["query_observations"][0]["policy_observations"][0]["uncertainties"], []
        )

    def test_effective_directive_and_default_fallback_for_all_four_destinations(self):
        for destination, directive in (
            ("image", "img-src"),
            ("font", "font-src"),
            ("media", "media-src"),
            ("connect", "connect-src"),
        ):
            model = model_for("https:", destination=destination)
            model["policies"][0]["serialized_policy"] = f"default-src 'none'; {directive} https:"
            row = self.analyze(model).to_dict()["query_observations"][0]
            self.assertEqual(row["decision"], "allowed_supplied_subset")
            self.assertEqual(row["policy_observations"][0]["selected_directive"], directive)
            model["policies"][0]["serialized_policy"] = "default-src 'none'"
            row = self.analyze(model).to_dict()["query_observations"][0]
            self.assertEqual(row["decision"], "blocked_supplied_subset")
            self.assertEqual(row["policy_observations"][0]["selected_directive"], "default-src")

    def test_independent_source_union_and_enforced_policy_intersection_grid(self):
        count = 0
        for a, b, c, d, report in itertools.product((False, True), repeat=5):
            model = model_for("'none'")
            model["policies"] = [
                {
                    "policy_id": "one",
                    "disposition": "enforce",
                    "serialized_policy": "img-src "
                    + " ".join("https:" if value else "http://unrelated.test" for value in (a, b)),
                },
                {
                    "policy_id": "two",
                    "disposition": "report" if report else "enforce",
                    "serialized_policy": "img-src "
                    + " ".join("https:" if value else "http://unrelated.test" for value in (c, d)),
                },
            ]
            allowed = (a or b) and (report or c or d)
            self.assertEqual(
                self.decision(model),
                "allowed_supplied_subset" if allowed else "blocked_supplied_subset",
            )
            count += 1
        self.assertEqual(count, 32)

    def test_report_only_denials_and_uncertainty_never_block_overall(self):
        for value in ("default-src 'none'", "img-src https://x.test/path", "sandbox"):
            model = model_for("https:")
            model["policies"].append(
                {"policy_id": "report", "disposition": "report", "serialized_policy": value}
            )
            row = self.analyze(model).to_dict()["query_observations"][0]
            self.assertEqual(row["decision"], "allowed_supplied_subset")
            self.assertIn(row["policy_observations"][1]["decision"], {"no_match", "unassessed"})

    def test_missing_directive_and_empty_complete_policy_set_are_unrestricted_subset(self):
        model = model_for("https:", destination="font")
        self.assertEqual(self.decision(model), "allowed_supplied_subset")
        model["policies"] = []
        self.assertEqual(self.decision(model), "allowed_supplied_subset")
        model["queries"] = []
        self.assertEqual(self.analyze(model).to_dict()["summary"]["query_count"], 0)

    def test_incomplete_policy_list_withholds_even_known_denial_or_empty_set(self):
        for expression in ("'none'", "https:"):
            model = model_for(expression)
            model["policy_list_complete"] = False
            self.assertEqual(self.decision(model), "unassessed")
        model["policies"] = []
        self.assertEqual(self.decision(model), "unassessed")

    def test_selected_unsupported_sources_do_not_become_silent_denials_or_allows(self):
        sources = (
            "https://app.example.test/path",
            "data:",
            "ws:",
            "'nonce-abc'",
            "'strict-dynamic'",
            "'sha256-abc'",
            "http://127.0.0.1",
            "https://[::1]",
            "app.example.test:0",
            "https://app.example.test?query",
            "ftp://app.example.test",
            "https://a*.test",
        )
        for source, supported in itertools.product(sources, ("", " https:")):
            row = self.analyze(model_for(source + supported)).to_dict()["query_observations"][0]
            self.assertEqual(row["decision"], "unassessed")
            self.assertIn(
                "unsupported_selected_source_expression",
                row["policy_observations"][0]["uncertainties"],
            )

    def test_unselected_unsupported_source_remains_labeled_not_used_for_other_destination(self):
        model = model_for("https://x.test/path", destination="font")
        model["policies"][0]["serialized_policy"] += "; font-src https:"
        document = self.analyze(model).to_dict()
        self.assertFalse(
            document["policy_observations"][0]["directives"][0]["source_expressions"][0][
                "supported"
            ]
        )
        self.assertEqual(document["query_observations"][0]["decision"], "allowed_supplied_subset")

    def test_unsupported_directives_withhold_enforced_policy_even_with_supported_matches(self):
        for directive in (
            "upgrade-insecure-requests",
            "block-all-mixed-content",
            "sandbox",
            "script-src https:",
            "unknown-fetch-mode enabled",
            "img-src, https:",
        ):
            model = model_for("https:")
            model["policies"][0]["serialized_policy"] += "; " + directive
            self.assertEqual(self.decision(model), "unassessed")

    def test_redirect_declarations_withhold_without_adopting_an_unobserved_destination(self):
        for count in (1, s.MAX_REDIRECT_COUNT):
            model = model_for("https:")
            model["queries"][0]["redirect_count"] = count
            self.assertEqual(self.decision(model), "unassessed")

    def test_url_profile_requires_already_canonical_dns_http_and_normalized_ports(self):
        cases = (
            {"scheme": "HTTPS", "host": "app.example.test", "port": None},
            {"scheme": "blob", "host": "app.example.test", "port": None},
            {"scheme": "https", "host": "APP.EXAMPLE.TEST", "port": None},
            {"scheme": "https", "host": "app.example.test.", "port": None},
            {"scheme": "https", "host": "127.0.0.1", "port": None},
            {"scheme": "https", "host": "a..test", "port": None},
            {"scheme": "https", "host": "-a.test", "port": None},
            {"scheme": "https", "host": "a" * 64 + ".test", "port": None},
            {"scheme": "https", "host": "app.example.test", "port": 443},
            {"scheme": "https", "host": "app.example.test", "port": 0},
            {"scheme": "https", "host": "app.example.test", "port": True},
            {"scheme": "https", "host": "app.example.test", "port": 81.0},
        )
        for url in cases:
            model = model_for("https:")
            model["queries"][0]["url"] = url
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_exact_native_aliases_collections_and_subclasses_precede_hash(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Mapping(dict):
            pass

        class Array(list):
            pass

        mutations = (
            lambda m: m.update(schema_version=True),
            lambda m: m.update(schema_version=1.0),
            lambda m: m.update(schema_version=Integer(1)),
            lambda m: m.update(policy_list_complete=1),
            lambda m: m.update(policies=Array(m["policies"])),
            lambda m: m.update(queries=tuple(m["queries"])),
            lambda m: m.update(protected_origin=Mapping(m["protected_origin"])),
            lambda m: m["policies"][0].update(serialized_policy=Text("img-src *")),
            lambda m: m["queries"][0].update(redirect_count=False),
            lambda m: m["queries"][0].update(redirect_count=0.0),
            lambda m: m["queries"][0].update(destination=Text("image")),
        )
        for mutate in mutations:
            model = component_fixture()
            mutate(model)
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_unknown_missing_null_and_duplicate_identifiers_are_not_normalized(self):
        mutations = (
            lambda m: m.update(extra=None),
            lambda m: m.pop("policy_list_complete"),
            lambda m: m.update(policies=None),
            lambda m: m["policies"][0].update(source="header"),
            lambda m: m["queries"][0].pop("redirect_count"),
            lambda m: m["queries"][0].update(destination="script"),
            lambda m: m["queries"][0]["url"].update(path="/"),
            lambda m: m["policies"].append(copy.deepcopy(m["policies"][0])),
            lambda m: m["queries"].append(copy.deepcopy(m["queries"][0])),
        )
        for mutate in mutations:
            model = component_fixture()
            mutate(model)
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_actual_array_directive_and_source_limit_boundaries(self):
        for name, maximum, key in (
            ("policies", s.MAX_POLICIES, "policy_id"),
            ("queries", s.MAX_QUERIES, "query_id"),
        ):
            model = model_for("https:")
            item = model[name][0]
            model[name] = [
                {**copy.deepcopy(item), key: f"item.{index}"} for index in range(maximum)
            ]
            self.analyze(model)
            model[name].append({**copy.deepcopy(item), key: "item.extra"})
            self.denied_before_hash(lambda model=model: self.analyze(model))
        model = model_for(" ".join(["https:"] * s.MAX_SOURCES_PER_DIRECTIVE))
        self.analyze(model)
        model["policies"][0]["serialized_policy"] += " https:"
        self.denied_before_hash(lambda: self.analyze(model))
        model = model_for("https:")
        model["policies"][0]["serialized_policy"] = ";".join(
            ["img-src https:"] * s.MAX_DIRECTIVES_PER_POLICY
        )
        self.analyze(model)
        model["policies"][0]["serialized_policy"] += ";img-src https:"
        self.denied_before_hash(lambda: self.analyze(model))

    def test_total_source_work_limit_and_source_string_limit_are_software_denials(self):
        model = model_for("https:")
        with patch.object(s, "MAX_TOTAL_SOURCES", 0):
            self.denied_before_hash(lambda: self.analyze(model))
        model = model_for("a" * (s.MAX_SOURCE_BYTES + 1))
        self.denied_before_hash(lambda: self.analyze(model))
        model["policies"][0]["serialized_policy"] = " " * (s.MAX_STRING_BYTES + 1)
        self.denied_before_hash(lambda: self.analyze(model))

    def test_raw_duplicate_members_including_escaped_spelling_are_denied(self):
        text = canonical(component_fixture())
        for replacement in (
            '"schema_version":1,"schema_version":1',
            '"schema_version":1,"schema_\\u0076ersion":1',
        ):
            data = text.replace('"schema_version":1', replacement).encode("ascii")
            self.denied_before_hash(
                lambda data=data: s.analyze_supplied_csp_fetch_bytes(model_bytes=data)
            )

    def test_raw_bounds_and_integer_grammar_precede_decoder_and_hash(self):
        cases = (
            b"[" * s.MAX_MODEL_DEPTH + b"0" + b"]" * s.MAX_MODEL_DEPTH,
            b"[" + b"0," * s.MAX_MODEL_NODES + b"0]",
            b'"' + b"a" * (s.MAX_STRING_BYTES + 1) + b'"',
            b'"' + b"\\u0061" * (s.MAX_STRING_BYTES + 1) + b'"',
            b"9223372036854775808",
            b"-9223372036854775809",
            b"--1",
            b"---1",
            b"--0",
            b"01",
            b"-01",
            b"1.0",
            b"NaN",
            b"Infinity",
            b'"\\ud800"',
            b'"\\u0000"',
        )
        for data in cases:
            with patch.object(s.json, "loads", side_effect=AssertionError("decoder")) as decoder:
                self.denied_before_hash(
                    lambda data=data: s.analyze_supplied_csp_fetch_bytes(model_bytes=data)
                )
            self.assertEqual(decoder.call_count, 0)

    def test_raw_bytes_family_ascii_size_and_copy_budget_precede_decoder(self):
        for data in (bytearray(b"{}"), b"", b"\xff", b" " * (s.MAX_MODEL_BYTES + 1)):
            with patch.object(s.json, "loads", side_effect=AssertionError("decoder")):
                self.denied_before_hash(
                    lambda data=data: s.analyze_supplied_csp_fetch_bytes(model_bytes=data)
                )
        data = canonical(component_fixture()).encode("ascii")
        with (
            patch.object(s, "MAX_WORK", len(data) - 1),
            patch.object(s, "_decode", side_effect=AssertionError("decode before copy budget")),
        ):
            self.denied_before_hash(lambda: s.analyze_supplied_csp_fetch_bytes(model_bytes=data))

    def test_native_cycles_depth_shared_nodes_and_escaped_bytes_precede_serialization(self):
        model = component_fixture()
        model["queries"].append(model)
        self.denied_before_hash(lambda: self.analyze(model))
        nested = 0
        for _ in range(s.MAX_MODEL_DEPTH):
            nested = [nested]
        self.denied_before_hash(lambda: self.analyze(nested))
        shared = {"a": ["b"]}
        with patch.object(s, "MAX_MODEL_NODES", 8):
            self.denied_before_hash(lambda: self.analyze([shared, shared]))
        with (
            patch.object(s, "MAX_MODEL_BYTES", 10),
            patch.object(s, "_canonical", side_effect=AssertionError("serialized before bounds")),
        ):
            self.denied_before_hash(lambda: self.analyze("\\" * 5))
        self.denied_before_hash(lambda: self.analyze({"schema_version": 1 << 10000}))

    def test_ascii_whitespace_escape_spelling_replays_but_unicode_whitespace_does_not(self):
        model = model_for("https:")
        model["policies"][0]["serialized_policy"] = "\tIMG-SRC\nhttps:\f\r"
        report = self.analyze(model)
        text = canonical(model).replace("IMG-SRC", "IMG-\\u0053RC")
        self.assertEqual(
            s.analyze_supplied_csp_fetch_bytes(model_bytes=text.encode("ascii")).to_json(),
            report.to_json(),
        )
        model["policies"][0]["serialized_policy"] = "img-src\u00a0https:"
        self.denied_before_hash(lambda: self.analyze(model))
        with self.assertRaises(s.CspFetchAnalysisError):
            s.CspFetchAnalysis.from_json(json.dumps(report.to_dict(), indent=2))

    def test_cohashed_false_decisions_fail_embedded_and_original_replay(self):
        model = component_fixture()
        valid = self.analyze(model).to_dict()
        mutations = (
            lambda d: d["query_observations"][0].update(decision="blocked_supplied_subset"),
            lambda d: d["query_observations"][0]["policy_observations"][0].update(
                matched_source_expressions=[]
            ),
            lambda d: d["policy_observations"][0].update(ignored_duplicate_directives=["img-src"]),
            lambda d: d["summary"].update(allowed_supplied_subset=0),
            lambda d: d["flags"].update(browser_behavior_verified=True),
            lambda d: d["effects"].update(network="allowed"),
            lambda d: d.update(source_model_sha256="sha256:" + "a" * 64),
            lambda d: d.update(profile_id="AOE-GB-D05-S13"),
        )
        for mutate in mutations:
            document = copy.deepcopy(valid)
            mutate(document)
            readdress(document)
            with self.assertRaises(s.CspFetchAnalysisError):
                s.CspFetchAnalysis.from_dict(document)
            with self.assertRaises(s.CspFetchAnalysisError):
                s.CspFetchAnalysis.from_json(canonical(document))
            forged = object.__new__(s.CspFetchAnalysis)
            object.__setattr__(forged, "document_json", canonical(document))
            for call in (
                forged.to_dict,
                forged.to_json,
                lambda forged=forged: s.verify_supplied_csp_fetch_analysis(forged, model=model),
            ):
                with self.assertRaises(s.CspFetchAnalysisError):
                    call()

    def test_canonical_equality_denies_native_report_bool_integer_float_aliases(self):
        valid = self.analyze().to_dict()
        for mutate in (
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1.0),
            lambda d: d["summary"].update(unassessed=False),
            lambda d: d["summary"].update(unassessed=0.0),
            lambda d: d["flags"].update(source_authenticated=0),
            lambda d: d.update(extra=None),
        ):
            document = copy.deepcopy(valid)
            mutate(document)
            readdress(document)
            with self.assertRaises(s.CspFetchAnalysisError):
                s.CspFetchAnalysis.from_dict(document)

    def test_separately_original_rejects_readdressed_valid_alternate_even_when_math_matches(self):
        model = component_fixture()
        alternate = copy.deepcopy(model)
        alternate["policies"][0]["policy_id"] = "renamed.still-same-math"
        report = self.analyze(alternate)
        self.assertEqual(report.to_dict()["summary"], self.analyze(model).to_dict()["summary"])
        self.assertEqual(s.CspFetchAnalysis.from_json(report.to_json()).to_json(), report.to_json())
        with self.assertRaises(s.CspFetchAnalysisError):
            s.verify_supplied_csp_fetch_analysis(report, model=model)

    def test_source_export_fixture_detachment_and_order_binding(self):
        model = component_fixture()
        report = self.analyze(model)
        before = report.to_json()
        model["policies"].clear()
        exported = report.to_dict()
        exported["source_model"]["policies"].clear()
        exported["query_observations"].clear()
        self.assertEqual(report.to_json(), before)
        self.assertEqual(len(component_fixture()["policies"]), 2)
        model = component_fixture()
        model["policies"].reverse()
        reordered = self.analyze(model).to_dict()
        self.assertNotEqual(
            reordered["source_model_sha256"], report.to_dict()["source_model_sha256"]
        )
        self.assertEqual(reordered["summary"], report.to_dict()["summary"])
        self.assertEqual(
            self.analyze(dict(reversed(list(component_fixture().items())))).to_json(), before
        )

    def test_frozen_wrapper_late_native_mutation_incomplete_and_subclasses_deny(self):
        report = self.analyze()
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"
        object.__setattr__(report, "document_json", "{}")
        for instance in (report, object.__new__(s.CspFetchAnalysis)):
            for call in (
                instance.to_dict,
                instance.to_json,
                lambda instance=instance: s.verify_supplied_csp_fetch_analysis(
                    instance, model=component_fixture()
                ),
            ):
                with self.assertRaises(s.CspFetchAnalysisError):
                    call()

        class Subclass(s.CspFetchAnalysis):
            pass

        with self.assertRaises(s.CspFetchAnalysisError):
            Subclass(self.analyze().to_json())
        with self.assertRaises(s.CspFetchAnalysisError):
            Subclass.from_dict(self.analyze().to_dict())

    def test_exact_actual_source_report_byte_and_node_boundaries(self):
        model = component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        _, model_bytes, model_nodes = s._capture(model, s._Budget())
        _, report_bytes, report_nodes = s._capture(document, s._Budget(), report=True)
        self.assertEqual(model_bytes, len(canonical(model)))
        self.assertEqual(report_bytes, len(report.to_json()))
        for name, required in (
            ("MAX_MODEL_BYTES", model_bytes),
            ("MAX_MODEL_NODES", model_nodes),
            ("MAX_REPORT_BYTES", report_bytes),
            ("MAX_REPORT_NODES", report_nodes),
        ):
            with patch.object(s, name, required):
                self.assertEqual(self.analyze(model).document_json, report.document_json)
            with patch.object(s, name, required - 1):
                self.denied_before_hash(lambda: self.analyze(model))

    def test_all_eight_public_boundaries_fund_work_before_any_digest(self):
        model = component_fixture()
        report = self.analyze(model)
        text, document = report.to_json(), report.to_dict()
        operations = {
            "produce": lambda: self.analyze(model),
            "bytes": lambda: s.analyze_supplied_csp_fetch_bytes(
                model_bytes=canonical(model).encode("ascii")
            ),
            "constructor": lambda: s.CspFetchAnalysis(text),
            "from_dict": lambda: s.CspFetchAnalysis.from_dict(document),
            "from_json": lambda: s.CspFetchAnalysis.from_json(text),
            "to_dict": report.to_dict,
            "to_json": report.to_json,
            "separate_original": lambda: s.verify_supplied_csp_fetch_analysis(report, model=model),
        }
        real_charge = s._Budget.charge
        for name, call in operations.items():
            with self.subTest(name=name):
                samples = []

                def observe(budget, amount, samples=samples):
                    real_charge(budget, amount)
                    samples.append(budget.used)

                with patch.object(s._Budget, "charge", observe):
                    result = call()
                required = samples[-1]
                with patch.object(s, "MAX_WORK", required - 1):
                    self.denied_before_hash(call)
                with patch.object(s, "MAX_WORK", required):
                    exact = call()
                self.assertEqual(
                    exact.document_json if type(exact) is s.CspFetchAnalysis else exact,
                    result.document_json if type(result) is s.CspFetchAnalysis else result,
                )

    def test_cumulative_retained_rows_are_bounded_before_digest(self):
        model = model_for(" ".join(["https:"] * s.MAX_SOURCES_PER_DIRECTIVE))
        model["queries"] = [
            {**copy.deepcopy(model["queries"][0]), "query_id": f"q.{index}"}
            for index in range(s.MAX_QUERIES)
        ]
        with patch.object(s, "MAX_REPORT_BYTES", 50_000):
            self.denied_before_hash(lambda: self.analyze(model))

    def test_existing_ownership_and_every_effect_flag_stay_nonauthorizing(self):
        document = self.analyze().to_dict()
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(
            all(type(value) is bool and value is False for value in document["flags"].values())
        )
        expected = {
            "component_id": "csp_supplied_external_fetch_predicates",
            "profile_id": "AOE-GB-D05-S14",
            "capability_id": "army.gb.d05.s14",
            "vector_id": "AV-GB-D05-S14-01",
            "work_package_id": "IWP2-AOE-GB-D05-S14",
            "wave_id": "IW2-014",
            "commander_id": "AOE-GB-D05-CMD",
            "group_owner_id": "AOE-HQ-04",
            "independent_validator_id": "AOE-HQ-34",
            "blueprint_sha256": (
                "sha256:519eecb0d32d95081a3bb2e04dc431d5ce71a47f1f65247f6f5e8d875a1fff43"
            ),
        }
        for key, value in expected.items():
            self.assertEqual(document[key], value)


if __name__ == "__main__":
    unittest.main()
