"""Independent supplied SemVer ordering, interval and replay controls."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_semver_interval_analysis as s


def _model(versions: tuple[str, ...] = ()) -> dict:
    return {
        "schema_version": 1,
        "versions": [
            {"version_id": f"v{index}", "version": value} for index, value in enumerate(versions)
        ],
        "comparisons": [],
        "intervals": [],
        "membership_queries": [],
    }


def _pair(left: str, right: str) -> dict:
    result = _model((left, right))
    result["comparisons"] = [
        {"comparison_id": "pair", "left_version_id": "v0", "right_version_id": "v1"}
    ]
    return result


def _bound(version: str, inclusive: bool) -> dict:
    return {"version": version, "inclusive": inclusive}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _rehash(document: dict) -> dict:
    """Truthfully address a false report, without pretending its math is genuine."""
    source = _canonical(document["source_model"]).encode("ascii")
    document["source_model_sha256"] = (
        "sha256:" + hashlib.sha256(s.MODEL_DOMAIN.encode("ascii") + b"\n" + source).hexdigest()
    )
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        s.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
    ).hexdigest()
    document["analysis_id"] = "SVA-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest
    return document


def _oracle_key(version: str) -> tuple:
    """Independent small-number oracle, intentionally unlike decimal-string math."""
    main = version.split("+", 1)[0]
    pieces = main.split("-", 1)
    core = tuple(int(value) for value in pieces[0].split("."))
    if len(pieces) == 1:
        return core + (1, ())
    identifiers = tuple(
        (0, int(value)) if value.isdecimal() else (1, value) for value in pieces[1].split(".")
    )
    return core + (0, identifiers)


class OfflineSemverIntervalAnalysisTests(unittest.TestCase):
    def relation(self, left: str, right: str) -> str:
        return s.analyze_supplied_semver_intervals(_pair(left, right)).to_dict()["comparisons"][0][
            "relation"
        ]

    def reject_before_digest(self, model: object) -> None:
        with (
            patch.object(s.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaises(s.SemverIntervalAnalysisError),
        ):
            s.analyze_supplied_semver_intervals(model)

    def reject_before_decoder(self, text: str) -> None:
        with (
            patch.object(s.json, "loads", side_effect=AssertionError("decoder reached")),
            patch.object(s.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaises(s.SemverIntervalAnalysisError),
        ):
            s.analyze_supplied_semver_intervals_bytes(model_bytes=text.encode("ascii"))

    def test_fixture_literal_goldens_and_known_rows(self) -> None:
        report = s.analyze_supplied_semver_intervals(s.component_fixture())
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "SVA-A6E6CFD7BA022DCC5257D44D6C3610F7")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:a6e6cfd7ba022dcc5257d44d6c3610f7e3d7c9c7b46fa650b898e3cc457e5c4b",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:b2d19e183c02e4549306c8603989a656cec9d713dc42441a6da0281d3ffe6418",
        )
        self.assertEqual(
            [row["relation"] for row in document["comparisons"]],
            ["less", "less", "equal"],
        )
        self.assertEqual(
            [row["membership"] for row in document["memberships"]],
            ["inside", "outside", "inside"],
        )

    def test_actual_report_domains_and_id_are_independently_addressed(self) -> None:
        document = s.analyze_supplied_semver_intervals(s.component_fixture()).to_dict()
        self.assertEqual(_rehash(copy.deepcopy(document)), document)
        self.assertNotEqual(s.DOMAIN, s.MODEL_DOMAIN)

    def test_all_public_round_trips_preserve_exact_identity(self) -> None:
        model = s.component_fixture()
        report = s.analyze_supplied_semver_intervals(model)
        expected = report.to_json()
        controls = (
            s.SemverIntervalAnalysis(report.to_dict()),
            s.SemverIntervalAnalysis.from_dict(report.to_dict()),
            s.SemverIntervalAnalysis.from_json(expected),
            s.analyze_supplied_semver_intervals_bytes(
                model_bytes=_canonical(model).encode("ascii")
            ),
            s.verify_supplied_semver_interval_analysis(report, model=model),
        )
        for value in controls:
            with self.subTest(entry=type(value).__name__):
                self.assertEqual(value.to_json(), expected)

    def test_normative_prerelease_chain(self) -> None:
        versions = (
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        )
        for left, right in zip(versions, versions[1:], strict=False):
            with self.subTest(left=left, right=right):
                self.assertEqual(self.relation(left, right), "less")
                self.assertEqual(self.relation(right, left), "greater")

    def test_numeric_ascii_and_prefix_identifier_ordering(self) -> None:
        controls = (
            ("1.0.0-9", "1.0.0-10"),
            ("1.0.0-9", "1.0.0-A"),
            ("1.0.0-A", "1.0.0-a"),
            ("1.0.0-a", "1.0.0-a.0"),
            ("1.0.0-a-", "1.0.0-a0"),
            ("1.0.0-01a", "1.0.0-A"),
            ("1.0.0-zzzz", "1.0.0"),
        )
        for left, right in controls:
            with self.subTest(left=left, right=right):
                self.assertEqual(self.relation(left, right), "less")

    def test_build_metadata_is_retained_but_does_not_order(self) -> None:
        for left, right in (
            ("1.0.0+001", "1.0.0+1"),
            ("1.0.0+a-B.007", "1.0.0+OTHER"),
            ("1.0.0-alpha+first", "1.0.0-alpha+second"),
        ):
            with self.subTest(left=left):
                document = s.analyze_supplied_semver_intervals(_pair(left, right)).to_dict()
                self.assertEqual(document["comparisons"][0]["relation"], "equal")
                self.assertEqual(document["parsed_versions"][0]["version"], left)
                self.assertEqual(document["parsed_versions"][1]["version"], right)
                self.assertNotEqual(
                    document["parsed_versions"][0]["build_metadata"],
                    document["parsed_versions"][1]["build_metadata"],
                )

    def test_large_decimal_core_is_not_integer_conversion(self) -> None:
        # Both are larger than signed64 and retain all bounded decimal digits.
        smaller = "9" * 507 + ".0.0"
        larger = "1" + "0" * 507 + ".0.0"
        document = s.analyze_supplied_semver_intervals(_pair(smaller, larger)).to_dict()
        self.assertEqual(len(larger), 512)
        self.assertEqual(document["comparisons"][0]["relation"], "less")
        self.assertEqual(document["parsed_versions"][1]["core"]["major"], larger[:-4])
        with patch.object(s, "_integer", side_effect=AssertionError("version int conversion")):
            produced = s.analyze_supplied_semver_intervals(_pair(smaller, larger))
        # Export correctly parses the report's ordinary JSON schema/budget integers.
        self.assertEqual(produced.analysis_id, document["analysis_id"])

    def test_independent_1296_pair_ordering_oracle(self) -> None:
        versions = tuple(
            f"{major}.{minor}.0{suffix}"
            for major, minor, suffix in itertools.product(
                range(3), range(2), ("", "-0", "-1", "-alpha", "-alpha.1", "-alpha.beta")
            )
        )
        pairs = list(itertools.product(range(len(versions)), repeat=2))
        self.assertEqual(len(pairs), 1296)
        count = 0
        for start in range(0, len(pairs), s.MAX_COMPARISONS):
            model = _model(versions)
            batch = pairs[start : start + s.MAX_COMPARISONS]
            model["comparisons"] = [
                {
                    "comparison_id": f"c{start + index}",
                    "left_version_id": f"v{left}",
                    "right_version_id": f"v{right}",
                }
                for index, (left, right) in enumerate(batch)
            ]
            observed = s.analyze_supplied_semver_intervals(model).to_dict()["comparisons"]
            for (left, right), row in zip(batch, observed, strict=True):
                a, b = _oracle_key(versions[left]), _oracle_key(versions[right])
                self.assertEqual(
                    row["relation"], "less" if a < b else "greater" if a > b else "equal"
                )
                self.assertIs(row["precedence_equal"], a == b)
                count += 1
        self.assertEqual(count, 1296)

    def test_independent_504_interval_membership_oracle(self) -> None:
        versions = ("0.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0", "1.0.0+x", "2.0.0")
        model = _model(versions)
        oracle = []
        for left in range(len(versions)):
            for right in range(left, len(versions)):
                for include_left, include_right in itertools.product((False, True), repeat=2):
                    name = f"i{len(model['intervals'])}"
                    model["intervals"].append(
                        {
                            "interval_id": name,
                            "lower": _bound(versions[left], include_left),
                            "upper": _bound(versions[right], include_right),
                        }
                    )
                    for index, value in enumerate(versions):
                        model["membership_queries"].append(
                            {
                                "query_id": f"q{len(oracle)}",
                                "version_id": f"v{index}",
                                "interval_id": name,
                            }
                        )
                        key, a, b = (
                            _oracle_key(value),
                            _oracle_key(versions[left]),
                            _oracle_key(versions[right]),
                        )
                        oracle.append(
                            (key > a or (include_left and key == a))
                            and (key < b or (include_right and key == b))
                        )
        self.assertEqual((len(model["intervals"]), len(oracle)), (84, 504))
        observed = s.analyze_supplied_semver_intervals(model).to_dict()["memberships"]
        self.assertEqual([row["membership"] == "inside" for row in observed], oracle)

    def test_unbounded_and_one_sided_intervals_include_prereleases(self) -> None:
        model = _model(("1.0.0-alpha", "1.0.0", "2.0.0"))
        model["intervals"] = [
            {"interval_id": "all", "lower": None, "upper": None},
            {"interval_id": "upper", "lower": None, "upper": _bound("1.0.0", False)},
            {"interval_id": "lower", "lower": _bound("1.0.0", True), "upper": None},
        ]
        model["membership_queries"] = [
            {"query_id": f"q{index}", "version_id": version, "interval_id": interval}
            for index, (version, interval) in enumerate(
                (("v0", "all"), ("v0", "upper"), ("v1", "upper"), ("v1", "lower"), ("v2", "lower"))
            )
        ]
        rows = s.analyze_supplied_semver_intervals(model).to_dict()["memberships"]
        self.assertEqual(
            [row["membership"] for row in rows], ["inside", "inside", "outside", "inside", "inside"]
        )
        self.assertEqual(
            (rows[0]["lower_check"], rows[0]["upper_check"]), ("unbounded", "unbounded")
        )

    def test_equal_open_bounds_are_empty_and_closed_build_bounds_are_one_class(self) -> None:
        for left, right in itertools.product((False, True), repeat=2):
            with self.subTest(left=left, right=right):
                model = _model(("1.0.0+elsewhere",))
                model["intervals"] = [
                    {
                        "interval_id": "i",
                        "lower": _bound("1.0.0+a", left),
                        "upper": _bound("1.0.0+b", right),
                    }
                ]
                model["membership_queries"] = [
                    {"query_id": "q", "version_id": "v0", "interval_id": "i"}
                ]
                document = s.analyze_supplied_semver_intervals(model).to_dict()
                self.assertIs(document["intervals"][0]["empty"], not (left and right))
                self.assertEqual(
                    document["memberships"][0]["membership"],
                    "inside" if left and right else "outside",
                )

    def test_reversed_bounds_are_schema_denial_before_hash(self) -> None:
        for lower, upper in (
            ("2.0.0", "1.0.0"),
            ("1.0.0", "1.0.0-alpha"),
            ("1.0.0-beta.11", "1.0.0-beta.2"),
        ):
            with self.subTest(lower=lower):
                model = _model()
                model["intervals"] = [
                    {
                        "interval_id": "i",
                        "lower": _bound(lower, False),
                        "upper": _bound(upper, True),
                    }
                ]
                self.reject_before_digest(model)

    def test_invalid_semver_grammar_is_not_normalized(self) -> None:
        invalid = (
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1..3",
            ".2.3",
            "1.2.",
            "-1.2.3",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-01",
            "1.2.3-a.01",
            "1.2.3-a..b",
            "1.2.3+a..b",
            "1.2.3++x",
            "1.2.3-a_b",
            "1.2.3+a_b",
            " 1.2.3",
            "1.2.3 ",
            ">=1.2.3",
            "^1.2.3",
            "~1.2.3",
            "1.2.*",
            "1.2.3+\n",
            "1.2.3-\u00e9",
            "1.2.3-\ud800",
        )
        for version in invalid:
            with self.subTest(version=repr(version)):
                self.reject_before_digest(_model((version,)))

    def test_identifier_count_and_version_length_exact_boundaries(self) -> None:
        for version in (
            "9" * 508 + ".0.0",
            "1.0.0-" + ".".join(["a"] * 64),
            "1.0.0-" + ".".join(["a"] * 32) + "+" + ".".join(["0"] * 32),
        ):
            with self.subTest(version=version[:20]):
                self.assertEqual(
                    s.analyze_supplied_semver_intervals(_model((version,))).to_dict()[
                        "parsed_versions"
                    ][0]["version"],
                    version,
                )
        for version in ("9" * 509 + ".0.0", "1.0.0+" + ".".join(["a"] * 65)):
            with self.subTest(length=len(version)):
                self.reject_before_digest(_model((version,)))

    def test_empty_model_is_a_supported_empty_arithmetic_report(self) -> None:
        document = s.analyze_supplied_semver_intervals(_model()).to_dict()
        for key in ("parsed_versions", "comparisons", "intervals", "memberships"):
            self.assertEqual(document[key], [])
        self.assertEqual(document["source_model"], _model())

    def test_duplicate_typed_ids_and_dangling_refs_precede_version_parse(self) -> None:
        controls = []
        for table in ("versions", "comparisons", "intervals", "membership_queries"):
            model = s.component_fixture()
            model[table].append(copy.deepcopy(model[table][0]))
            controls.append(model)
        for table, key in (
            ("comparisons", "left_version_id"),
            ("comparisons", "right_version_id"),
            ("membership_queries", "version_id"),
            ("membership_queries", "interval_id"),
        ):
            model = s.component_fixture()
            model[table][0][key] = "absent"
            controls.append(model)
        for index, model in enumerate(controls):
            with (
                self.subTest(index=index),
                patch.object(s, "_parse", side_effect=AssertionError("parse reached")),
            ):
                self.reject_before_digest(model)

    def test_typed_id_namespaces_equal_labels_and_case_sensitive_refs(self) -> None:
        model = _pair("1.0.0", "1.0.0")
        model["comparisons"][0]["comparison_id"] = "v0"
        model["intervals"] = [{"interval_id": "v0", "lower": None, "upper": None}]
        model["membership_queries"] = [{"query_id": "v0", "version_id": "v0", "interval_id": "v0"}]
        self.assertEqual(
            s.analyze_supplied_semver_intervals(model).to_dict()["comparisons"][0]["relation"],
            "equal",
        )
        model["comparisons"][0]["left_version_id"] = "V0"
        self.reject_before_digest(model)

    def test_list_permutation_preserves_math_but_not_source_identity(self) -> None:
        first = s.component_fixture()
        second = copy.deepcopy(first)
        for name in ("versions", "comparisons", "intervals", "membership_queries"):
            second[name].reverse()
        a = s.analyze_supplied_semver_intervals(first).to_dict()
        b = s.analyze_supplied_semver_intervals(second).to_dict()
        self.assertNotEqual(a["analysis_sha256"], b["analysis_sha256"])
        self.assertEqual(
            {row["comparison_id"]: row for row in a["comparisons"]},
            {row["comparison_id"]: row for row in b["comparisons"]},
        )
        self.assertEqual(
            {row["query_id"]: row for row in a["memberships"]},
            {row["query_id"]: row for row in b["memberships"]},
        )

    def test_closed_shape_missing_unknown_and_malformed_records_deny(self) -> None:
        controls = []
        model = s.component_fixture()
        del model["comparisons"]
        controls.append(model)
        model = s.component_fixture()
        model["npm_range"] = "*"
        controls.append(model)
        for table in ("versions", "comparisons", "intervals", "membership_queries"):
            for mutation in (None, [], {"unknown": "x"}):
                model = s.component_fixture()
                model[table][0] = mutation
                controls.append(model)
        for index, model in enumerate(controls):
            with self.subTest(index=index):
                self.reject_before_digest(model)

    def test_exact_native_schema_bounds_and_array_types(self) -> None:
        for schema in (True, False, 1.0, "1", None, 2):
            model = _model()
            model["schema_version"] = schema
            with self.subTest(schema=schema):
                self.reject_before_digest(model)
        for inclusive in (0, 1, 0.0, 1.0, "true", None):
            model = _model()
            model["intervals"] = [
                {"interval_id": "i", "lower": _bound("1.0.0", inclusive), "upper": None}
            ]
            with self.subTest(inclusive=inclusive):
                self.reject_before_digest(model)
        for table in ("versions", "comparisons", "intervals", "membership_queries"):
            model = _model()
            model[table] = ()
            with self.subTest(table=table):
                self.reject_before_digest(model)

    def test_native_alias_classes_cannot_enter_source_or_report(self) -> None:
        class Text(str):
            pass

        class Number(int):
            pass

        class Mapping(dict):
            pass

        class Array(list):
            pass

        for value in (Mapping(_model()),):
            self.reject_before_digest(value)
        for key, value in (("schema_version", Number(1)), ("versions", Array())):
            model = _model()
            model[key] = value
            self.reject_before_digest(model)
        model = _model((Text("1.0.0"),))
        self.reject_before_digest(model)
        model = _model()
        model[Text("schema_version")] = model.pop("schema_version")
        self.reject_before_digest(model)
        document = s.analyze_supplied_semver_intervals(_model()).to_dict()
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.SemverIntervalAnalysis.from_dict(Mapping(document))

    def test_cycles_repeated_subtrees_and_large_native_int_precede_serialization(self) -> None:
        cycle = []
        cycle.append(cycle)
        model = _model()
        model["versions"] = cycle
        with patch.object(s.json, "dumps", side_effect=AssertionError("dump reached")):
            self.reject_before_digest(model)
            model = _model()
            model["schema_version"] = 10**5000
            self.reject_before_digest(model)
            subtree = [None] * 1000
            model = _model()
            model["versions"] = [subtree] * 40
            self.reject_before_digest(model)

    def test_fixed_table_limits_are_checked_before_parse_and_hash(self) -> None:
        for table, maximum in (
            ("versions", s.MAX_VERSIONS),
            ("comparisons", s.MAX_COMPARISONS),
            ("intervals", s.MAX_INTERVALS),
            ("membership_queries", s.MAX_MEMBERSHIPS),
        ):
            model = _model()
            model[table] = [None] * (maximum + 1)
            with (
                self.subTest(table=table),
                patch.object(s, "_parse", side_effect=AssertionError("parse reached")),
            ):
                self.reject_before_digest(model)

    def test_valid_table_maxima_are_supported_with_short_records(self) -> None:
        model = _model(tuple("1.0.0" for _ in range(s.MAX_VERSIONS)))
        model["comparisons"] = [
            {"comparison_id": f"c{i}", "left_version_id": "v0", "right_version_id": "v1"}
            for i in range(s.MAX_COMPARISONS)
        ]
        model["intervals"] = [
            {"interval_id": f"i{i}", "lower": None, "upper": None} for i in range(s.MAX_INTERVALS)
        ]
        model["membership_queries"] = [
            {"query_id": f"q{i}", "version_id": "v0", "interval_id": "i0"}
            for i in range(s.MAX_MEMBERSHIPS)
        ]
        report = s.analyze_supplied_semver_intervals(model).to_dict()
        self.assertEqual(len(report["parsed_versions"]), 256)
        self.assertEqual(len(report["comparisons"]), 256)
        self.assertEqual(len(report["intervals"]), 128)
        self.assertEqual(len(report["memberships"]), 512)

    def test_identifier_native_ascii_and_length_limits(self) -> None:
        for identifier in ("", "-bad", "a:b", "a/b", "a ", "\u00e9", "a" * 65, 1, True):
            model = _model(("1.0.0",))
            model["versions"][0]["version_id"] = identifier
            with self.subTest(identifier=identifier):
                self.reject_before_digest(model)
        model = _model(("1.0.0",))
        model["versions"][0]["version_id"] = "a" * 64
        self.assertEqual(
            s.analyze_supplied_semver_intervals(model).to_dict()["parsed_versions"][0][
                "version_id"
            ],
            "a" * 64,
        )

    def test_duplicate_json_keys_at_every_supplied_level_deny(self) -> None:
        base = _canonical(s.component_fixture())
        mutations = (
            base.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            base.replace('"version_id":"beta2"', '"version_id":"beta2","version_id":"other"', 1),
            base.replace('"inclusive":true', '"inclusive":true,"inclusive":false', 1),
            base.replace(
                '"comparison_id":"numeric-prerelease"',
                '"comparison_id":"numeric-prerelease","comparison_id":"other"',
                1,
            ),
            base.replace('"schema_version":1', '"schema_version":1,"schema_\\u0076ersion":1', 1),
        )
        for raw in mutations:
            with self.subTest(raw=raw[:50]), self.assertRaises(s.SemverIntervalAnalysisError):
                s.analyze_supplied_semver_intervals_bytes(model_bytes=raw.encode("ascii"))

    def test_raw_float_nonfinite_integer_overflow_and_malformed_tokens_predecode(self) -> None:
        for token in (
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "-Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "--1",
            "01",
            "-",
            "1" * 21,
        ):
            with self.subTest(token=token):
                self.reject_before_decoder('{"schema_version":' + token + "}")

    def test_raw_depth_nodes_and_string_limits_precede_decoder(self) -> None:
        controls = (
            "[" * s.MAX_MODEL_DEPTH + "0" + "]" * s.MAX_MODEL_DEPTH,
            "[" + ",".join("0" for _ in range(s.MAX_MODEL_NODES)) + "]",
            '{"x":"' + "a" * (s.MAX_VERSION_BYTES + 1) + '"}',
            '{"x":"\\uD800"}',
            '{"x":"\\u0000"}',
        )
        for text in controls:
            with self.subTest(length=len(text)):
                self.reject_before_decoder(text)
        with patch.object(s.json, "loads", wraps=json.loads) as decoder:
            with self.assertRaises(s.SemverIntervalAnalysisError):
                s.analyze_supplied_semver_intervals_bytes(
                    model_bytes=("[" * 15 + "0" + "]" * 15).encode("ascii")
                )
            self.assertEqual(decoder.call_count, 1)

    def test_raw_and_native_model_byte_limits_precede_hash(self) -> None:
        raw = _canonical(_model())
        exact = raw + " " * (s.MAX_MODEL_BYTES - len(raw))
        self.assertEqual(
            s.analyze_supplied_semver_intervals_bytes(model_bytes=exact.encode("ascii")).to_dict()[
                "source_model"
            ],
            _model(),
        )
        with (
            patch.object(s.json, "loads", side_effect=AssertionError("decoder reached")),
            self.assertRaises(s.SemverIntervalAnalysisError),
        ):
            s.analyze_supplied_semver_intervals_bytes(model_bytes=(exact + " ").encode("ascii"))
        with (
            patch.object(s, "MAX_MODEL_BYTES", 10),
            patch.object(s.json, "dumps", side_effect=AssertionError("dump reached")),
        ):
            self.reject_before_digest(_model())

    def test_exact_bytes_and_json_families_are_required(self) -> None:
        raw = _canonical(_model()).encode("ascii")
        for value in (
            bytearray(raw),
            memoryview(raw),
            raw.decode("ascii"),
            b"",
            b"\xff",
            b"\xef\xbb\xbf" + raw,
        ):
            with (
                self.subTest(kind=type(value).__name__),
                self.assertRaises(s.SemverIntervalAnalysisError),
            ):
                s.analyze_supplied_semver_intervals_bytes(model_bytes=value)
        for value in (None, b"{}", "", 1):
            with self.assertRaises(s.SemverIntervalAnalysisError):
                s.SemverIntervalAnalysis.from_json(value)

    def test_raw_copy_work_is_reserved_before_parser_entry(self) -> None:
        raw = _canonical(_model()).encode("ascii")
        with (
            patch.object(s, "MAX_WORK", len(raw) - 1),
            patch.object(s, "_decode", side_effect=AssertionError("parser reached")),
            patch.object(s.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaises(s.SemverIntervalAnalysisError),
        ):
            s.analyze_supplied_semver_intervals_bytes(model_bytes=raw)

    def test_json_formatting_and_escapes_are_parsed_snapshot_not_raw_provenance(self) -> None:
        model = s.component_fixture()
        canonical = s.analyze_supplied_semver_intervals(model).to_json()
        pretty = json.dumps(model, indent=2).replace("beta2", "beta\\u0032")
        self.assertEqual(
            s.analyze_supplied_semver_intervals_bytes(model_bytes=pretty.encode("ascii")).to_json(),
            canonical,
        )
        self.assertNotEqual(pretty.encode("ascii"), _canonical(model).encode("ascii"))

    def test_full_report_byte_and_node_denial_precedes_any_address_hash(self) -> None:
        model = s.component_fixture()
        real = s.analyze_supplied_semver_intervals(model).to_dict()
        with (
            patch.object(s, "MAX_REPORT_BYTES", len(_canonical(real)) - 1),
            patch.object(s.json, "dumps", side_effect=AssertionError("dump reached")),
        ):
            self.reject_before_digest(model)
        budget = s._Budget()
        _, _, nodes = s._capture(real, budget, report=True)
        with patch.object(s, "MAX_REPORT_NODES", nodes - 1):
            self.reject_before_digest(model)

    def test_genuine_bounded_source_exhausts_retained_report_nodes_before_hash(self) -> None:
        label = "1.0.0-" + ".".join(["a"] * s.MAX_VERSION_IDENTIFIERS)
        model = _model(tuple(label for _ in range(s.MAX_VERSIONS)))
        self.assertLess(len(_canonical(model)), s.MAX_MODEL_BYTES)
        # Each parsed identifier is a five-node record. All source labels fit,
        # but their exact parsed projections alone exceed the report node cap.
        self.assertGreater(s.MAX_VERSIONS * s.MAX_VERSION_IDENTIFIERS * 5, s.MAX_REPORT_NODES)
        with patch.object(s.json, "dumps", side_effect=AssertionError("dump reached")):
            self.reject_before_digest(model)
        with (
            patch.object(s.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaisesRegex(s.SemverIntervalAnalysisError, "retained result"),
        ):
            s.analyze_supplied_semver_intervals(model)

    def test_cumulative_work_budget_is_not_reset_during_export_or_verification(self) -> None:
        model = s.component_fixture()
        report = s.analyze_supplied_semver_intervals(model)
        producer = s._Budget()
        s._derive(model, producer)
        export = s._Budget()
        s._capture_report(report, export)
        self.assertGreater(export.work, producer.work)
        with (
            patch.object(s, "MAX_WORK", producer.work),
            self.assertRaises(s.SemverIntervalAnalysisError),
        ):
            report.to_dict()
        with patch.object(s, "MAX_WORK", export.work):
            self.assertEqual(report.to_dict()["source_model"], model)
            with self.assertRaises(s.SemverIntervalAnalysisError):
                s.verify_supplied_semver_interval_analysis(report, model=model)
        with (
            patch.object(s, "MAX_WORK", 0),
            patch.object(s.json, "dumps", side_effect=AssertionError("dump reached")),
        ):
            self.reject_before_digest(model)

    def test_false_comparison_membership_and_parsed_source_rehash_is_not_replay(self) -> None:
        original = s.analyze_supplied_semver_intervals(s.component_fixture()).to_dict()
        changes = (
            lambda d: d["comparisons"][0].update(relation="greater", precedence_equal=False),
            lambda d: d["memberships"][0].update(membership="outside"),
            lambda d: d["parsed_versions"][0]["core"].update(major="2"),
            lambda d: d["parsed_versions"][0]["prerelease"][1].update(numeric=False),
            lambda d: d["parsed_versions"][2].update(build_metadata=["other"]),
            lambda d: d["intervals"][0].update(empty=True),
        )
        for index, change in enumerate(changes):
            document = copy.deepcopy(original)
            change(document)
            _rehash(document)
            with self.subTest(index=index):
                with self.assertRaises(s.SemverIntervalAnalysisError):
                    s.SemverIntervalAnalysis.from_dict(document)
                with self.assertRaises(s.SemverIntervalAnalysisError):
                    s.SemverIntervalAnalysis.from_json(_canonical(document))

    def test_native_report_aliases_never_replay_original_canonical_identity(self) -> None:
        original = s.analyze_supplied_semver_intervals(s.component_fixture()).to_dict()
        for field, value in (("schema_version", True), ("schema_version", 1.0)):
            document = copy.deepcopy(original)
            document[field] = value
            self.assertNotEqual(_canonical(document), _canonical(original))
            with self.assertRaises(s.SemverIntervalAnalysisError):
                s.SemverIntervalAnalysis.from_dict(document)
        document = copy.deepcopy(original)
        document["comparisons"][2]["precedence_equal"] = 1
        self.assertEqual(document, original)
        self.assertNotEqual(_canonical(document), _canonical(original))
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.SemverIntervalAnalysis.from_dict(document)

    def test_cohashed_effect_or_qualification_promotion_is_rejected(self) -> None:
        original = s.analyze_supplied_semver_intervals(s.component_fixture()).to_dict()
        for category, key, value in (
            ("flags", "vulnerability_verified", True),
            ("flags", "live_use_approved", True),
            ("effects", "execution", "allowed"),
            ("effects", "authority", "granted"),
        ):
            document = copy.deepcopy(original)
            document[category][key] = value
            _rehash(document)
            with self.subTest(key=key), self.assertRaises(s.SemverIntervalAnalysisError):
                s.SemverIntervalAnalysis.from_dict(document)

    def test_build_only_source_change_fails_separate_original_verification(self) -> None:
        first = _pair("1.0.0+a", "1.0.0+b")
        second = _pair("1.0.0+a", "1.0.0+c")
        report = s.analyze_supplied_semver_intervals(second)
        self.assertEqual(report.to_dict()["comparisons"][0]["relation"], "equal")
        self.assertEqual(
            s.verify_supplied_semver_interval_analysis(report, model=second).to_json(),
            report.to_json(),
        )
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.verify_supplied_semver_interval_analysis(report, model=first)

    def test_coherently_changed_embedded_model_is_not_original_source_proof(self) -> None:
        first = _pair("1.0.0", "2.0.0")
        second = _pair("2.0.0", "1.0.0")
        report = s.analyze_supplied_semver_intervals(second)
        parsed = s.SemverIntervalAnalysis.from_json(report.to_json())
        self.assertEqual(parsed.to_dict()["comparisons"][0]["relation"], "greater")
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.verify_supplied_semver_interval_analysis(parsed, model=first)

    def test_exports_fixture_and_original_graph_are_detached(self) -> None:
        model = s.component_fixture()
        report = s.analyze_supplied_semver_intervals(model)
        expected = report.to_json()
        model["versions"][0]["version"] = "9.0.0"
        exported = report.to_dict()
        exported["source_model"]["versions"].clear()
        exported["comparisons"][0]["relation"] = "greater"
        self.assertEqual(report.to_json(), expected)
        self.assertEqual(s.component_fixture()["versions"][0]["version"], "1.0.0-beta.2")
        with self.assertRaises(FrozenInstanceError):
            report._document_json = "{}"

    def test_forged_wrapper_and_missing_slot_reject_before_positive_export(self) -> None:
        valid = s.analyze_supplied_semver_intervals(s.component_fixture())
        false = valid.to_dict()
        false["comparisons"][0]["relation"] = "greater"
        _rehash(false)
        forged = object.__new__(s.SemverIntervalAnalysis)
        object.__setattr__(forged, "_document_json", _canonical(false))
        missing = object.__new__(s.SemverIntervalAnalysis)
        for report in (forged, missing):
            for consumer in (
                report.to_dict,
                report.to_json,
                lambda report=report: s.verify_supplied_semver_interval_analysis(
                    report, model=s.component_fixture()
                ),
            ):
                with self.assertRaises(s.SemverIntervalAnalysisError):
                    consumer()

    def test_report_duplicate_json_and_unknown_fields_are_rejected(self) -> None:
        report = s.analyze_supplied_semver_intervals(s.component_fixture())
        raw = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.SemverIntervalAnalysis.from_json(raw)
        document = report.to_dict()
        document["effective_vulnerability"] = False
        _rehash(document)
        with self.assertRaises(s.SemverIntervalAnalysisError):
            s.SemverIntervalAnalysis.from_dict(document)

    def test_lane_flags_and_effects_are_nonqualifying(self) -> None:
        report = s.analyze_supplied_semver_intervals(s.component_fixture()).to_dict()
        self.assertEqual(
            (report["profile_id"], report["capability_id"], report["wave_id"]),
            ("AOE-GC-D17-S04", "army.gc.d17.s04", "IW2-016"),
        )
        self.assertEqual(report["roadmap_package_ids"], ["A7.4"])
        self.assertTrue(all(value is False for value in report["flags"].values()))
        self.assertTrue(all(value == "none" for value in report["effects"].values()))
        self.assertEqual(report["input_provenance"], "caller_supplied_unverified")


if __name__ == "__main__":
    unittest.main()
