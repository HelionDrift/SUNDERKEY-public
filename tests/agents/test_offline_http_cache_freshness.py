"""Independent integer-grid, boundary and replay controls for cache arithmetic."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_http_cache_freshness as cache

ERROR = cache.HttpCacheFreshnessAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def case(**changes):
    return {
        "case_id": "synthetic",
        "cache_kind": "shared",
        "request_time_seconds": 1000,
        "response_time_seconds": 1005,
        "evaluated_at_seconds": 1020,
        "date_value_seconds": 998,
        "age_value_seconds": 3,
        "max_age_seconds": 60,
        "s_maxage_seconds": 30,
        "expires_value_seconds": 1100,
        **changes,
    }


def model(cases=None):
    return {"schema_version": 1, "cases": [case()] if cases is None else cases}


def component_fixture():
    return cache.component_fixture()


def observe(**changes):
    return cache.analyze_supplied_http_cache_freshness(model([case(**changes)])).to_dict()[
        "case_observations"
    ][0]


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-http-cache-freshness.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "HCF-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class HttpCacheFreshnessTests(unittest.TestCase):
    def deny_before_hash(self, value):
        with (
            patch.object(cache, "_address") as address,
            patch.object(cache.hashlib, "sha256") as digest,
        ):
            with self.assertRaises(ERROR):
                cache.analyze_supplied_http_cache_freshness(value)
            address.assert_not_called()
            digest.assert_not_called()

    def raw_before_decoder(self, text):
        with (
            patch.object(cache.json, "loads") as decoder,
            patch.object(cache, "_address") as address,
        ):
            with self.assertRaises(ERROR):
                cache.HttpCacheFreshnessAnalysis.from_json(text)
            decoder.assert_not_called()
            address.assert_not_called()

    def test_real_fixture_literal_identity_and_outcomes(self):
        document = cache.analyze_supplied_http_cache_freshness(component_fixture()).to_dict()
        self.assertEqual(document["analysis_id"], "HCF-0BAD647F4D3912738A81DF19809036A5")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:0bad647f4d3912738a81df19809036a525ade12999384344c1a0fa903e51bb67",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:f606de94e82cbfc57f697a0dbdad503f795855cfe47d15f37a9d748a95e87796",
        )
        rows = document["case_observations"]
        self.assertEqual([row["current_age_seconds"] for row in rows], [23, 23, 23])
        self.assertEqual([row["freshness_lifetime_seconds"] for row in rows], [23, 60, None])
        self.assertEqual([row["freshness_comparison"] for row in rows], [False, True, None])
        self.assertEqual(
            [row["outcome"] for row in rows],
            [
                "not_fresh_under_supplied_arithmetic",
                "fresh_under_supplied_arithmetic",
                "unassessed",
            ],
        )
        self.assertEqual(
            rows[2]["unassessed_reasons"], ["no_explicit_lifetime_heuristics_unassessed"]
        )

    def test_roundtrips_properties_and_separate_original_verification(self):
        original = component_fixture()
        report = cache.analyze_supplied_http_cache_freshness(original)
        document = report.to_dict()
        for rebuilt in (
            cache.HttpCacheFreshnessAnalysis(document),
            cache.HttpCacheFreshnessAnalysis.from_dict(document),
            cache.HttpCacheFreshnessAnalysis.from_json(report.to_json()),
            cache.analyze_supplied_http_cache_freshness_bytes(
                model_bytes=canonical(original).encode("ascii")
            ),
            cache.verify_supplied_http_cache_freshness_analysis(report, model=original),
        ):
            self.assertEqual(rebuilt.to_json(), report.to_json())
            self.assertIsNot(rebuilt, report)
        self.assertEqual(report.analysis_id, document["analysis_id"])
        self.assertEqual(report.analysis_sha256, document["analysis_sha256"])

    def test_independent_simplified_integer_grid_age_oracle(self):
        pending = []
        expected = {}
        count = 0
        for request in range(3):
            for response in range(request, 4):
                for evaluated in range(response, 5):
                    for date, age in itertools.product(range(-2, 7), range(4)):
                        identifier = f"grid-{count}"
                        count += 1
                        pending.append(
                            case(
                                case_id=identifier,
                                request_time_seconds=request,
                                response_time_seconds=response,
                                evaluated_at_seconds=evaluated,
                                date_value_seconds=date,
                                age_value_seconds=age,
                                max_age_seconds=10,
                                s_maxage_seconds=None,
                                expires_value_seconds=None,
                            )
                        )
                        # Under the admitted chronology, response time cancels algebraically.
                        expected[identifier] = max(evaluated - date, age + evaluated - request)
        self.assertEqual(count, 1008)
        for start in range(0, count, 128):
            rows = cache.analyze_supplied_http_cache_freshness(model(pending[start : start + 128]))
            for row in rows.to_dict()["case_observations"]:
                with self.subTest(identifier=row["case_id"]):
                    self.assertEqual(row["current_age_seconds"], expected[row["case_id"]])
                    self.assertIs(row["freshness_comparison"], expected[row["case_id"]] < 10)

    def test_all_shared_private_lifetime_presence_precedence(self):
        for kind, s_present, max_present, expires_present in itertools.product(
            ("shared", "private"), (False, True), (False, True), (False, True)
        ):
            row = observe(
                cache_kind=kind,
                s_maxage_seconds=11 if s_present else None,
                max_age_seconds=41 if max_present else None,
                expires_value_seconds=1071 if expires_present else None,
            )
            if kind == "shared" and s_present:
                source, lifetime = "shared_s_maxage", 11
            elif max_present:
                source, lifetime = "max_age", 41
            elif expires_present:
                source, lifetime = "expires_minus_effective_date", 73
            else:
                source, lifetime = "no_explicit_lifetime", None
            self.assertEqual(
                (row["lifetime_source"], row["freshness_lifetime_seconds"]), (source, lifetime)
            )
            self.assertIs(row["freshness_comparison"], None if lifetime is None else lifetime > 23)

    def test_zero_directive_is_present_and_not_a_fallback(self):
        shared = observe(s_maxage_seconds=0)
        private = observe(cache_kind="private", max_age_seconds=0)
        self.assertEqual(shared["lifetime_source"], "shared_s_maxage")
        self.assertEqual(private["lifetime_source"], "max_age")
        self.assertEqual(shared["freshness_lifetime_seconds"], 0)
        self.assertEqual(private["freshness_lifetime_seconds"], 0)
        self.assertFalse(shared["freshness_comparison"])
        self.assertFalse(private["freshness_comparison"])

    def test_lifetime_strictly_greater_than_age_equality_is_not_fresh(self):
        for lifetime, fresh in ((22, False), (23, False), (24, True)):
            row = observe(s_maxage_seconds=lifetime)
            self.assertIs(row["freshness_comparison"], fresh)
        zero = observe(
            request_time_seconds=0,
            response_time_seconds=0,
            evaluated_at_seconds=0,
            date_value_seconds=0,
            age_value_seconds=0,
            s_maxage_seconds=0,
        )
        self.assertEqual(zero["current_age_seconds"], 0)
        self.assertIs(zero["freshness_comparison"], False)

    def test_genuine_trace_accounts_for_age_and_response_delay(self):
        row = observe()
        self.assertEqual(
            [
                row[name]
                for name in (
                    "apparent_age_seconds",
                    "response_delay_seconds",
                    "corrected_age_value_seconds",
                    "corrected_initial_age_seconds",
                    "resident_time_seconds",
                    "current_age_seconds",
                )
            ],
            [7, 5, 8, 8, 15, 23],
        )
        self.assertEqual(observe(age_value_seconds=0)["current_age_seconds"], 22)
        self.assertEqual(observe(date_value_seconds=900)["current_age_seconds"], 120)

    def test_response_clock_variation_preserves_simplified_age_not_trace(self):
        delays = []
        for response in (1000, 1005, 1010, 1020):
            row = observe(response_time_seconds=response)
            self.assertEqual(row["current_age_seconds"], 23)
            delays.append(row["response_delay_seconds"])
        self.assertEqual(delays, [0, 5, 10, 20])

    def test_future_date_apparent_age_clamps_zero_without_claiming_clock_truth(self):
        row = observe(date_value_seconds=1200)
        self.assertEqual(row["apparent_age_seconds"], 0)
        self.assertEqual(row["current_age_seconds"], 23)
        self.assertTrue(row["freshness_comparison"])

    def test_absent_age_is_explicit_zero_not_an_unknown_projection(self):
        absent = observe(age_value_seconds=None)
        zero = observe(age_value_seconds=0)
        self.assertEqual(absent["current_age_seconds"], zero["current_age_seconds"])
        self.assertEqual(absent["effective_age_seconds"], 0)
        self.assertEqual(absent["age_value_source"], "declared_absent_age_zero")
        self.assertNotEqual(absent["age_value_source"], zero["age_value_source"])
        with self.assertRaises(ERROR):
            observe(age_value_seconds="unknown")

    def test_absent_date_receipt_time_substitution_is_only_arithmetic(self):
        row = observe(
            date_value_seconds=None,
            s_maxage_seconds=None,
            max_age_seconds=None,
            expires_value_seconds=1030,
        )
        self.assertEqual(row["effective_date_seconds"], 1005)
        self.assertEqual(row["effective_date_source"], "declared_response_time_for_absent_date")
        self.assertEqual(row["apparent_age_seconds"], 0)
        self.assertEqual(row["freshness_lifetime_seconds"], 25)
        self.assertEqual(row["current_age_seconds"], 23)
        self.assertTrue(row["freshness_comparison"])
        with self.assertRaises(ERROR):
            observe(date_value_seconds="invalid")

    def test_negative_expires_lifetime_is_not_silently_zeroed(self):
        row = observe(s_maxage_seconds=None, max_age_seconds=None, expires_value_seconds=990)
        self.assertEqual(row["freshness_lifetime_seconds"], -8)
        self.assertFalse(row["freshness_comparison"])
        self.assertEqual(row["unassessed_reasons"], [])

    def test_missing_each_clock_is_unassessed_with_partial_observations(self):
        for field, reason in (
            ("request_time_seconds", "request_time_unavailable"),
            ("response_time_seconds", "response_time_unavailable"),
            ("evaluated_at_seconds", "evaluation_time_unavailable"),
        ):
            row = observe(**{field: None})
            self.assertEqual(row["outcome"], "unassessed")
            self.assertIsNone(row["freshness_comparison"])
            self.assertIsNone(row["current_age_seconds"])
            self.assertEqual(row["freshness_lifetime_seconds"], 30)
            self.assertEqual(row["unassessed_reasons"], [reason])
        row = observe(
            date_value_seconds=None,
            response_time_seconds=None,
            s_maxage_seconds=None,
            max_age_seconds=None,
        )
        self.assertIsNone(row["effective_date_seconds"])
        self.assertIsNone(row["freshness_lifetime_seconds"])

    def test_reversed_declared_clocks_do_not_create_negative_or_guessed_age(self):
        for changes, reason in (
            ({"request_time_seconds": 1006}, "declared_request_response_order_inconsistent"),
            ({"evaluated_at_seconds": 1004}, "declared_response_evaluation_order_inconsistent"),
        ):
            row = observe(**changes)
            self.assertEqual(row["outcome"], "unassessed")
            self.assertIsNone(row["current_age_seconds"])
            self.assertEqual(row["unassessed_reasons"], [reason])

    def test_no_explicit_lifetime_does_not_invent_a_heuristic_or_reuse_denial(self):
        row = observe(s_maxage_seconds=None, max_age_seconds=None, expires_value_seconds=None)
        self.assertEqual(row["current_age_seconds"], 23)
        self.assertIsNone(row["freshness_lifetime_seconds"])
        self.assertEqual(row["outcome"], "unassessed")
        row = observe(cache_kind="private", max_age_seconds=None, expires_value_seconds=None)
        self.assertEqual(row["outcome"], "unassessed")

    def test_negative_epoch_instants_and_exact_signed64_boundaries(self):
        shifted = observe(
            request_time_seconds=-100,
            response_time_seconds=-95,
            evaluated_at_seconds=-80,
            date_value_seconds=-102,
            expires_value_seconds=0,
        )
        self.assertEqual(shifted["current_age_seconds"], 23)
        for instant in (cache.MIN_INTEGER, cache.MAX_INTEGER):
            row = observe(
                request_time_seconds=instant,
                response_time_seconds=instant,
                evaluated_at_seconds=instant,
                date_value_seconds=instant,
                age_value_seconds=0,
                s_maxage_seconds=cache.MAX_INTEGER,
            )
            self.assertEqual(row["current_age_seconds"], 0)
            self.assertTrue(row["freshness_comparison"])

    def test_each_age_intermediate_overflow_is_explicitly_unassessed(self):
        low, high = cache.MIN_INTEGER, cache.MAX_INTEGER
        cases = (
            {
                "request_time_seconds": high,
                "response_time_seconds": high,
                "evaluated_at_seconds": high,
                "date_value_seconds": low,
            },
            {
                "request_time_seconds": low,
                "response_time_seconds": high,
                "evaluated_at_seconds": high,
                "date_value_seconds": high,
            },
            {"age_value_seconds": high},
            {
                "request_time_seconds": low,
                "response_time_seconds": low,
                "evaluated_at_seconds": high,
                "date_value_seconds": low,
            },
            {
                "request_time_seconds": 0,
                "response_time_seconds": 0,
                "evaluated_at_seconds": 1,
                "date_value_seconds": 0,
                "age_value_seconds": high,
            },
            {
                "request_time_seconds": low,
                "response_time_seconds": low,
                "evaluated_at_seconds": low,
                "date_value_seconds": high,
            },
        )
        for changes in cases:
            row = observe(**changes)
            self.assertIn("age_arithmetic_outside_signed64", row["unassessed_reasons"])
            self.assertIsNone(row["freshness_comparison"])
            self.assertEqual(row["outcome"], "unassessed")

    def test_expires_subtraction_overflow_is_not_wrapped_or_saturated(self):
        for date, expires in (
            (cache.MIN_INTEGER, cache.MAX_INTEGER),
            (cache.MAX_INTEGER, cache.MIN_INTEGER),
        ):
            row = observe(
                date_value_seconds=date,
                expires_value_seconds=expires,
                max_age_seconds=None,
                s_maxage_seconds=None,
            )
            self.assertIsNone(row["freshness_lifetime_seconds"])
            self.assertIn("lifetime_arithmetic_outside_signed64", row["unassessed_reasons"])
            self.assertIsNone(row["freshness_comparison"])

    def test_native_aliases_and_negative_deltas_fail_before_hash(self):
        for field in (*cache._INSTANTS, *cache._DELTAS):
            for value in (True, False, 1.0, "1", [], {}):
                self.deny_before_hash(model([case(**{field: value})]))
        for field in cache._DELTAS:
            self.deny_before_hash(model([case(**{field: -1})]))
        for field in (*cache._INSTANTS, *cache._DELTAS):
            for value in (cache.MIN_INTEGER - 1, cache.MAX_INTEGER + 1, 2**5000):
                self.deny_before_hash(model([case(**{field: value})]))

    def test_closed_shapes_ids_versions_and_case_limits(self):
        for version in (True, False, 1.0, "1", None, 0, 2):
            self.deny_before_hash({"schema_version": version, "cases": [case()]})
        for cases in ([], (), [case()] * 2, [case(case_id=f"case-{i}") for i in range(129)]):
            self.deny_before_hash(model(cases))
        for changes in (
            {"case_id": ""},
            {"case_id": "x" * 129},
            {"case_id": "bad space"},
            {"cache_kind": "unknown"},
            {"cache_kind": True},
        ):
            self.deny_before_hash(model([case(**changes)]))
        for extra in ("headers", "url", "no_cache", "clock", "credentials"):
            self.deny_before_hash(model([case(**{extra: None})]))
        for field in case():
            incomplete = case()
            incomplete.pop(field)
            self.deny_before_hash(model([incomplete]))
        self.deny_before_hash({**model(), "unknown": None})

    def test_exact_maximum_case_count_preserves_order(self):
        source = model([case(case_id=f"max-{i}") for i in range(128)])
        rows = cache.analyze_supplied_http_cache_freshness(source).to_dict()["case_observations"]
        self.assertEqual([row["case_id"] for row in rows], [f"max-{i}" for i in range(128)])
        self.assertTrue(all(row["current_age_seconds"] == 23 for row in rows))

    def test_native_subclasses_deny_without_normalization_hooks(self):
        class Text(str):
            def __str__(self):
                raise AssertionError("String hook reached")

        class Number(int):
            def __str__(self):
                raise AssertionError("Integer hook reached")

        class Mapping(dict):
            def items(self):
                raise AssertionError("Mapping hook reached")

        class Sequence(list):
            def __iter__(self):
                raise AssertionError("Sequence hook reached")

        for value in (
            Mapping(model()),
            model(Sequence([case()])),
            model([case(case_id=Text("native"))]),
            model([case(age_value_seconds=Number(1))]),
        ):
            with patch.object(cache.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()

    def test_native_dag_cycles_depth_escaping_and_bytes_before_copy(self):
        cycle = []
        cycle.append(cycle)
        shared = ["x" * 256] * 128
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (
            cycle,
            nested,
            [shared] * 40,
            ['"' * 256] * 2100,
            ["\\" * 256] * 2100,
            [None] * 32768,
        ):
            with patch.object(cache.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()

    def test_raw_lexical_integer_limits_precede_decoder(self):
        for token in (
            "--1",
            "---1",
            "--0",
            "-01",
            "01",
            "+1",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "-Infinity",
            "9223372036854775808",
            "-9223372036854775809",
        ):
            self.raw_before_decoder('{"schema_version":' + token + ',"cases":[]}')
        self.raw_before_decoder("9" * 20000)

    def test_raw_depth_nodes_strings_escapes_and_byte_limits_precede_decoder(self):
        for scalar in ("0", "true", "null", '"x"'):
            self.raw_before_decoder("[" * 16 + scalar + "]" * 16)
        for text in (
            "[" + ",".join("0" for _ in range(32768)) + "]",
            '"' + "x" * 257 + '"',
            '"' + "\\u0078" * 257 + '"',
            '"\\u00e4"',
            '"\\n"',
            " " * 1048577,
        ):
            self.raw_before_decoder(text)

    def test_duplicate_fields_malformed_json_and_bool_wire_are_rejected(self):
        text = canonical(model())
        for supplied in (
            text.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            text.replace('"cache_kind":"shared"', '"cache_kind":"shared","cache_kind":"shared"'),
            text.replace('"age_value_seconds":3', '"age_value_seconds":true'),
            "{]",
            "{}",
            "[]",
            "null",
        ):
            with patch.object(cache, "_address") as address, self.assertRaises(ERROR):
                cache.analyze_supplied_http_cache_freshness_bytes(
                    model_bytes=supplied.encode("ascii")
                )
            address.assert_not_called()

    def test_exact_bytes_intake_and_equivalent_ascii_spellings(self):
        class Bytes(bytes):
            pass

        for supplied in (
            b"",
            b" " * 1048577,
            b"\xff",
            "{}",
            bytearray(b"{}"),
            memoryview(b"{}"),
            Bytes(b"{}"),
        ):
            with patch.object(cache.json, "loads") as decoder, self.assertRaises(ERROR):
                cache.analyze_supplied_http_cache_freshness_bytes(model_bytes=supplied)
            decoder.assert_not_called()
        source = model()
        expected = cache.analyze_supplied_http_cache_freshness(source).to_json()
        for text in (
            json.dumps(source, indent=2),
            canonical(source).replace("synthetic", "\\u0073ynthetic"),
        ):
            self.assertEqual(
                cache.analyze_supplied_http_cache_freshness_bytes(
                    model_bytes=text.encode("ascii")
                ).to_json(),
                expected,
            )

    def test_report_and_replay_final_work_reserved_before_any_hash(self):
        source = component_fixture()
        observed = []
        original_charge = cache._Work.charge

        def capture(self, amount):
            original_charge(self, amount)
            observed.append(self.count)

        with patch.object(cache._Work, "charge", capture):
            report = cache.analyze_supplied_http_cache_freshness(source)
            text = report.to_json()
        exact = max(observed)
        for operation in (
            lambda: cache.analyze_supplied_http_cache_freshness(source),
            report.to_json,
            lambda: cache.HttpCacheFreshnessAnalysis.from_json(text),
        ):
            with (
                patch.object(cache, "MAX_WORK", exact - 1),
                patch.object(cache, "_address") as address,
            ):
                with self.assertRaisesRegex(ERROR, "work bound"):
                    operation()
                address.assert_not_called()
        with patch.object(cache, "MAX_WORK", exact):
            self.assertEqual(cache.analyze_supplied_http_cache_freshness(source).to_json(), text)
            self.assertEqual(cache.HttpCacheFreshnessAnalysis.from_json(text).to_json(), text)

    def test_work_and_cumulative_output_budgets_deny_before_hash(self):
        with patch.object(cache, "MAX_WORK", 1), patch.object(cache.json, "dumps") as serializer:
            self.deny_before_hash(model())
            serializer.assert_not_called()
        supplied = model([case(case_id=f"case-{i}") for i in range(128)])
        with patch.object(cache, "MAX_DOCUMENT_BYTES", 80000):
            self.deny_before_hash(supplied)

    def test_owned_input_and_export_detachment(self):
        original = component_fixture()
        frozen = copy.deepcopy(original)
        report = cache.analyze_supplied_http_cache_freshness(original)
        expected = report.to_json()
        original["cases"][0]["age_value_seconds"] = 900
        exported = report.to_dict()
        exported["case_observations"][0]["current_age_seconds"] = 0
        exported["source_model"]["cases"].clear()
        self.assertEqual(report.to_json(), expected)
        self.assertEqual(component_fixture(), frozen)
        self.assertEqual(
            cache.verify_supplied_http_cache_freshness_analysis(report, model=frozen).to_json(),
            expected,
        )
        with self.assertRaises(ERROR):
            cache.verify_supplied_http_cache_freshness_analysis(report, model=original)

    def test_cohashed_false_arithmetic_trace_and_outcomes_are_rejected(self):
        document = cache.analyze_supplied_http_cache_freshness(component_fixture()).to_dict()
        for field, value in (
            ("current_age_seconds", 0),
            ("freshness_lifetime_seconds", 999),
            ("freshness_comparison", True),
            ("response_delay_seconds", 0),
            ("corrected_age_value_seconds", 3),
            ("effective_date_seconds", 0),
            ("outcome", "fresh_under_supplied_arithmetic"),
            ("unassessed_reasons", ["unknown"]),
            ("case_id", "foreign"),
        ):
            changed = copy.deepcopy(document)
            changed["case_observations"][0][field] = value
            forged = readdress(changed)
            for intake in (
                cache.HttpCacheFreshnessAnalysis.from_dict,
                lambda item: cache.HttpCacheFreshnessAnalysis.from_json(canonical(item)),
            ):
                with self.assertRaises(ERROR):
                    intake(forged)

    def test_cohashed_metadata_native_alias_and_effect_promotion_are_rejected(self):
        document = cache.analyze_supplied_http_cache_freshness(component_fixture()).to_dict()
        for field, value in (
            ("schema_version", True),
            ("case_count", 3.0),
            ("profile_id", "AOE-GB-D05-S03"),
            ("source_model_sha256", "sha256:" + "a" * 64),
            ("limitations", []),
        ):
            forged = copy.deepcopy(document)
            forged[field] = value
            with self.assertRaises(ERROR):
                cache.HttpCacheFreshnessAnalysis.from_dict(readdress(forged))
        for section, field, value in (
            ("flags", "clock_truth_verified", True),
            ("flags", "reuse_approved", 0),
            ("effects", "cache_write", "invoked"),
            ("bounds", "cases", 129),
        ):
            forged = copy.deepcopy(document)
            forged[section][field] = value
            with self.assertRaises(ERROR):
                cache.HttpCacheFreshnessAnalysis.from_json(canonical(readdress(forged)))

    def test_coherent_alternate_originals_self_replay_but_cannot_rebind(self):
        original = component_fixture()
        for field in (
            "age_value_seconds",
            "request_time_seconds",
            "max_age_seconds",
            "case_id",
            "cache_kind",
            "order",
        ):
            alternate = copy.deepcopy(original)
            if field == "order":
                alternate["cases"].reverse()
            elif field == "case_id":
                alternate["cases"][0][field] = "other-case"
            elif field == "cache_kind":
                alternate["cases"][0][field] = "private"
            else:
                alternate["cases"][0][field] += 1
            report = cache.analyze_supplied_http_cache_freshness(alternate)
            self.assertEqual(
                cache.HttpCacheFreshnessAnalysis.from_json(report.to_json()).to_json(),
                report.to_json(),
            )
            with self.assertRaises(ERROR):
                cache.verify_supplied_http_cache_freshness_analysis(report, model=original)

    def test_incomplete_native_and_mutated_wrapper_fail_at_public_use(self):
        missing = object.__new__(cache.HttpCacheFreshnessAnalysis)
        with self.assertRaises(ERROR):
            missing.to_json()
        report = cache.analyze_supplied_http_cache_freshness(component_fixture())
        forged = report.to_dict()
        forged["case_observations"][0]["current_age_seconds"] = 0
        object.__setattr__(report, "_document_json", canonical(readdress(forged)))
        with self.assertRaises(ERROR):
            report.to_dict()
        with self.assertRaises(ERROR):
            cache.verify_supplied_http_cache_freshness_analysis(report, model=component_fixture())
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                cache.verify_supplied_http_cache_freshness_analysis(foreign, model=model())

    def test_bound_ownership_and_exact_false_flags_none_effects(self):
        document = cache.analyze_supplied_http_cache_freshness(component_fixture()).to_dict()
        expected = {
            "component_id": "http_supplied_cache_freshness_arithmetic",
            "profile_id": "AOE-GB-D05-S02",
            "capability_id": "army.gb.d05.s02",
            "vector_id": "AV-GB-D05-S02-01",
            "work_package_id": "IWP2-AOE-GB-D05-S02",
            "wave_id": "IW2-002",
            "commander_id": "AOE-GB-D05-CMD",
            "group_owner_id": "AOE-HQ-04",
            "independent_validator_id": "AOE-HQ-34",
            "blueprint_sha256": (
                "sha256:03c71eef405c080e094fbab91db4a0b25fe141cf3e581a81c62a51cf2db4da4a"
            ),
        }
        self.assertEqual({name: document[name] for name in expected}, expected)
        self.assertTrue(
            all(type(value) is bool and value is False for value in document["flags"].values())
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertNotIn("headers", document["source_model"]["cases"][0])


if __name__ == "__main__":
    unittest.main()
