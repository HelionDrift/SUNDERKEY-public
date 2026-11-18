"""Independent declared-key differential, replay and containment controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_cache_key_differential as cache

ERROR = cache.CacheKeyDifferentialAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def fixture():
    return cache.component_fixture()


def observe(source):
    return cache.analyze_supplied_cache_key_differential(source).to_dict()["pair_observations"][0]


def one_pair():
    source = fixture()
    source["pairs"] = source["pairs"][:1]
    return source


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-cache-key-differential.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "CKD-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class CacheKeyDifferentialTests(unittest.TestCase):
    def deny_before_hash(self, source):
        with patch.object(cache, "_address") as address:
            with self.assertRaises(ERROR):
                cache.analyze_supplied_cache_key_differential(source)
            address.assert_not_called()

    def test_fixture_outcomes_and_declared_boundary(self):
        source = fixture()
        report = cache.analyze_supplied_cache_key_differential(source)
        document = report.to_dict()
        rows = document["pair_observations"]
        self.assertEqual(document["candidate_signal_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in rows],
            ["candidate_key_collision_with_distinct_signatures", "distinct_declared_keys"],
        )
        self.assertEqual([row["declared_key_collision"] for row in rows], [True, False])
        self.assertEqual([row["vary_values_equal"] for row in rows], [True, False])
        self.assertEqual([row["candidate_deception_signal"] for row in rows], [True, False])
        self.assertTrue(all(row["base_key_equal"] for row in rows))
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S04")
        self.assertEqual(document["blueprint_sha256"], cache.BLUEPRINT_SHA256)
        self.assertEqual(document["analysis_id"], "CKD-6DE7EF5D6AFB892762AC9DF4602E52EA")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:6de7ef5d6afb892762ac9df4602e52eae97f07e68933ba3e4d1198ea6f68e5b5",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:86b43817acf634ad4a9ed0c6941ceb1a1efd9ba776ac4c64b56b552226628997",
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertFalse(any("verified" in row["outcome"] for row in rows))

    def test_key_field_projection_grid(self):
        for field in ("method", "scheme", "host", "path", "query"):
            source = one_pair()
            source["pairs"][0]["right"]["request"][field] += "x"
            row = observe(source)
            expected = not source["key_rule"]["include_" + field]
            self.assertIs(row["base_key_equal"], expected, field)
            self.assertIs(row["declared_key_collision"], expected, field)
            source["key_rule"]["include_" + field] = not source["key_rule"]["include_" + field]
            toggled = observe(source)
            self.assertIs(toggled["base_key_equal"], not expected, field)
        source = one_pair()
        source["pairs"][0]["left"]["request"]["query"] = ""
        source["pairs"][0]["right"]["request"]["query"] = ""
        self.assertTrue(observe(source)["base_key_equal"])

    def test_declared_header_projection_and_absence_are_distinct(self):
        source = one_pair()
        source["key_rule"]["header_names"] = ["accept-language"]
        row = observe(source)
        self.assertFalse(row["base_key_equal"])
        source["pairs"][0]["right"]["request"]["headers"] = {}
        self.assertFalse(observe(source)["base_key_equal"])
        source["pairs"][0]["left"]["request"]["headers"] = {}
        self.assertTrue(observe(source)["base_key_equal"])
        source["pairs"][0]["right"]["request"]["headers"] = {"accept-language": ""}
        self.assertFalse(observe(source)["base_key_equal"])

    def test_vary_equal_absent_different_and_different_declarations(self):
        source = one_pair()
        for side in ("left", "right"):
            source["pairs"][0][side]["response"]["vary"] = ["accept-language"]
        self.assertFalse(observe(source)["declared_key_collision"])
        source["pairs"][0]["right"]["request"]["headers"]["accept-language"] = "en"
        self.assertTrue(observe(source)["declared_key_collision"])
        source["pairs"][0]["left"]["request"]["headers"] = {}
        source["pairs"][0]["right"]["request"]["headers"] = {}
        self.assertTrue(observe(source)["declared_key_collision"])
        source["pairs"][0]["right"]["response"]["vary"] = []
        row = observe(source)
        self.assertIsNone(row["declared_key_collision"])
        self.assertEqual(row["uncertainty"], ["vary_declarations_differ"])

    def test_no_store_undeclared_vary_wildcard_and_same_signature(self):
        for field, value, reason in (
            ("vary", None, "vary_undeclared"),
            ("vary", "*", "vary_wildcard"),
            ("no_store", True, "declared_no_store"),
            ("no_store", None, "no_store_undeclared"),
        ):
            source = one_pair()
            source["pairs"][0]["left"]["response"][field] = value
            row = observe(source)
            self.assertEqual(row["outcome"], "unassessed")
            self.assertFalse(row["candidate_deception_signal"])
            self.assertIn(reason, row["uncertainty"])
        source = one_pair()
        source["pairs"][0]["right"]["response"]["signature"] = source["pairs"][0]["left"][
            "response"
        ]["signature"]
        row = observe(source)
        self.assertEqual(row["outcome"], "declared_key_collision_same_signature")
        self.assertFalse(row["response_signatures_distinct"])
        self.assertFalse(row["candidate_deception_signal"])

    def test_distinct_base_key_stays_negative_with_unknown_vary(self):
        source = one_pair()
        source["pairs"][0]["right"]["request"]["path"] = "/other"
        source["pairs"][0]["left"]["response"]["vary"] = None
        source["pairs"][0]["right"]["response"]["no_store"] = None
        row = observe(source)
        self.assertFalse(row["declared_key_collision"])
        self.assertEqual(row["outcome"], "distinct_declared_keys")
        self.assertFalse(row["candidate_deception_signal"])

    def test_roundtrip_detachment_and_separate_originals(self):
        source = fixture()
        original = copy.deepcopy(source)
        report = cache.analyze_supplied_cache_key_differential(source)
        expected = report.to_json()
        for rebuilt in (
            cache.CacheKeyDifferentialAnalysis.from_dict(report.to_dict()),
            cache.CacheKeyDifferentialAnalysis.from_json(expected),
            cache.analyze_supplied_cache_key_differential_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            cache.verify_supplied_cache_key_differential_analysis(report, model=source),
        ):
            self.assertEqual(rebuilt.to_json(), expected)
        self.assertEqual(report.analysis_id, report.to_dict()["analysis_id"])
        self.assertEqual(report.analysis_sha256, report.to_dict()["analysis_sha256"])
        source["pairs"][0]["right"]["response"]["signature"] = "sha256:" + "c" * 64
        exported = report.to_dict()
        exported["pair_observations"].clear()
        self.assertEqual(report.to_json(), expected)
        with self.assertRaises(ERROR):
            cache.verify_supplied_cache_key_differential_analysis(report, model=source)
        self.assertEqual(
            cache.verify_supplied_cache_key_differential_analysis(report, model=original).to_json(),
            expected,
        )

    def test_closed_shapes_duplicates_and_native_aliases(self):
        source = one_pair()
        for version in (True, 1.0, "1", None, 2):
            self.deny_before_hash({**source, "schema_version": version})
        self.deny_before_hash({**source, "extra": None})
        self.deny_before_hash({**source, "pairs": []})
        self.deny_before_hash({**source, "pairs": [source["pairs"][0]] * 2})
        for field in source["key_rule"]:
            changed = copy.deepcopy(source)
            changed["key_rule"].pop(field)
            self.deny_before_hash(changed)
        for field in ("include_path", "include_query"):
            for value in (1, 0, None, "true"):
                changed = copy.deepcopy(source)
                changed["key_rule"][field] = value
                self.deny_before_hash(changed)
        for field in ("pair_id", "left", "right"):
            changed = copy.deepcopy(source)
            changed["pairs"][0].pop(field)
            self.deny_before_hash(changed)
        for section in ("request", "response"):
            changed = copy.deepcopy(source)
            changed["pairs"][0]["left"][section]["extra"] = "x"
            self.deny_before_hash(changed)
        for value in ([], {}, 0, True, "sha256:" + "A" * 64, "x"):
            changed = copy.deepcopy(source)
            changed["pairs"][0]["left"]["response"]["signature"] = value
            self.deny_before_hash(changed)

    def test_header_name_lists_sensitive_headers_and_values(self):
        for names in (
            ["x-a", "x-a"],
            ["x-z", "x-a"],
            ["Accept"],
            ["cookie"],
            ["x-" + "a" * 64],
            ["x"] * 33,
            "x-a",
        ):
            source = one_pair()
            source["key_rule"]["header_names"] = names
            self.deny_before_hash(source)
        for vary in (
            ["x", "x"],
            ["z", "a"],
            ["Authorization"],
            ["authorization"],
            ["x"] * 17,
            True,
        ):
            source = one_pair()
            source["pairs"][0]["left"]["response"]["vary"] = vary
            self.deny_before_hash(source)
        source = one_pair()
        source["pairs"][0]["left"]["request"]["headers"] = {"cookie": "secret"}
        self.deny_before_hash(source)
        source = one_pair()
        source["pairs"][0]["left"]["request"]["headers"] = {"X-Test": "x"}
        self.deny_before_hash(source)
        source = one_pair()
        source["pairs"][0]["left"]["request"]["headers"] = {"x": 1}
        self.deny_before_hash(source)

    def test_pair_limit_and_order(self):
        source = one_pair()
        template = source["pairs"][0]
        source["pairs"] = [{**copy.deepcopy(template), "pair_id": f"pair-{i}"} for i in range(64)]
        document = cache.analyze_supplied_cache_key_differential(source).to_dict()
        self.assertEqual(document["pair_count"], 64)
        self.assertEqual(document["candidate_signal_count"], 64)
        self.assertEqual(
            [row["pair_id"] for row in document["pair_observations"]],
            [f"pair-{i}" for i in range(64)],
        )
        source["pairs"].append({**copy.deepcopy(template), "pair_id": "pair-64"})
        self.deny_before_hash(source)

    def test_raw_duplicate_members_and_lexical_bounds(self):
        source = canonical(one_pair())
        for raw in (
            source.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            source.replace('"no_store":false', '"no_store":false,"no_store":false', 1),
            source.replace('"schema_version":1', '"schema_version":01'),
            source.replace('"schema_version":1', '"schema_version":1.0'),
            '"' + "x" * 257 + '"',
            '"' + "\\u0078" * 257 + '"',
            '"\\u00e4"',
            "[" * 16 + "0" + "]" * 16,
            "9" * 20000,
        ):
            with patch.object(cache, "_address") as address, self.assertRaises(ERROR):
                cache.analyze_supplied_cache_key_differential_bytes(model_bytes=raw.encode("ascii"))
            address.assert_not_called()

    def test_bytes_exact_types_and_equivalent_ascii_escapes(self):
        class Bytes(bytes):
            pass

        for content in (b"", b"\xff", "{}", bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}")):
            with self.assertRaises(ERROR):
                cache.analyze_supplied_cache_key_differential_bytes(model_bytes=content)
        source = one_pair()
        expected = cache.analyze_supplied_cache_key_differential(source).to_json()
        for raw in (
            json.dumps(source, indent=2),
            canonical(source).replace("synthetic", "\\u0073ynthetic"),
        ):
            actual = cache.analyze_supplied_cache_key_differential_bytes(
                model_bytes=raw.encode("ascii")
            )
            self.assertEqual(actual.to_json(), expected)

    def test_cycles_depth_native_subclasses_and_work_bound(self):
        cycle = []
        cycle.append(cycle)
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (cycle, nested, [None] * 32768, ["\\" * 256] * 2100):
            with patch.object(cache.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()

        class Mapping(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        self.deny_before_hash(Mapping(one_pair()))
        with patch.object(cache, "MAX_WORK", 1):
            self.deny_before_hash(one_pair())

    def test_cohashed_report_tamper_and_effect_promotion_rejected(self):
        document = cache.analyze_supplied_cache_key_differential(fixture()).to_dict()
        for field, value in (
            ("declared_key_collision", False),
            ("candidate_deception_signal", False),
            ("response_signatures_distinct", False),
            ("outcome", "verified_live_poisoning"),
            ("uncertainty", ["none"]),
        ):
            changed = copy.deepcopy(document)
            changed["pair_observations"][0][field] = value
            with self.assertRaises(ERROR):
                cache.CacheKeyDifferentialAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "poisoning_verified", True),
            ("effects", "network", "invoked"),
            ("bounds", "pairs", 65),
        ):
            changed = copy.deepcopy(document)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                cache.CacheKeyDifferentialAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(document)
        changed["candidate_signal_count"] = 2
        with self.assertRaises(ERROR):
            cache.CacheKeyDifferentialAnalysis.from_dict(readdress(changed))

    def test_mutated_wrapper_and_foreign_report_rejected(self):
        report = cache.analyze_supplied_cache_key_differential(fixture())
        forged = report.to_dict()
        forged["pair_observations"][0]["candidate_deception_signal"] = False
        object.__setattr__(report, "_document_json", canonical(readdress(forged)))
        with self.assertRaises(ERROR):
            report.to_dict()
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                cache.verify_supplied_cache_key_differential_analysis(foreign, model=fixture())

    def test_no_io_or_process_paths(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            report = cache.analyze_supplied_cache_key_differential(fixture())
            self.assertEqual(report.to_dict()["candidate_signal_count"], 1)


if __name__ == "__main__":
    unittest.main()
