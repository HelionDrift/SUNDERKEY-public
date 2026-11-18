"""Inert RFC 9110 bytes-range arithmetic and exact source replay tests."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_http_byte_range_analysis as ranges


def model(field: bytes, length: int = 20) -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-range",
        "range_field_value_base64": base64.b64encode(field).decode("ascii"),
        "representation_length": length,
    }


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class HttpByteRangeAnalysisTests(unittest.TestCase):
    def test_fresh_fixture_and_independent_member_arithmetic(self) -> None:
        supplied = ranges.component_fixture()
        self.assertEqual(supplied, model(b"bytes=0-4, 10-, -3"))
        report = ranges.analyze_supplied_http_byte_ranges(supplied)
        self.assertEqual(report.analysis_id, "HBR-4AFC73E40EFC1614C2E08A2EE3641092")
        self.assertEqual(
            report.analysis_sha256,
            "sha256:4afc73e40efc1614c2e08a2ee364109280fac1972dba013432ef029779803b58",
        )
        self.assertEqual(
            report.to_dict()["source_model_sha256"],
            "sha256:170bf551c714b44aa5539a5454585448c6a077b71ec4e7eee258e89a09b281b9",
        )
        rows = report.to_dict()["members"]
        self.assertEqual(
            [(r["selected_first"], r["selected_last"], r["selected_octets"]) for r in rows],
            [(0, 4, 5), (10, 19, 10), (17, 19, 3)],
        )
        self.assertEqual(
            report.to_dict()["overlap_pairs"],
            [{"left_index": 1, "right_index": 2, "selected_first": 17, "selected_last": 19}],
        )
        self.assertTrue(report.to_dict()["rfc_get_satisfiable_predicate"])
        self.assertEqual(report.to_dict()["effects"]["network"], "none")
        self.assertFalse(report.to_dict()["flags"]["server_response_verified"])
        self.assertEqual(ranges.component_fixture(), supplied)
        supplied["source_id"] = "mutated"
        self.assertEqual(report.to_dict()["source_model"]["source_id"], "synthetic-range")

    def test_suffix_and_zero_length_satisfiability_are_not_octets(self) -> None:
        for field, length, predicate, selected in (
            (b"bytes=-1", 0, True, (None, None, 0)),
            (b"bytes=-0", 0, False, (None, None, 0)),
            (b"bytes=0-", 0, False, (None, None, 0)),
            (b"bytes=-3", 2, True, (0, 1, 2)),
            (b"bytes=2-100", 3, True, (2, 2, 1)),
            (b"bytes=3-100", 3, False, (None, None, 0)),
        ):
            with self.subTest(field=field, length=length):
                row = ranges.analyze_supplied_http_byte_ranges(model(field, length)).to_dict()
                self.assertEqual(row["rfc_get_satisfiable_predicate"], predicate)
                member = row["members"][0]
                self.assertEqual(
                    (member["selected_first"], member["selected_last"], member["selected_octets"]),
                    selected,
                )

    def test_list_ows_empty_elements_and_case_insensitive_unit(self) -> None:
        report = ranges.analyze_supplied_http_byte_ranges(
            model(b"BYTES=\t,  0-1\t, ,\t-1,", 4)
        ).to_dict()
        self.assertEqual(report["empty_list_elements_ignored"], 3)
        self.assertEqual(len(report["members"]), 2)
        self.assertEqual(report["members"][1]["selected_first"], 3)

    def test_overlap_is_not_adjacency_or_server_response(self) -> None:
        report = ranges.analyze_supplied_http_byte_ranges(model(b"bytes=0-1,2-3,1-2", 4)).to_dict()
        self.assertEqual(
            [(r["left_index"], r["right_index"]) for r in report["overlap_pairs"]],
            [(0, 2), (1, 2)],
        )
        self.assertTrue(report["server_behavior_unassessed"])

    def test_small_independent_inclusive_interval_oracle(self) -> None:
        for length in range(5):
            for first in range(5):
                for last in range(first, 5):
                    source = model(f"bytes={first}-{last}".encode("ascii"), length)
                    row = ranges.analyze_supplied_http_byte_ranges(source).to_dict()
                    expected = (
                        [] if first >= length else list(range(first, min(last, length - 1) + 1))
                    )
                    observed = row["members"][0]
                    actual = (
                        []
                        if observed["selected_first"] is None
                        else list(range(observed["selected_first"], observed["selected_last"] + 1))
                    )
                    self.assertEqual(actual, expected)
                    self.assertEqual(observed["rfc_satisfiable"], first < length)

    def test_malformed_member_syntax_is_rejected(self) -> None:
        for field in (
            b"units=0-1",
            b"bytes=",
            b"bytes=, ,",
            b"bytes=1",
            b"bytes=1--2",
            b"bytes=2-1",
            b"bytes=-",
            b"bytes=+1-2",
            b"bytes=1- 2",
            b"bytes=1-2,7-a",
            b"bytes=1-2=3",
            b"bytes=1-2\n",
            b"bytes=9223372036854775808-",
            b"bytes=-9223372036854775808",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                    ranges.analyze_supplied_http_byte_ranges(model(field))

    def test_native_numeric_aliases_and_base64_are_closed(self) -> None:
        for bad in (True, 1.0, None, -1, 2**63):
            source = model(b"bytes=0-1")
            source["representation_length"] = bad
            with self.subTest(bad=bad):
                with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                    ranges.analyze_supplied_http_byte_ranges(source)
        for bad in ("Ynl0ZXM9MC0x=", "%%%", 0, False):
            source = model(b"bytes=0-1")
            source["range_field_value_base64"] = bad
            with self.subTest(bad=bad):
                with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                    ranges.analyze_supplied_http_byte_ranges(source)
        source = model(b"bytes=0-1")
        source["extra"] = 0
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.analyze_supplied_http_byte_ranges(source)

    def test_raw_duplicate_integer_float_depth_and_ascii_denial(self) -> None:
        valid = canonical(model(b"bytes=0-1"))
        raw = valid.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        samples = (
            raw,
            valid.replace('"representation_length":20', '"representation_length":1.0'),
            valid.replace('"representation_length":20', '"representation_length":' + "9" * 500),
            valid.replace('"representation_length":20', '"representation_length":true'),
            valid.replace('"source_id":"synthetic-range"', '"source_id":"\u00e9"'),
        )
        for sample in samples:
            with self.subTest(sample=sample[:80]):
                with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                    ranges.analyze_supplied_http_byte_ranges_bytes(
                        model_bytes=(
                            sample.encode("ascii") if sample.isascii() else sample.encode("utf-8")
                        )
                    )

    def test_all_public_roundtrips_and_original_model(self) -> None:
        source = model(b"bytes=0-4, 10-, -3")
        report = ranges.analyze_supplied_http_byte_ranges(source)
        by_bytes = ranges.analyze_supplied_http_byte_ranges_bytes(
            model_bytes=canonical(source).encode("ascii")
        )
        self.assertEqual(report.to_json(), by_bytes.to_json())
        self.assertEqual(
            ranges.HttpByteRangeAnalysis.from_dict(report.to_dict()).to_json(), report.to_json()
        )
        self.assertEqual(
            ranges.HttpByteRangeAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(ranges.HttpByteRangeAnalysis(report.to_dict()).to_json(), report.to_json())
        self.assertEqual(
            ranges.verify_supplied_http_byte_range_analysis(report, model=source).to_json(),
            report.to_json(),
        )
        owned = report.to_dict()
        owned["members"][0]["selected_first"] = 99
        self.assertEqual(report.to_dict()["members"][0]["selected_first"], 0)
        alternate = model(b"bytes=0-5, 10-, -3")
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.verify_supplied_http_byte_range_analysis(report, model=alternate)

    def test_cohashed_false_result_cannot_replay(self) -> None:
        document = ranges.analyze_supplied_http_byte_ranges(model(b"bytes=0-1")).to_dict()
        document["rfc_get_satisfiable_predicate"] = False
        addressed = {
            key: value
            for key, value in document.items()
            if key not in {"analysis_id", "analysis_sha256"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                ranges.DOMAIN.encode("ascii") + b"\n" + canonical(addressed).encode("ascii")
            ).hexdigest()
        )
        document["analysis_id"] = "HBR-" + digest[7:39].upper()
        document["analysis_sha256"] = digest
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.HttpByteRangeAnalysis.from_dict(document)
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.HttpByteRangeAnalysis.from_json(canonical(document))

    def test_cycles_shared_containers_and_subclasses(self) -> None:
        source = model(b"bytes=0-1")
        source["source_id"] = type("TextSubclass", (str,), {})("synthetic-range")
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.analyze_supplied_http_byte_ranges(source)
        cycle = []
        cycle.append(cycle)
        source = model(b"bytes=0-1")
        source["source_id"] = cycle
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.analyze_supplied_http_byte_ranges(source)

    def test_default_field_and_retained_bounds(self) -> None:
        source = model(b"bytes=" + b"0-0," * 128 + b"0-0")
        with self.assertRaises(ranges.HttpByteRangeAnalysisError):
            ranges.analyze_supplied_http_byte_ranges(source)
        source = model(b"bytes=0-0,0-0,0-0")
        with patch.object(ranges, "MAX_OVERLAPS", 2):
            with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                ranges.analyze_supplied_http_byte_ranges(source)
        report = ranges.analyze_supplied_http_byte_ranges(source).to_dict()
        self.assertEqual(len(report["overlap_pairs"]), 3)

    def test_real_field_and_report_ceiling_denials_precede_any_digest(self) -> None:
        too_large = model(b"bytes=0-1," + b"0-1," * 2048)
        with patch.object(
            ranges.hashlib, "sha256", side_effect=AssertionError("hash too early")
        ) as digest:
            with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                ranges.analyze_supplied_http_byte_ranges(too_large)
            digest.assert_not_called()
        source = model(b"bytes=0-1,0-1,0-1")
        normal = ranges.analyze_supplied_http_byte_ranges(source)
        with (
            patch.object(ranges, "MAX_REPORT_BYTES", len(normal.to_json()) - 1),
            patch.object(
                ranges.hashlib, "sha256", side_effect=AssertionError("hash too early")
            ) as digest,
        ):
            with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                ranges.analyze_supplied_http_byte_ranges(source)
            digest.assert_not_called()

    def test_all_eight_public_forms_deny_reduced_work_before_hash(self) -> None:
        source = model(b"bytes=0-1")
        report = ranges.analyze_supplied_http_byte_ranges(source)
        document = report.to_dict()
        text = report.to_json()
        operations = (
            lambda: ranges.analyze_supplied_http_byte_ranges(source),
            lambda: ranges.analyze_supplied_http_byte_ranges_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            lambda: ranges.HttpByteRangeAnalysis(document),
            lambda: ranges.HttpByteRangeAnalysis.from_dict(document),
            lambda: ranges.HttpByteRangeAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: ranges.verify_supplied_http_byte_range_analysis(report, model=source),
        )
        for index, operation in enumerate(operations):
            with (
                self.subTest(operation=index),
                patch.object(ranges, "MAX_WORK", 1),
                patch.object(
                    ranges.hashlib,
                    "sha256",
                    side_effect=AssertionError("digest before budget denial"),
                ) as digest,
            ):
                with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                    operation()
                digest.assert_not_called()

    def test_all_eight_public_forms_exact_work_boundary_before_first_digest(self) -> None:
        source = model(b"bytes=0-1")
        report = ranges.analyze_supplied_http_byte_ranges(source)
        document = report.to_dict()
        text = report.to_json()
        operations = (
            lambda: ranges.analyze_supplied_http_byte_ranges(source),
            lambda: ranges.analyze_supplied_http_byte_ranges_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            lambda: ranges.HttpByteRangeAnalysis(document),
            lambda: ranges.HttpByteRangeAnalysis.from_dict(document),
            lambda: ranges.HttpByteRangeAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: ranges.verify_supplied_http_byte_range_analysis(report, model=source),
        )
        real_sha256 = hashlib.sha256
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                low, high = 0, ranges.MAX_WORK
                while low + 1 < high:
                    middle = (low + high) // 2
                    with patch.object(ranges, "MAX_WORK", middle):
                        try:
                            operation()
                        except ranges.HttpByteRangeAnalysisError:
                            low = middle
                        else:
                            high = middle
                with (
                    patch.object(ranges, "MAX_WORK", high - 1),
                    patch.object(ranges.hashlib, "sha256", wraps=real_sha256) as digest,
                ):
                    with self.assertRaises(ranges.HttpByteRangeAnalysisError):
                        operation()
                    digest.assert_not_called()
                with patch.object(ranges, "MAX_WORK", high):
                    operation()


if __name__ == "__main__":
    unittest.main()
