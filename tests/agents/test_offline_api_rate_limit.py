"""Synthetic, source-bound fixed-window rate-limit projection tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_rate_limit as rate_limit


def encoded(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {k: v for k, v in changed.items() if k not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(encoded({"domain": rate_limit.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "ARL-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


def event(
    name: str, time: int, *, subject: str = "u", route: str = "a", outcome: str = "admitted"
) -> dict:
    return {
        "event_id": name,
        "timestamp_ms": time,
        "subject_id": subject,
        "route_id": route,
        "outcome": outcome,
    }


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class ReportAlias(rate_limit.ApiRateLimitReport):
    pass


class OfflineApiRateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = rate_limit.component_fixture()
        self.source_id = "synthetic:rate-limit"

    def analyze(self, model=None) -> rate_limit.ApiRateLimitReport:
        return rate_limit.analyze_api_rate_limit(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_candidate_is_only_supplied_data_not_abuse_finding(self) -> None:
        content = encoded(self.model)
        report = rate_limit.analyze_api_rate_limit(
            source_content=content,
            source_id=self.source_id,
        )
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S13")
        self.assertEqual(document["wave_id"], "IW2-004")
        self.assertEqual(
            document["source"],
            {
                "source_id": self.source_id,
                "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                "byte_count": len(content),
            },
        )
        self.assertEqual(
            document["windows"],
            [
                {
                    "subject_id": "test-user",
                    "route_id": "lookup",
                    "window_start_ms": 0,
                    "window_end_ms_exclusive": 1_000,
                    "max_admitted_requests": 2,
                    "observed_admitted": 3,
                    "observed_rate_limited": 1,
                    "admitted_event_ids": ["e1", "e2", "e3"],
                    "rate_limited_event_ids": ["e4"],
                    "threshold_exceeded_in_supplied_records": True,
                    "assessment": "candidate_admitted_over_limit",
                }
            ],
        )
        self.assertEqual(
            document["summary"],
            {
                "window_count": 1,
                "record_count": 4,
                "admitted_count": 3,
                "rate_limited_count": 1,
                "candidate_admitted_over_limit": 1,
                "within_supplied_limit": 0,
                "unknown_incomplete_traffic": 0,
            },
        )
        self.assertTrue(document["offline_only"])
        for field in (
            "traffic_authenticated",
            "policy_authenticated",
            "server_enforcement_observed",
            "abuse_finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(
            rate_limit.verify_api_rate_limit(
                report,
                source_content=content,
                source_id=self.source_id,
            ),
            report,
        )

    def test_fixed_window_boundary_and_subject_route_isolation(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy"] = {
            "window_ms": 10,
            "window_origin_ms": 5,
            "route_limits": [
                {"route_id": "a", "max_admitted_requests": 1},
                {"route_id": "b", "max_admitted_requests": 1},
            ],
        }
        model["records"] = [
            event("a2", 14),
            event("a1", 5),
            event("a3", 15),
            event("b1", 14, route="b"),
            event("u2", 14, subject="v"),
        ]
        windows = self.analyze(model).to_dict()["windows"]
        self.assertEqual(
            [(w["subject_id"], w["route_id"], w["window_start_ms"]) for w in windows],
            [("u", "a", 5), ("u", "a", 15), ("u", "b", 5), ("v", "a", 5)],
        )
        self.assertEqual(windows[0]["admitted_event_ids"], ["a1", "a2"])
        self.assertEqual(windows[0]["assessment"], "candidate_admitted_over_limit")
        self.assertTrue(all(w["assessment"] == "within_supplied_limit" for w in windows[1:]))
        self.assertEqual(windows[1]["window_end_ms_exclusive"], 25)

    def test_rate_limited_records_do_not_raise_admitted_count(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"] = [
            event("a", 100, route="lookup"),
            event("b", 200, route="lookup"),
            event("c", 300, route="lookup", outcome="rate_limited"),
            event("d", 400, route="lookup", outcome="rate_limited"),
        ]
        window = self.analyze(model).to_dict()["windows"][0]
        self.assertFalse(window["threshold_exceeded_in_supplied_records"])
        self.assertEqual(window["assessment"], "within_supplied_limit")
        self.assertEqual(window["observed_rate_limited"], 2)

    def test_incomplete_traffic_is_unknown_even_with_observed_excess(self) -> None:
        model = copy.deepcopy(self.model)
        model["traffic_complete"] = False
        window = self.analyze(model).to_dict()["windows"][0]
        self.assertTrue(window["threshold_exceeded_in_supplied_records"])
        self.assertEqual(window["assessment"], "unknown_incomplete_traffic")
        model["records"] = [event("only", 100, route="lookup")]
        window = self.analyze(model).to_dict()["windows"][0]
        self.assertFalse(window["threshold_exceeded_in_supplied_records"])
        self.assertEqual(window["assessment"], "unknown_incomplete_traffic")

    def test_zero_limit_and_empty_records(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy"]["route_limits"][0]["max_admitted_requests"] = 0
        model["records"] = [event("one", 999, subject="u", route="lookup")]
        self.assertEqual(
            self.analyze(model).to_dict()["windows"][0]["assessment"],
            "candidate_admitted_over_limit",
        )
        model["records"] = []
        document = self.analyze(model).to_dict()
        self.assertEqual(document["windows"], [])
        self.assertEqual(document["summary"]["record_count"], 0)

    def test_fixture_detachment_determinism_and_replay(self) -> None:
        fixture = rate_limit.component_fixture()
        fixture["policy"]["route_limits"][0]["max_admitted_requests"] = 50
        self.assertEqual(
            rate_limit.component_fixture()["policy"]["route_limits"][0]["max_admitted_requests"], 2
        )
        first = self.analyze()
        second = self.analyze()
        self.assertEqual(first.to_json(), second.to_json())
        detached = first.to_dict()
        detached["windows"][0]["assessment"] = "within_supplied_limit"
        self.assertNotEqual(detached, first.to_dict())
        parsed = rate_limit.ApiRateLimitReport.from_json("\n" + first.to_json() + "\n")
        self.assertEqual(parsed, first)
        self.assertIsNot(
            rate_limit.verify_api_rate_limit(
                first,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            first,
        )
        permuted = copy.deepcopy(self.model)
        permuted["records"] = list(reversed(permuted["records"]))
        self.assertEqual(self.analyze(permuted).to_dict()["windows"], first.to_dict()["windows"])
        self.assertNotEqual(self.analyze(permuted).to_json(), first.to_json())

    def test_replay_rejects_changed_source_and_readdressed_forgery(self) -> None:
        original = self.analyze()
        changed = copy.deepcopy(self.model)
        changed["records"][0]["timestamp_ms"] = 999
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.verify_api_rate_limit(
                original,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = original.to_dict()
        forged["windows"][0]["admitted_event_ids"][0] = "forged"
        parsed = rate_limit.ApiRateLimitReport.from_json(encoded(readdress(forged)).decode("ascii"))
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.verify_api_rate_limit(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport.from_json(
                original.to_json().replace(
                    '"abuse_finding_claimed":false', '"abuse_finding_claimed":true'
                )
            )

    def test_public_constructor_and_exports_validate_local_report(self) -> None:
        report = self.analyze()
        self.assertEqual(
            rate_limit.ApiRateLimitReport(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport("\n" + report.to_json())
        self.assertEqual(
            rate_limit.ApiRateLimitReport.from_json("\n" + report.to_json() + "\n"),
            report,
        )

        forged_effects = report.to_dict()
        forged_effects["effects"]["network"] = "invoked"
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport(encoded(readdress(forged_effects)).decode("ascii"))

        within = copy.deepcopy(self.model)
        within["records"] = within["records"][:2]
        forged_candidate = self.analyze(within).to_dict()
        window = forged_candidate["windows"][0]
        window["assessment"] = "candidate_admitted_over_limit"
        forged_candidate["summary"]["within_supplied_limit"] = 0
        forged_candidate["summary"]["candidate_admitted_over_limit"] = 1
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport(encoded(readdress(forged_candidate)).decode("ascii"))

        locally_plausible = report.to_dict()
        locally_plausible["windows"][0]["admitted_event_ids"][0] = "forged-event"
        plausible_report = rate_limit.ApiRateLimitReport(
            encoded(readdress(locally_plausible)).decode("ascii")
        )
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.verify_api_rate_limit(
                plausible_report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

        object.__setattr__(report, "_json", encoded(readdress(forged_effects)).decode("ascii"))
        with self.assertRaises(rate_limit.ApiRateLimitError):
            report.to_json()
        with self.assertRaises(rate_limit.ApiRateLimitError):
            report.to_dict()

    def test_closed_schema_and_ambiguous_records_rejected(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["scope"] = "target"
        invalid.append(extra)
        duplicate_route = copy.deepcopy(self.model)
        duplicate_route["policy"]["route_limits"].append(
            copy.deepcopy(duplicate_route["policy"]["route_limits"][0])
        )
        invalid.append(duplicate_route)
        duplicate_event = copy.deepcopy(self.model)
        duplicate_event["records"][1]["event_id"] = "e1"
        invalid.append(duplicate_event)
        for field, value in (
            ("traffic_complete", 1),
            ("records", {}),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[field] = value
            invalid.append(candidate)
        for field, value in (
            ("timestamp_ms", -1),
            ("timestamp_ms", 1.5),
            ("route_id", "missing"),
            ("event_id", "../../x"),
            ("outcome", "unknown"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate["records"][0][field] = value
            invalid.append(candidate)
        for field, value in (("window_ms", 0), ("window_origin_ms", -1), ("route_limits", [])):
            candidate = copy.deepcopy(self.model)
            candidate["policy"][field] = value
            invalid.append(candidate)
        before_origin = copy.deepcopy(self.model)
        before_origin["policy"]["window_origin_ms"] = 500
        invalid.append(before_origin)
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(rate_limit.ApiRateLimitError):
                self.analyze(candidate)

    def test_duplicate_keys_oversized_and_unsupported_json(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"policy":{"window_ms":1,"window_ms":2}}',
            b'{"records":[{"timestamp_ms":1,"timestamp_ms":2}]}',
            b'{"x":NaN}',
            b'{"x":1.1}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (rate_limit.MAX_DEPTH + 1) + b"0" + b"]" * (rate_limit.MAX_DEPTH + 1),
            b" " * (rate_limit.MAX_SOURCE_BYTES + 1),
        ]
        for content in bad:
            with (
                self.subTest(content=content[:32]),
                self.assertRaises(rate_limit.ApiRateLimitError),
            ):
                rate_limit.analyze_api_rate_limit(
                    source_content=content,
                    source_id=self.source_id,
                )
        for content, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "../source"),
        ):
            with self.assertRaises(rate_limit.ApiRateLimitError):
                rate_limit.analyze_api_rate_limit(
                    source_content=content,
                    source_id=identity,
                )

    def test_record_and_report_bounds(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"] = [
            event(f"e{index}", index, route="lookup") for index in range(rate_limit.MAX_RECORDS + 1)
        ]
        with self.assertRaises(rate_limit.ApiRateLimitError):
            self.analyze(model)
        report = self.analyze()
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.verify_api_rate_limit(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport.from_json(StringAlias(report.to_json()))
        with self.assertRaises(rate_limit.ApiRateLimitError):
            rate_limit.ApiRateLimitReport.from_json(report.to_json() + report.to_json())

    def test_no_network_or_process_effect(self) -> None:
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                report = self.analyze()
                self.assertEqual(
                    rate_limit.verify_api_rate_limit(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
