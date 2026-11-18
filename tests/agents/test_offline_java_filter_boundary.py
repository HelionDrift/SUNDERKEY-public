"""Tests for the inert Java servlet-filter declaration projection."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_java_filter_boundary as java


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class JavaFilterBoundaryTests(unittest.TestCase):
    source_id = "synthetic:java-filter"

    def setUp(self) -> None:
        self.model = java.component_fixture()

    def analyze(self, model: dict | None = None) -> java.JavaFilterBoundaryReport:
        return java.analyze_java_filter_boundary(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_projects_dispatcher_specific_gap_without_runtime_claim(self) -> None:
        report = self.analyze().to_dict()
        by_id = {item["route_id"]: item for item in report["projections"]}
        self.assertEqual(by_id["account"]["assessment"], "declared_coverage")
        self.assertEqual(by_id["forwarded"]["assessment"], "candidate_declared_coverage_gap")
        self.assertEqual(by_id["forwarded"]["basis"], "guard_dispatcher_absent")
        self.assertEqual(by_id["account"]["route_path"], by_id["forwarded"]["route_path"])
        self.assertNotEqual(by_id["account"]["dispatcher"], by_id["forwarded"]["dispatcher"])
        self.assertEqual(by_id["health"]["assessment"], "not_required")
        self.assertFalse(report["filter_execution_observed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_declared_forward_dispatcher_closes_gap(self) -> None:
        model = copy.deepcopy(self.model)
        model["filters"][0]["dispatchers"].append("FORWARD")
        projection = self.analyze(model).to_dict()["projections"][1]
        self.assertEqual(projection["assessment"], "declared_coverage")
        self.assertEqual(projection["covering_guard_ids"], ["guard"])

    def test_missing_guard_and_incomplete_declarations(self) -> None:
        model = copy.deepcopy(self.model)
        model["filters"] = []
        projections = self.analyze(model).to_dict()["projections"]
        self.assertEqual(projections[0]["basis"], "guard_route_absent")
        model["declarations_complete"] = False
        self.assertTrue(
            all(p["assessment"] == "unknown" for p in self.analyze(model).to_dict()["projections"])
        )

    def test_source_replay_rejects_changed_bytes_and_readdressed_report(self) -> None:
        report = self.analyze()
        self.assertEqual(
            java.verify_java_filter_boundary(
                report, source_content=encoded(self.model), source_id=self.source_id
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["filters"][0]["dispatchers"].append("FORWARD")
        with self.assertRaises(java.JavaFilterBoundaryError):
            java.verify_java_filter_boundary(
                report, source_content=encoded(changed), source_id=self.source_id
            )
        forged = report.to_dict()
        forged["projections"][1]["assessment"] = "declared_coverage"
        forged["summary"]["assessments"]["candidate_declared_coverage_gap"] -= 1
        forged["summary"]["assessments"]["declared_coverage"] += 1
        from sunderkey.offline_framework_declaration_core import canonical, report_address

        forged["report_id"], forged["report_sha256"] = report_address(
            forged, domain=java.DOMAIN, prefix="JFB-"
        )
        parsed = java.JavaFilterBoundaryReport.from_json(canonical(forged))
        with self.assertRaises(java.JavaFilterBoundaryError):
            java.verify_java_filter_boundary(
                parsed, source_content=encoded(self.model), source_id=self.source_id
            )

    def test_report_claim_tampering_rejected(self) -> None:
        report = self.analyze()
        damaged = report.to_dict()
        damaged["positive_use_approved"] = True
        with self.assertRaises(java.JavaFilterBoundaryError):
            java.JavaFilterBoundaryReport.from_json(encoded(damaged).decode("ascii"))
        object.__setattr__(report, "_json", encoded(damaged).decode("ascii"))
        with self.assertRaises(java.JavaFilterBoundaryError):
            report.to_json()

    def test_closed_model_rejects_ambiguous_paths_and_mapping_refs(self) -> None:
        invalid = []
        for section, field, value in (
            ("routes", "route_path", "/a/../b"),
            ("routes", "route_path", "/a%2Fb"),
            ("routes", "dispatcher", "request"),
            ("routes", "requires_guard", 1),
            ("filters", "route_ids", ["missing"]),
            ("filters", "dispatchers", ["REQUEST", "REQUEST"]),
            ("filters", "kind", "unknown"),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = value
            invalid.append(model)
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        duplicate = copy.deepcopy(self.model)
        duplicate["routes"].append(copy.deepcopy(duplicate["routes"][0]))
        invalid.append(duplicate)
        duplicate_pair = copy.deepcopy(self.model)
        duplicate_pair["routes"][1]["dispatcher"] = "REQUEST"
        invalid.append(duplicate_pair)
        for model in invalid:
            with self.subTest(model=model), self.assertRaises(java.JavaFilterBoundaryError):
                self.analyze(model)

    def test_raw_decoder_rejects_duplicate_keys_numbers_depth_and_size(self) -> None:
        invalid = (
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (java.MAX_DEPTH + 1) + b"0" + b"]" * (java.MAX_DEPTH + 1),
            b" " * (java.MAX_SOURCE_BYTES + 1),
        )
        for raw in invalid:
            with self.subTest(raw=raw[:24]), self.assertRaises(java.JavaFilterBoundaryError):
                java.analyze_java_filter_boundary(source_content=raw, source_id=self.source_id)

    def test_native_adapter_detaches_and_rejects_subclasses(self) -> None:
        model = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = java.analyze_supplied_java_filter_boundary(model)
        self.assertEqual(report, self.analyze())
        model["source"]["declarations_complete"] = False
        self.assertNotEqual(report, java.analyze_supplied_java_filter_boundary(model))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": self.source_id, "source": []},
        ):
            with self.assertRaises(java.JavaFilterBoundaryError):
                java.analyze_supplied_java_filter_boundary(invalid)

        class DictAlias(dict):
            pass

        with self.assertRaises(java.JavaFilterBoundaryError):
            java.analyze_supplied_java_filter_boundary(
                DictAlias({"source_id": self.source_id, "source": self.model})
            )

    def test_empty_routes_and_determinism_without_effects(self) -> None:
        model = copy.deepcopy(self.model)
        model["routes"] = []
        model["filters"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        report = self.analyze()
        self.assertEqual(report.to_json(), self.analyze().to_json())
        reversed_model = copy.deepcopy(self.model)
        reversed_model["routes"].reverse()
        self.assertEqual(
            self.analyze(reversed_model).to_dict()["projections"], report.to_dict()["projections"]
        )
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    java.verify_java_filter_boundary(
                        report, source_content=encoded(self.model), source_id=self.source_id
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
