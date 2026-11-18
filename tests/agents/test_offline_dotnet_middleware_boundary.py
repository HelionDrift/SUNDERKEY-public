"""Tests for inert .NET endpoint-routing middleware declarations."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_dotnet_middleware_boundary as dotnet


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class DotnetMiddlewareBoundaryTests(unittest.TestCase):
    source_id = "synthetic:dotnet-middleware"

    def setUp(self) -> None:
        self.model = dotnet.component_fixture()

    def analyze(self, model: dict | None = None) -> dotnet.DotnetMiddlewareBoundaryReport:
        return dotnet.analyze_dotnet_middleware_boundary(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_projects_order_without_runtime_claim(self) -> None:
        report = self.analyze().to_dict()
        projections = {p["route_id"]: p for p in report["projections"]}
        self.assertEqual(projections["account"]["assessment"], "declared_order_satisfied")
        self.assertEqual(
            projections["account"]["stage_ids"], ["routing", "authorization", "endpoints"]
        )
        self.assertEqual(projections["health"]["assessment"], "not_required")
        self.assertFalse(report["middleware_execution_observed"])
        self.assertFalse(report["server_enforcement_observed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_authorization_after_endpoint_is_candidate_declared_gap(self) -> None:
        model = copy.deepcopy(self.model)
        model["middleware"][2], model["middleware"][3] = (
            model["middleware"][3],
            model["middleware"][2],
        )
        account = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(account["assessment"], "candidate_declared_order_gap")
        self.assertEqual(account["basis"], "authorization_outside_endpoint_window")

    def test_missing_authorization_and_incomplete_declarations(self) -> None:
        model = copy.deepcopy(self.model)
        model["middleware"] = [p for p in model["middleware"] if p["stage"] != "authorization"]
        account = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(
            (account["assessment"], account["basis"]),
            ("candidate_declared_order_gap", "authorization_missing"),
        )
        model["declarations_complete"] = False
        self.assertTrue(
            all(p["assessment"] == "unknown" for p in self.analyze(model).to_dict()["projections"])
        )
        model["middleware"] = []
        self.assertTrue(
            all(p["assessment"] == "unknown" for p in self.analyze(model).to_dict()["projections"])
        )

    def test_authentication_placement_is_not_misclassified_as_authorization(self) -> None:
        model = copy.deepcopy(self.model)
        model["middleware"].remove({"middleware_id": "authentication", "stage": "authentication"})
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][0]["assessment"],
            "declared_order_satisfied",
        )
        model["middleware"].insert(
            2, {"middleware_id": "authentication", "stage": "authentication"}
        )
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][0]["assessment"],
            "declared_order_satisfied",
        )

    def test_source_replay_rejects_changed_bytes_and_readdressed_report(self) -> None:
        report = self.analyze()
        self.assertEqual(
            dotnet.verify_dotnet_middleware_boundary(
                report, source_content=encoded(self.model), source_id=self.source_id
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["middleware"][2], changed["middleware"][3] = (
            changed["middleware"][3],
            changed["middleware"][2],
        )
        with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
            dotnet.verify_dotnet_middleware_boundary(
                report, source_content=encoded(changed), source_id=self.source_id
            )
        forged = report.to_dict()
        forged["projections"][0]["assessment"] = "candidate_declared_order_gap"
        forged["summary"]["assessments"]["declared_order_satisfied"] -= 1
        forged["summary"]["assessments"]["candidate_declared_order_gap"] += 1
        from sunderkey.offline_framework_declaration_core import canonical, report_address

        forged["report_id"], forged["report_sha256"] = report_address(
            forged, domain=dotnet.DOMAIN, prefix="DMB-"
        )
        parsed = dotnet.DotnetMiddlewareBoundaryReport.from_json(canonical(forged))
        with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
            dotnet.verify_dotnet_middleware_boundary(
                parsed, source_content=encoded(self.model), source_id=self.source_id
            )

    def test_report_claim_tampering_rejected(self) -> None:
        report = self.analyze()
        damaged = report.to_dict()
        damaged["server_enforcement_observed"] = True
        with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
            dotnet.DotnetMiddlewareBoundaryReport.from_json(encoded(damaged).decode("ascii"))
        object.__setattr__(report, "_json", encoded(damaged).decode("ascii"))
        with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
            report.to_json()

    def test_closed_model_rejects_unsupported_pipeline_and_ambiguous_paths(self) -> None:
        invalid = []
        for section, field, value in (
            ("routes", "route_path", "/a%2Fb"),
            ("routes", "route_path", "https://example.invalid"),
            ("routes", "requires_authorization", 1),
            ("middleware", "stage", "custom"),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = value
            invalid.append(model)
        for field, value in (("pipeline_kind", "implicit"), ("declarations_complete", "true")):
            model = copy.deepcopy(self.model)
            model[field] = value
            invalid.append(model)
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        duplicate = copy.deepcopy(self.model)
        duplicate["middleware"].append(copy.deepcopy(duplicate["middleware"][0]))
        invalid.append(duplicate)
        duplicate_stage = copy.deepcopy(self.model)
        duplicate_stage["middleware"].append({"middleware_id": "routing-two", "stage": "routing"})
        invalid.append(duplicate_stage)
        missing_endpoint = copy.deepcopy(self.model)
        missing_endpoint["middleware"] = [
            p for p in missing_endpoint["middleware"] if p["stage"] != "endpoint"
        ]
        invalid.append(missing_endpoint)
        for model in invalid:
            with self.subTest(model=model), self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
                self.analyze(model)

    def test_raw_decoder_rejects_duplicate_keys_numbers_depth_and_size(self) -> None:
        invalid = (
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (dotnet.MAX_DEPTH + 1) + b"0" + b"]" * (dotnet.MAX_DEPTH + 1),
            b" " * (dotnet.MAX_SOURCE_BYTES + 1),
        )
        for raw in invalid:
            with (
                self.subTest(raw=raw[:24]),
                self.assertRaises(dotnet.DotnetMiddlewareBoundaryError),
            ):
                dotnet.analyze_dotnet_middleware_boundary(
                    source_content=raw, source_id=self.source_id
                )

    def test_native_adapter_detaches_and_rejects_subclasses(self) -> None:
        model = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = dotnet.analyze_supplied_dotnet_middleware_boundary(model)
        self.assertEqual(report, self.analyze())
        model["source"]["declarations_complete"] = False
        self.assertNotEqual(report, dotnet.analyze_supplied_dotnet_middleware_boundary(model))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": self.source_id, "source": []},
        ):
            with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
                dotnet.analyze_supplied_dotnet_middleware_boundary(invalid)

        class DictAlias(dict):
            pass

        with self.assertRaises(dotnet.DotnetMiddlewareBoundaryError):
            dotnet.analyze_supplied_dotnet_middleware_boundary(
                DictAlias({"source_id": self.source_id, "source": self.model})
            )

    def test_empty_routes_and_determinism_without_effects(self) -> None:
        model = copy.deepcopy(self.model)
        model["routes"] = []
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
                    dotnet.verify_dotnet_middleware_boundary(
                        report, source_content=encoded(self.model), source_id=self.source_id
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
