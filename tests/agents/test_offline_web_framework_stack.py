"""Bounded synthetic framework-stack declaration tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_web_framework_stack as stack


def _row(model: dict, route_id: str = "account-gap") -> dict:
    report = stack.analyze_supplied_web_framework_stack(model).to_dict()
    return next(row for row in report["route_observations"] if row["route_id"] == route_id)


class WebFrameworkStackTests(unittest.TestCase):
    def _deny_before_address(self, model: dict) -> None:
        with patch.object(stack, "_address") as address:
            with self.assertRaises(stack.WebFrameworkStackAnalysisError):
                stack.analyze_supplied_web_framework_stack(model)
            address.assert_not_called()

    def test_fixture_is_deterministic_and_source_replay_is_exact(self) -> None:
        model = stack.component_fixture()
        report = stack.analyze_supplied_web_framework_stack(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], stack.PROFILE_ID)
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 1)
        self.assertEqual(body["route_count"], 3)
        self.assertEqual(
            [row["outcome"] for row in body["route_observations"]],
            [
                "candidate_declared_guard_order_gap",
                "declared_guard_precedes_handler",
                "unknown",
            ],
        )
        self.assertEqual(set(body["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in body["flags"].values()))
        self.assertEqual(
            report.to_json(), stack.analyze_supplied_web_framework_stack(model).to_json()
        )
        detached = stack.WebFrameworkStackAnalysis.from_json(report.to_json())
        self.assertEqual(
            stack.verify_supplied_web_framework_stack_analysis(detached, model=model).to_json(),
            report.to_json(),
        )
        model["routes"][0]["steps"].reverse()
        with self.assertRaises(stack.WebFrameworkStackAnalysisError):
            stack.verify_supplied_web_framework_stack_analysis(report, model=model)

    def test_guard_absence_or_late_order_is_only_declared_gap(self) -> None:
        model = stack.component_fixture()
        self.assertEqual(_row(model)["gap"], "required_guard_after_handler")
        model["routes"][0]["steps"].pop()
        self.assertEqual(_row(model)["gap"], "required_guard_absent")
        model["routes"][0]["steps"].insert(0, {"step_id": "session-guard", "kind": "guard"})
        self.assertEqual(_row(model)["outcome"], "declared_guard_precedes_handler")

    def test_unknown_or_mistyped_premise_never_promotes(self) -> None:
        changes = (
            (
                lambda x: x["applications"][0].update(middleware_semantics_complete=False),
                "middleware_semantics_incomplete",
            ),
            (
                lambda x: x["applications"][0].update(upstream_controls_complete=False),
                "upstream_controls_incomplete",
            ),
            (lambda x: x["routes"][0].update(policy_complete=False), "route_policy_incomplete"),
            (lambda x: x["routes"][0].update(chain_complete=False), "route_chain_incomplete"),
            (
                lambda x: x["routes"][0].update(declared_reachable=False),
                "route_reachability_unknown",
            ),
            (
                lambda x: x["routes"][0].update(handler_id="missing"),
                "declared_handler_missing_or_mistyped",
            ),
            (
                lambda x: x["routes"][0]["steps"][1].update(kind="other"),
                "required_guard_kind_mismatch",
            ),
        )
        for change, reason in changes:
            with self.subTest(reason=reason):
                model = stack.component_fixture()
                change(model)
                row = _row(model)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_schema_types_references_and_order(self) -> None:
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x["applications"][0].update(language="other"),
            lambda x: x["applications"][0].update(middleware_semantics_complete=1),
            lambda x: x["routes"][0].update(application_id="missing"),
            lambda x: x["routes"][0].update(chain_complete=1),
            lambda x: x["routes"][0]["steps"][0].update(kind="arbitrary"),
            lambda x: x["routes"][0]["steps"].append(copy.deepcopy(x["routes"][0]["steps"][0])),
            lambda x: x["routes"][0]["steps"].append(
                {"step_id": "other-handler", "kind": "handler"}
            ),
            lambda x: x["routes"].reverse(),
        )
        for change in changes:
            with self.subTest(change=change):
                model = stack.component_fixture()
                change(model)
                self._deny_before_address(model)

    def test_bytes_replay_and_forgery(self) -> None:
        model = stack.component_fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = stack.analyze_supplied_web_framework_stack(model)
        self.assertEqual(
            stack.analyze_supplied_web_framework_stack_bytes(model_bytes=raw).to_json(),
            report.to_json(),
        )
        for invalid in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(stack.WebFrameworkStackAnalysisError):
                    stack.analyze_supplied_web_framework_stack_bytes(model_bytes=invalid)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(stack.WebFrameworkStackAnalysisError):
            stack.WebFrameworkStackAnalysis.from_dict(forged)
        with self.assertRaises(stack.WebFrameworkStackAnalysisError):
            stack.verify_supplied_web_framework_stack_analysis(report.to_dict(), model=model)

    def test_cycles_and_resource_bounds(self) -> None:
        model = stack.component_fixture()
        model["cycle"] = model
        self._deny_before_address(model)
        model = stack.component_fixture()
        model["routes"] = model["routes"] * (stack.MAX_ROUTES + 1)
        self._deny_before_address(model)
        model = stack.component_fixture()
        model["routes"][0]["route_id"] = "x" * (stack.MAX_STRING_BYTES + 1)
        self._deny_before_address(model)


if __name__ == "__main__":
    unittest.main()
