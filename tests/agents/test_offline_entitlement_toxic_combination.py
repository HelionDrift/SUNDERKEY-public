"""Tests for inert entitlement toxic-pair comparisons."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_entitlement_toxic_combination as toxic
from sunderkey.offline_framework_declaration_core import canonical, report_address


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class EntitlementToxicCombinationTests(unittest.TestCase):
    source_id = "synthetic:entitlements"

    def setUp(self) -> None:
        self.model = toxic.component_fixture()

    def analyze(self, model: dict | None = None) -> toxic.EntitlementToxicCombinationReport:
        return toxic.analyze_entitlement_toxic_combination(
            source_content=encoded(self.model if model is None else model), source_id=self.source_id
        )

    def test_fixture_candidate_and_negative_are_declaration_only(self) -> None:
        report = self.analyze().to_dict()
        by_principal = {p["principal_id"]: p for p in report["projections"]}
        self.assertEqual(
            by_principal["alice"]["assessment"], "candidate_declared_toxic_combination"
        )
        self.assertEqual(by_principal["alice"]["declared_membership"], [True, True])
        self.assertEqual(by_principal["bob"]["assessment"], "declared_pair_not_present")
        self.assertFalse(report["assignments_authenticated"])
        self.assertFalse(report["permission_enforcement_observed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["effects"].values()), {"none"})
        self.assertEqual(report["wave_id"], "IW2-015")

    def test_inheritance_and_assignment_changes_are_exact(self) -> None:
        model = copy.deepcopy(self.model)
        model["principals"][0]["role_ids"] = ["approver"]
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][0]["assessment"],
            "declared_pair_not_present",
        )
        model["roles"][0]["inherits"] = ["editor"]
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][0]["assessment"],
            "candidate_declared_toxic_combination",
        )

    def test_each_partial_or_dynamic_premise_yields_unknown(self) -> None:
        for field in (
            "graph_complete",
            "assignments_complete",
            "grants_complete",
            "toxic_policy_complete",
            "dynamic_entitlements_absent",
        ):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                report = self.analyze(model).to_dict()
                self.assertFalse(report["premises_complete"])
                self.assertTrue(all(p["assessment"] == "unknown" for p in report["projections"]))
                self.assertTrue(
                    all(p["declared_membership"] == [None, None] for p in report["projections"])
                )
        model = copy.deepcopy(self.model)
        model["graph_complete"] = False
        model["toxic_policy_complete"] = "true"
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            self.analyze(model)

    def test_closed_graph_rejects_cycles_refs_pairs_and_non_boolean_flags(self) -> None:
        invalid = []
        cycle = copy.deepcopy(self.model)
        cycle["roles"][2]["inherits"] = ["approver"]
        invalid.append(cycle)
        missing_parent = copy.deepcopy(self.model)
        missing_parent["roles"][0]["inherits"] = ["missing"]
        invalid.append(missing_parent)
        missing_assignment = copy.deepcopy(self.model)
        missing_assignment["principals"][0]["role_ids"] = ["missing"]
        invalid.append(missing_assignment)
        duplicate_pair = copy.deepcopy(self.model)
        duplicate_pair["toxic_pairs"].append(
            {
                "pair_id": "reversed",
                "permission_a": "payment.approve",
                "permission_b": "payment.create",
            }
        )
        invalid.append(duplicate_pair)
        same_pair = copy.deepcopy(self.model)
        same_pair["toxic_pairs"][0]["permission_b"] = "payment.create"
        invalid.append(same_pair)
        for model in invalid:
            with (
                self.subTest(model=model),
                self.assertRaises(toxic.EntitlementToxicCombinationError),
            ):
                self.analyze(model)

    def test_raw_decoder_bounds_and_closed_source(self) -> None:
        invalid = (
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"x":NaN}',
            b'{"x":1.2}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (toxic.MAX_DEPTH + 1) + b"0" + b"]" * (toxic.MAX_DEPTH + 1),
            b" " * (toxic.MAX_SOURCE_BYTES + 1),
        )
        for raw in invalid:
            with (
                self.subTest(raw=raw[:24]),
                self.assertRaises(toxic.EntitlementToxicCombinationError),
            ):
                toxic.analyze_entitlement_toxic_combination(
                    source_content=raw, source_id=self.source_id
                )
        model = copy.deepcopy(self.model)
        model["target_url"] = "https://example.invalid"
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            self.analyze(model)

    def test_exact_replay_rejects_changed_and_readdressed_source(self) -> None:
        report = self.analyze()
        self.assertEqual(
            toxic.verify_entitlement_toxic_combination(
                report, source_content=encoded(self.model), source_id=self.source_id
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["principals"][0]["role_ids"] = ["approver"]
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            toxic.verify_entitlement_toxic_combination(
                report, source_content=encoded(changed), source_id=self.source_id
            )
        forged = report.to_dict()
        forged["projections"][0]["assessment"] = "declared_pair_not_present"
        forged["summary"]["assessments"]["candidate_declared_toxic_combination"] -= 1
        forged["summary"]["assessments"]["declared_pair_not_present"] += 1
        forged["report_id"], forged["report_sha256"] = report_address(
            forged, domain=toxic.DOMAIN, prefix="ETC-"
        )
        parsed = toxic.EntitlementToxicCombinationReport.from_json(canonical(forged))
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            toxic.verify_entitlement_toxic_combination(
                parsed, source_content=encoded(self.model), source_id=self.source_id
            )

    def test_report_claim_tampering_and_adapter_validation(self) -> None:
        report = self.analyze()
        forged = report.to_dict()
        forged["positive_use_approved"] = True
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            toxic.EntitlementToxicCombinationReport.from_json(canonical(forged))
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        self.assertEqual(toxic.analyze_supplied_entitlement_toxic_combination(native), report)
        native["source"]["dynamic_entitlements_absent"] = False
        self.assertNotEqual(toxic.analyze_supplied_entitlement_toxic_combination(native), report)
        native["extra"] = False
        with self.assertRaises(toxic.EntitlementToxicCombinationError):
            toxic.analyze_supplied_entitlement_toxic_combination(native)

    def test_example_fixture_and_no_effects(self) -> None:
        root = Path(__file__).resolve().parents[2]
        example = json.loads(
            (root / "examples/offline-entitlement-toxic-combination-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"]["source"], self.model)
        self.assertEqual(example["profile_id"], toxic.PROFILE_ID)
        self.assertEqual(example["component_id"], toxic.COMPONENT_ID)
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    toxic.verify_entitlement_toxic_combination(
                        report, source_content=encoded(self.model), source_id=self.source_id
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
