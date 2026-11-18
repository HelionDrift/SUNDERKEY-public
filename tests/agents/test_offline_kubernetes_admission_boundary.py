"""Synthetic Kubernetes admission projection and original-source replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_kubernetes_admission_boundary as admission

ERROR = admission.KubernetesAdmissionBoundaryAnalysisError


def fixture() -> dict:
    return admission.component_fixture()


def analyze(model: dict) -> dict:
    return admission.analyze_supplied_kubernetes_admission_boundary(model).to_dict()


def row(model: dict, request_id: str = "admitted-contradiction") -> dict:
    return next(
        item for item in analyze(model)["request_observations"] if item["request_id"] == request_id
    )


class KubernetesAdmissionBoundaryTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(admission, "_address") as address:
            with self.assertRaises(ERROR):
                admission.analyze_supplied_kubernetes_admission_boundary(model)
            address.assert_not_called()

    def test_fixture_replay_and_no_effects(self):
        model = fixture()
        report = admission.analyze_supplied_kubernetes_admission_boundary(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GC-D15-S08")
        self.assertEqual(document["blueprint_sha256"], admission.BLUEPRINT_SHA256)
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [item["outcome"] for item in document["request_observations"]],
            [
                "candidate_declared_reject_admitted_contradiction",
                "matches_declared_admission",
                "unknown",
            ],
        )
        self.assertEqual(
            document["request_observations"][0]["veto_policy_ids"], ["block-privileged"]
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(),
            admission.analyze_supplied_kubernetes_admission_boundary(model).to_json(),
        )
        parsed = admission.KubernetesAdmissionBoundaryAnalysis.from_json(report.to_json())
        self.assertEqual(
            admission.verify_supplied_kubernetes_admission_boundary_analysis(
                parsed, model=model
            ).to_json(),
            report.to_json(),
        )
        model["requests"][0]["post_mutation_fields"]["privileged"] = "false"
        with self.assertRaises(ERROR):
            admission.verify_supplied_kubernetes_admission_boundary_analysis(report, model=model)

    def test_no_veto_does_not_claim_base_admission(self):
        model = fixture()
        model["requests"][0]["post_mutation_fields"]["privileged"] = "false"
        observed = row(model)
        self.assertIsNone(observed["expected_outcome"])
        self.assertEqual(observed["outcome"], "unknown")
        self.assertIn("unmodeled_admission_stages", observed["uncertainty"])
        model["requests"][0]["supplied_outcome"] = "rejected"
        self.assertEqual(row(model)["outcome"], "unknown")
        model["requests"][0]["post_mutation_fields"]["privileged"] = "true"
        self.assertEqual(row(model)["expected_outcome"], "reject")
        model["requests"][0]["namespace_id"] = "team-b"
        self.assertEqual(row(model)["matching_policy_ids"], [])
        self.assertIsNone(row(model)["expected_outcome"])

    def test_webhook_fail_ignore_and_unknown_availability(self):
        model = fixture()
        policy = model["policies"][0]
        policy["policy_kind"] = "validating_webhook"
        policy["availability"] = "unavailable"
        self.assertEqual(row(model)["expected_outcome"], "reject")
        self.assertEqual(row(model)["veto_policy_ids"], ["block-privileged"])
        policy["failure_policy"] = "ignore"
        self.assertIsNone(row(model)["expected_outcome"])
        self.assertEqual(row(model)["outcome"], "unknown")
        self.assertIn("unmodeled_admission_stages", row(model)["uncertainty"])
        policy["availability"] = "unknown"
        self.assertEqual(row(model)["outcome"], "unknown")
        self.assertIn("matching_policy_uncertain", row(model)["uncertainty"])

    def test_incomplete_premises_never_promote_candidate(self):
        cases = (
            ("inventory", lambda x: x.update(policy_set_complete=False), "policy_set_incomplete"),
            (
                "context",
                lambda x: x["requests"][0].update(context_complete=False),
                "request_context_incomplete",
            ),
            (
                "mutation",
                lambda x: x["requests"][0].update(mutation_complete=False),
                "mutation_result_incomplete",
            ),
            (
                "observation",
                lambda x: x["requests"][0].update(observation_complete=False),
                "request_observation_incomplete",
            ),
            (
                "policy_semantics",
                lambda x: x["policies"][0].update(semantics_complete=False),
                "matching_policy_uncertain",
            ),
            (
                "policy_effect",
                lambda x: x["policies"][0].update(effect="unknown"),
                "matching_policy_uncertain",
            ),
        )
        for name, change, reason in cases:
            with self.subTest(name=name):
                model = fixture()
                change(model)
                observed = row(model)
                self.assertEqual(observed["outcome"], "unknown")
                self.assertIn(reason, observed["uncertainty"])
        model = fixture()
        model["requests"][2]["crd_schema_complete"] = True
        self.assertIn(
            "operator_reconciliation_incomplete", row(model, "unknown-operator")["uncertainty"]
        )
        model["requests"][2]["operator_reconcile_complete"] = True
        model["requests"][2]["crd_schema_complete"] = False
        self.assertIn("crd_schema_incomplete", row(model, "unknown-operator")["uncertainty"])

    def test_closed_types_references_and_no_widening(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(policy_set_complete=1),
            lambda x: x["policies"][0].update(policy_kind="mutating_webhook"),
            lambda x: x["policies"][0].update(match_field="privileged", match_value=None),
            lambda x: x["policies"][0].update(failure_policy="ignore"),
            lambda x: x["policies"][0].update(availability="unavailable"),
            lambda x: x["policies"][0].update(semantics_complete=1),
            lambda x: x["requests"][0].update(resource_family="custom"),
            lambda x: x["requests"][0].update(operation="delete"),
            lambda x: x["requests"][0].update(post_mutation_fields={"x": True}),
            lambda x: x["requests"][0].update(context_complete=1),
            lambda x: x["requests"].reverse(),
        )
        for change in changes:
            model = fixture()
            change(model)
            with self.subTest(model=model):
                self.deny_before_hash(model)

    def test_raw_bytes_and_forged_report(self):
        model = fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = admission.analyze_supplied_kubernetes_admission_boundary(model)
        self.assertEqual(
            admission.analyze_supplied_kubernetes_admission_boundary_bytes(
                model_bytes=raw
            ).to_json(),
            report.to_json(),
        )
        for data in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(data=data[:40]):
                with self.assertRaises(ERROR):
                    admission.analyze_supplied_kubernetes_admission_boundary_bytes(model_bytes=data)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(ERROR):
            admission.KubernetesAdmissionBoundaryAnalysis.from_dict(forged)
        forged = copy.deepcopy(report.to_dict())
        forged["source_model"]["requests"][0]["post_mutation_fields"]["privileged"] = "false"
        with self.assertRaises(ERROR):
            admission.KubernetesAdmissionBoundaryAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            admission.verify_supplied_kubernetes_admission_boundary_analysis(
                report.to_dict(), model=model
            )

    def test_native_cycle_and_bounds(self):
        model = fixture()
        model["cycle"] = model
        self.deny_before_hash(model)
        model = fixture()
        model["requests"] = model["requests"] * (admission.MAX_REQUESTS + 1)
        self.deny_before_hash(model)
        model = fixture()
        model["requests"][0]["request_id"] = "x" * (admission.MAX_STRING_BYTES + 1)
        self.deny_before_hash(model)


if __name__ == "__main__":
    unittest.main()
