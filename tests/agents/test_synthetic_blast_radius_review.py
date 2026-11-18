"""Offline synthetic impact review preserves consent and evidence limits."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

from sunderkey.synthetic_blast_radius_review import (
    SyntheticBlastRadiusReviewError,
    build_synthetic_blast_radius_review,
    verify_synthetic_blast_radius_review,
)
from sunderkey.synthetic_scenario_planning import (
    SyntheticScenarioConsent,
    SyntheticScenarioRequest,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
PRINCIPAL = "synthetic-principal:sha256:" + "c" * 64
SURFACE = "surface:sha256:" + "d" * 64
SERVICE = "synthetic-resource:sha256:" + "1" * 64
DATA = "synthetic-resource:sha256:" + "2" * 64
RECOVERY = "synthetic-resource:sha256:" + "3" * 64
EVIDENCE = "sha256:" + "e" * 64
BOUNDARY = "sha256:" + "f" * 64
EDGE_TIME = "2026-09-23T14:15:00Z"


def request(**changes):
    values = {
        "request_id": "request:one", "tenant_id": "tenant:one",
        "scope_sha256": SCOPE, "scenario_id": "scenario:one",
        "kind": "synthetic_insider_start_position",
        "synthetic_principal_ref": PRINCIPAL, "surface_ref": SURFACE,
        "created_at": "2026-09-23T12:00:00Z",
        "window_start": "2026-09-23T14:00:00Z",
        "window_end": "2026-09-23T15:00:00Z", "source_sha256": SOURCE,
    }
    values.update(changes)
    return SyntheticScenarioRequest(**values)


def consent(**changes):
    values = {
        "tenant_id": "tenant:one", "scope_sha256": SCOPE,
        "scenario_id": "scenario:one", "kind": "synthetic_insider_start_position",
        "synthetic_principal_refs": (PRINCIPAL,), "surface_refs": (SURFACE,),
        "issued_at": "2026-09-23T11:00:00Z",
        "expires_at": "2026-09-23T16:00:00Z", "source_sha256": SOURCE,
    }
    values.update(changes)
    return SyntheticScenarioConsent(**values)


def node(ref, kind, impact="none"):
    return {
        "node_ref": ref, "kind": kind, "impact_class": impact,
        "evidence_sha256": EVIDENCE,
    }


def edge(source, target, result="declared_passed", at=EDGE_TIME):
    return {
        "from_ref": source, "to_ref": target,
        "boundary_kind": "network_segment", "boundary_sha256": BOUNDARY,
        "declared_result": result, "occurred_at": at,
        "evidence_sha256": EVIDENCE,
    }


def graph():
    return {
        "schema_version": 1, "seed_ref": PRINCIPAL,
        "nodes": [
            node(PRINCIPAL, "principal"),
            node(SERVICE, "service", "synthetic_service_access"),
            node(DATA, "data_canary", "synthetic_data_canary_reach"),
            node(RECOVERY, "recovery_canary", "synthetic_recovery_canary_reach"),
        ],
        "edges": [
            edge(PRINCIPAL, SERVICE), edge(SERVICE, DATA),
            edge(SERVICE, RECOVERY, "declared_blocked"),
        ],
        "source_sha256": SOURCE,
    }


def closure():
    return {
        "cleanup_status": "pending", "cleanup_at": None,
        "cleanup_evidence_sha256": None,
        "disclosure_status": "pending", "disclosure_at": None,
        "disclosure_evidence_sha256": None,
        "custody_sha256": SOURCE,
    }


def review(**changes):
    values = {
        "request": request(), "consent": consent(),
        "planned_at": "2026-09-23T13:00:00Z",
        "review_at": "2026-09-23T16:00:00Z",
        "graph": graph(), "closure": closure(),
    }
    values.update(changes)
    return build_synthetic_blast_radius_review(**values)


class SyntheticBlastRadiusReviewTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_report_matches_closed_schema(self):
        path = (
            Path(__file__).resolve().parents[2] / "registry" / "schemas"
            / "synthetic-blast-radius-review-v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(review())
        bad = review()
        bad["unknown"] = True
        with self.assertRaises(ValidationError):
            validator.validate(bad)

    def test_declared_impact_paths_are_bounded_and_unqualified(self):
        result = review()
        self.assertEqual(result["declared_reachable_node_count"], 3)
        self.assertEqual(result["declared_blocked_edge_count"], 1)
        self.assertEqual(
            [item["node_ref"] for item in result["declared_impact_paths"]],
            [SERVICE, DATA],
        )
        self.assertEqual(result["declared_impact_paths"][1]["declared_path"], [
            PRINCIPAL, SERVICE, DATA,
        ])
        self.assertTrue(result["cleanup_due"])
        self.assertTrue(result["disclosure_due"])
        self.assertFalse(result["path_outcomes_verified"])
        self.assertFalse(result["consent_authenticated"])
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(result["effects"]["target_interaction"], "none")
        self.assertEqual(result["effects"]["credential_collection"], "none")
        self.assertEqual(
            verify_synthetic_blast_radius_review(
                request(), consent(), planned_at="2026-09-23T13:00:00Z",
                review_at="2026-09-23T16:00:00Z", graph=graph(),
                closure=closure(), result=result,
            )["status"],
            "valid",
        )

    def test_blocked_unknown_and_cycles_do_not_expand_impact(self):
        source = graph()
        source["edges"][1]["declared_result"] = "unknown"
        source["edges"].append(edge(DATA, SERVICE))
        source["edges"].sort(key=lambda item: (item["from_ref"], item["to_ref"]))
        result = review(graph=source)
        self.assertEqual(result["declared_reachable_node_count"], 2)
        self.assertEqual(len(result["declared_impact_paths"]), 1)
        self.assertEqual(result["unknown_edge_count"], 1)

    def test_missing_or_mismatched_consent_fails_closed(self):
        for approval in (
            consent(scenario_id="scenario:other"),
            consent(surface_refs=("surface:sha256:" + "9" * 64,)),
            consent(expires_at="2026-09-23T14:30:00Z"),
        ):
            with self.subTest(approval=approval):
                with self.assertRaisesRegex(
                    SyntheticBlastRadiusReviewError, "no current consent candidate",
                ):
                    review(consent=approval)
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "plan is invalid"):
            review(request=request(tenant_id="tenant:other"))

    def test_out_of_scope_and_secret_like_nodes_fail_closed(self):
        bad = graph()
        bad["nodes"][1]["node_ref"] = "employee@example.com"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "opaque synthetic"):
            review(graph=bad)
        bad = graph()
        bad["seed_ref"] = SERVICE
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "seed differs"):
            review(graph=bad)
        bad = graph()
        bad["nodes"][2]["impact_class"] = "actual_sensitive_data"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "classification"):
            review(graph=bad)

    def test_edge_time_boundary_and_order_fail_closed(self):
        bad = graph()
        bad["edges"][0]["occurred_at"] = "2026-09-23T15:00:00Z"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "consented window"):
            review(graph=bad)
        bad = graph()
        bad["edges"][0]["boundary_sha256"] = "none"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "boundary evidence"):
            review(graph=bad)
        bad = graph()
        bad["edges"].reverse()
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "canonical"):
            review(graph=bad)
        bad = graph()
        bad["edges"][0]["from_ref"] = []
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "invalid nodes"):
            review(graph=bad)
        bad = graph()
        bad["nodes"][1]["kind"] = []
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "classification"):
            review(graph=bad)
        bad = graph()
        bad["edges"][0]["occurred_at"] = "2026-09-23T14:15:00Z"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "consented window"):
            review(graph=bad, planned_at="2026-09-23T14:30:00Z")
        bad = graph()
        bad["edges"].append(copy.deepcopy(bad["edges"][-1]))
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "canonical"):
            review(graph=bad)

    def test_declared_closure_is_not_verified(self):
        complete = closure()
        complete.update({
            "cleanup_status": "declared_complete",
            "cleanup_at": "2026-09-23T15:10:00Z",
            "cleanup_evidence_sha256": EVIDENCE,
            "disclosure_status": "declared_complete",
            "disclosure_at": "2026-09-23T15:20:00Z",
            "disclosure_evidence_sha256": EVIDENCE,
        })
        result = review(closure=complete)
        self.assertFalse(result["cleanup_due"])
        self.assertFalse(result["disclosure_due"])
        self.assertFalse(result["cleanup_verified"])
        self.assertFalse(result["disclosure_verified"])
        complete["cleanup_at"] = "2026-09-23T14:00:00Z"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "timing"):
            review(closure=complete)
        pending = closure()
        pending["cleanup_evidence_sha256"] = EVIDENCE
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "pending cleanup"):
            review(closure=pending)

    def test_source_and_report_tampering_fail_replay(self):
        result = review()
        changed = graph()
        changed["edges"][1]["declared_result"] = "declared_blocked"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "does not reproduce"):
            verify_synthetic_blast_radius_review(
                request(), consent(), planned_at="2026-09-23T13:00:00Z",
                review_at="2026-09-23T16:00:00Z", graph=changed,
                closure=closure(), result=result,
            )
        tampered = copy.deepcopy(result)
        tampered["effects"]["target_interaction"] = "allowed"
        with self.assertRaisesRegex(SyntheticBlastRadiusReviewError, "does not reproduce"):
            verify_synthetic_blast_radius_review(
                request(), consent(), planned_at="2026-09-23T13:00:00Z",
                review_at="2026-09-23T16:00:00Z", graph=graph(),
                closure=closure(), result=tampered,
            )


if __name__ == "__main__":
    unittest.main()
