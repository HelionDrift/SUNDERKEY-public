"""Refusal and exact-replay tests for conditional path review eligibility."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime
from pathlib import Path

from sunderkey import offline_path_review_eligibility as gate

SCOPE = "sha256:" + "a" * 64
CONTEXT = "sha256:" + "b" * 64
SOURCES = ["sha256:" + str(index) * 64 for index in range(5)]
TIME = "2026-09-30T12:00:00Z"
FIXTURE_TRUSTED_NOW = "2026-09-30T12:05:00Z"


def rebind_reviews(item: dict) -> None:
    body = {key: value for key, value in item.items() if key != "reviews"}
    body_sha = gate._sha({"domain": gate.DOMAIN + ".candidate-body", "body": body})
    for review in item["reviews"]:
        review["candidate_body_sha256"] = body_sha


def candidate() -> dict:
    nodes = ["node:entry", "node:middle", "node:objective"]
    node_proofs = [
        {"node_id": node, "proof_id": f"proof:n{index}"}
        for index, node in enumerate(nodes)
    ]
    edges = [
        {"from_id": nodes[index], "to_id": nodes[index + 1],
         "proof_id": f"proof:e{index}"}
        for index in range(2)
    ]
    observations = []
    for index, (kind, subject, obj, proof) in enumerate(
        [("node", node, None, f"proof:n{position}")
         for position, node in enumerate(nodes)]
        + [("edge", nodes[position], nodes[position + 1], f"proof:e{position}")
           for position in range(2)]
    ):
        observations.append({
            "proof_id": proof,
            "claim_kind": kind,
            "subject_id": subject,
            "object_id": obj,
            "disposition": "supports",
            "evidence_class": "independently_authenticated_observation",
            "source_sha256": SOURCES[index],
            "lineage_sha256s": [SOURCES[index]],
            "producer_id": "producer:one",
            "tenant_id": "tenant:one",
            "context_sha256": CONTEXT,
            "scope_sha256": SCOPE,
            "observed_at": "2026-09-30T11:00:00Z",
            "expires_at": "2026-09-30T13:00:00Z",
        })
    result = {
        "schema_version": 1,
        "tenant_id": "tenant:one",
        "context_sha256": CONTEXT,
        "scope_sha256": SCOPE,
        "evaluated_at": TIME,
        "path": {"nodes": nodes, "node_proofs": node_proofs, "edges": edges},
        "observations": observations,
        "reviews": [],
    }
    body = {key: value for key, value in result.items() if key != "reviews"}
    body_sha = gate._sha({"domain": gate.DOMAIN + ".candidate-body", "body": body})
    result["reviews"] = [
        {"review_id": f"review:{role}", "role": role, "reviewer_id": f"reviewer:{role}",
         "decision": "accept", "candidate_body_sha256": body_sha,
         "reviewed_at": "2026-09-30T11:30:00Z"}
        for role in ("control", "assurance")
    ]
    return result


class FixtureVerifier:
    """Inert fixture only. It is not an independently trusted verifier."""

    def __init__(self) -> None:
        self.time_override = None
        self.observation_override = None
        self.lineage_override = None
        self.review_override = None

    def verify_time(self, candidate_body_sha256, evaluated_at):
        now = datetime.fromisoformat(FIXTURE_TRUSTED_NOW.replace("Z", "+00:00"))
        proposed = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
        age = (now - proposed).total_seconds()
        result = {
            "candidate_body_sha256": candidate_body_sha256,
            "evaluated_at": evaluated_at,
            "decision": ("within_trusted_current_window" if 0 <= age <= 900
                         else "outside_trusted_current_window"),
            "verifier_id": "verifier:fixture",
        }
        if self.time_override is not None:
            result.update(self.time_override)
        return result

    def verify_observation(self, observation, candidate_body_sha256, evaluated_at):
        del evaluated_at
        result = {
            "proof_id": observation["proof_id"],
            "source_sha256": observation["source_sha256"],
            "candidate_body_sha256": candidate_body_sha256,
            "verification_kind": "independently_authenticated_observation",
            "accepted": True,
            "verifier_id": "verifier:fixture",
        }
        if self.observation_override is not None:
            result.update(self.observation_override)
        return result

    def verify_lineage(self, observations, candidate_body_sha256, evaluated_at):
        del evaluated_at
        sources = sorted({item for obs in observations for item in obs["lineage_sha256s"]})
        result = {
            "candidate_body_sha256": candidate_body_sha256,
            "source_sha256s": sources,
            "complete": True,
            "conflict_free": True,
            "verifier_id": "verifier:fixture",
        }
        if self.lineage_override is not None:
            result.update(self.lineage_override)
        return result

    def verify_review(self, review, candidate_body_sha256, evaluated_at):
        del evaluated_at
        result = {
            "review_id": review["review_id"],
            "reviewer_id": review["reviewer_id"],
            "role": review["role"],
            "candidate_body_sha256": candidate_body_sha256,
            "decision": "accept",
            "accepted": True,
            "verifier_id": "verifier:fixture",
        }
        if self.review_override is not None:
            result.update(self.review_override)
        return result


class PathReviewEligibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.item = candidate()
        self.verifier = FixtureVerifier()

    def assert_refused(self, item=None, verifier=None) -> None:
        with self.assertRaises(gate.PathReviewEligibilityError):
            gate.evaluate_path_review_eligibility(
                self.item if item is None else item,
                self.verifier if verifier is None else verifier,
            )

    def test_conditional_packet_and_fresh_replay_only(self) -> None:
        packet = gate.evaluate_path_review_eligibility(self.item, self.verifier)
        self.assertEqual(packet["eligibility"],
                         "conditional_review_eligible_under_injected_verifier")
        self.assertEqual(packet["world_edge_promotion"], "none")
        self.assertEqual(packet["finding_eligibility"], "none")
        self.assertEqual(set(packet["operational_effects"].values()), {"none"})
        self.assertEqual(gate.verify_path_review_eligibility(packet, self.item,
                                                             self.verifier), packet)

    def test_checked_synthetic_example_matches_fixture(self) -> None:
        example = Path(__file__).resolve().parents[2] / "examples" / (
            "offline-path-review-eligibility.json"
        )
        supplied = json.loads(example.read_text(encoding="utf-8"))
        self.assertEqual(supplied, self.item)
        packet = gate.evaluate_path_review_eligibility(supplied, self.verifier)
        self.assertEqual(packet["verifier_trust"],
                         "externally_assumed_not_established_by_this_module")

    def test_offline_and_operator_sources_refused(self) -> None:
        for source_class in ("operator_supplied", "offline_specialist_leaf"):
            with self.subTest(source_class=source_class):
                item = candidate()
                item["observations"][0]["evidence_class"] = source_class
                self.assert_refused(item)

    def test_missing_intermediate_hop_refused(self) -> None:
        item = candidate()
        item["path"]["edges"].pop()
        self.assert_refused(item)
        item = candidate()
        item["path"]["nodes"][1] = {"unexpected": "mapping"}
        self.assert_refused(item)

    def test_source_substitution_and_context_rebinding_refused(self) -> None:
        item = candidate()
        item["observations"][0]["source_sha256"] = "sha256:" + "f" * 64
        self.assert_refused(item)
        item = candidate()
        item["observations"][1]["context_sha256"] = "sha256:" + "f" * 64
        self.assert_refused(item)

    def test_stale_or_future_observation_refused(self) -> None:
        item = candidate()
        item["observations"][0]["expires_at"] = TIME
        self.assert_refused(item)
        item = candidate()
        item["observations"][0]["observed_at"] = "2026-09-30T12:01:00Z"
        self.assert_refused(item)

    def test_backdated_candidate_refused_by_injected_trusted_time(self) -> None:
        item = candidate()
        item["evaluated_at"] = "2026-09-30T11:40:00Z"
        rebind_reviews(item)
        self.assert_refused(item)

    def test_missing_or_substituted_time_receipt_refused(self) -> None:
        with self.assertRaises(gate.PathReviewEligibilityError):
            gate.evaluate_path_review_eligibility(self.item, object())
        self.verifier.time_override = {"candidate_body_sha256": SCOPE}
        self.assert_refused()
        self.verifier.time_override = {"evaluated_at": "2026-09-30T11:59:00Z"}
        self.assert_refused()
        self.verifier.time_override = {"decision": "outside_trusted_current_window"}
        self.assert_refused()
        self.verifier.time_override = {"decision": True}
        self.assert_refused()

    def test_conflict_and_incomplete_lineage_refused(self) -> None:
        self.verifier.lineage_override = {"conflict_free": False}
        self.assert_refused()
        self.verifier.lineage_override = {"complete": False}
        self.assert_refused()
        item = candidate()
        item["observations"][1]["disposition"] = "contradicts"
        self.assert_refused(item)

    def test_same_reviewer_or_producer_as_reviewer_refused(self) -> None:
        item = candidate()
        item["reviews"][1]["reviewer_id"] = item["reviews"][0]["reviewer_id"]
        self.assert_refused(item)
        item = candidate()
        item["reviews"][0]["reviewer_id"] = "producer:one"
        self.assert_refused(item)

    def test_forged_or_unbound_verifier_receipt_refused(self) -> None:
        self.verifier.observation_override = {"candidate_body_sha256": SCOPE}
        self.assert_refused()
        self.verifier.observation_override = None
        self.verifier.lineage_override = {"source_sha256s": [SOURCES[0]]}
        self.assert_refused()
        self.verifier.lineage_override = None
        self.verifier.review_override = {"reviewer_id": "reviewer:other"}
        self.assert_refused()
        self.verifier.review_override = None
        self.verifier.observation_override = {"accepted": 1}
        self.assert_refused()

    def test_tamper_or_rebind_packet_refused_on_replay(self) -> None:
        packet = gate.evaluate_path_review_eligibility(self.item, self.verifier)
        changed = copy.deepcopy(packet)
        changed["finding_eligibility"] = "accepted"
        with self.assertRaises(gate.PathReviewEligibilityError):
            gate.verify_path_review_eligibility(changed, self.item, self.verifier)
        changed = candidate()
        changed["tenant_id"] = "tenant:other"
        with self.assertRaises(gate.PathReviewEligibilityError):
            gate.verify_path_review_eligibility(packet, changed, self.verifier)


if __name__ == "__main__":
    unittest.main()
