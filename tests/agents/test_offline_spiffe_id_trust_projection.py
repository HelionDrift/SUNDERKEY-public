"""Source-replayed tests for inert SPIFFE ID and trust-domain projection."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_spiffe_id_trust_projection as spiffe


class SpiffeIdTrustProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = spiffe.component_fixture()

    def projection(self, model: dict, index: int = 1) -> dict:
        return spiffe.analyze_supplied_spiffe_id_trust(model).to_dict()["projections"][index]

    def test_untrusted_domain_is_only_a_declared_candidate(self) -> None:
        original = copy.deepcopy(self.model)
        report = spiffe.analyze_supplied_spiffe_id_trust(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S10")
        self.assertEqual(document["summary"], {
            "observation_count": 2, "candidate_count": 1, "unknown_count": 1,
        })
        trusted, untrusted = document["projections"]
        self.assertEqual(trusted["projected_decision"], "unknown")
        self.assertEqual(trusted["basis"], "no_svid_or_bundle_validation")
        self.assertEqual(untrusted["projected_decision"], "deny")
        self.assertEqual(untrusted["assessment"], "candidate_declared_trust_boundary_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "trust_policy_authenticated",
            "reported_outcomes_authenticated", "svid_signature_validated",
            "trust_bundle_validated", "effective_workload_access_observed",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            spiffe.verify_supplied_spiffe_id_trust(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            spiffe.verify_supplied_spiffe_id_trust_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_syntax_rejections_follow_narrow_spiffe_id_boundary(self) -> None:
        invalid = (
            "spiffe:///service",
            "spiffe://example.org/service/",
            "spiffe://example.org/./service",
            "spiffe://example.org/../service",
            "spiffe://example.org/a//b",
            "spiffe://example.org/service?query=1",
            "spiffe://example.org/service#fragment",
            "spiffe://example.org:443/service",
            "spiffe://user@example.org/service",
            "spiffe://Example.org/service",
            "spiffe://example.org/percent%20encoded",
            "https://example.org/service",
        )
        for value in invalid:
            model = copy.deepcopy(self.model)
            model["observations"][0]["spiffe_id"] = value
            with self.subTest(value=value):
                row = self.projection(model, 0)
                self.assertEqual(row["projected_decision"], "deny")
                self.assertEqual(row["basis"], "invalid_spiffe_id")
        model = copy.deepcopy(self.model)
        model["observations"][0]["spiffe_id"] = "SPIFFE://example.org/Service"
        row = self.projection(model, 0)
        self.assertEqual(row["parsed_trust_domain"], "example.org")
        self.assertEqual(row["projected_decision"], "unknown")

    def test_incomplete_trust_policy_preserves_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["trust_policy_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "incomplete_trust_policy")
        model = copy.deepcopy(self.model)
        model["observations"][1]["reported_outcome"] = "rejected"
        self.assertEqual(self.projection(model)["assessment"], "declared_rejection_consistent")

    def test_closed_bounded_model_rejects_bad_metadata(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["bundle_endpoint"] = "https://example.invalid"
        cases.append(extra)
        duplicate = copy.deepcopy(self.model)
        duplicate["trusted_domains"].append("example.org")
        cases.append(duplicate)
        uppercase = copy.deepcopy(self.model)
        uppercase["trusted_domains"] = ["Example.org"]
        cases.append(uppercase)
        observation = copy.deepcopy(self.model)
        observation["observations"].append(copy.deepcopy(observation["observations"][0]))
        cases.append(observation)
        oversized = copy.deepcopy(self.model)
        oversized["observations"][0]["spiffe_id"] = "a" * (spiffe.MAX_ID_BYTES + 1)
        cases.append(oversized)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(spiffe.SpiffeIdTrustProjectionError):
                    spiffe.analyze_supplied_spiffe_id_trust(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = spiffe.analyze_supplied_spiffe_id_trust(self.model)
        changed = copy.deepcopy(self.model)
        changed["trusted_domains"].append("other.example")
        with self.assertRaises(spiffe.SpiffeIdTrustProjectionError):
            spiffe.verify_supplied_spiffe_id_trust(report, model=changed)
        with self.assertRaises(spiffe.SpiffeIdTrustProjectionError):
            spiffe.verify_supplied_spiffe_id_trust_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(spiffe.SpiffeIdTrustProjectionError):
            spiffe.SpiffeIdTrustProjectionReport({})
        with self.assertRaises(spiffe.SpiffeIdTrustProjectionError):
            spiffe.verify_supplied_spiffe_id_trust(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
