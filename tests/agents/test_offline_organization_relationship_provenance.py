"""Separate-source replay tests for synthetic relationship claims."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_organization_relationship_provenance as relationship


class OrganizationRelationshipProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = relationship.component_fixture()

    def report(self, model: dict) -> dict:
        return relationship.analyze_supplied_organization_relationships(model).to_dict()

    def test_conflict_and_stale_claims_remain_unverified(self) -> None:
        original = copy.deepcopy(self.model)
        report = relationship.analyze_supplied_organization_relationships(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D01-S09")
        self.assertEqual(document["summary"], {
            "relationship_count": 2, "conflict_candidate_count": 1, "unknown_count": 1,
        })
        self.assertEqual(document["projections"][0]["disposition"],
                         "candidate_conflicting_supplied_relationship_claims")
        self.assertEqual(document["projections"][1]["disposition"],
                         "unknown_only_stale_claims")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "source_independence_proven", "person_identity_verified",
            "relationship_verified", "personal_data_processed", "public_collection_performed",
            "target_interaction_performed", "finding_claimed", "full_candidate_assembled",
            "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            relationship.verify_supplied_organization_relationships(
                report, model=original,
            ).to_dict(),
            document,
        )
        self.assertEqual(
            relationship.verify_supplied_organization_relationships_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_newer_same_source_record_supersedes_older_fresh_claim(self) -> None:
        model = copy.deepcopy(self.model)
        update = copy.deepcopy(model["records"][0])
        update["record_id"] = "synthetic:update"
        update["observed_tick"] = 96
        update["reported_state"] = "former"
        model["records"].append(update)
        row = self.report(model)["projections"][0]
        self.assertEqual(row["disposition"], "supplied_former_not_exclusion")
        self.assertEqual(row["superseded_fresh_record_ids"], ["synthetic:current"])

    def test_distinct_supplied_sources_do_not_prove_identity(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][1]["reported_state"] = "current"
        report = self.report(model)
        self.assertEqual(report["projections"][0]["disposition"],
                         "multiple_supplied_current_sources")
        self.assertFalse(report["person_identity_verified"])
        self.assertFalse(report["source_independence_proven"])

    def test_incomplete_sources_or_policy_keep_unknown(self) -> None:
        for field in ("sources_complete", "policy_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["summary"]["unknown_count"], 2)

    def test_closed_model_rejects_names_contacts_and_real_identifiers(self) -> None:
        cases = []
        name = copy.deepcopy(self.model)
        name["records"][0]["full_name"] = "forbidden"
        cases.append(name)
        real = copy.deepcopy(self.model)
        real["records"][0]["subject_id"] = "someone@example.com"
        cases.append(real)
        duplicate = copy.deepcopy(self.model)
        duplicate["records"][1]["record_id"] = "synthetic:current"
        cases.append(duplicate)
        future = copy.deepcopy(self.model)
        future["records"][0]["observed_tick"] = 101
        cases.append(future)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(relationship.OrganizationRelationshipProvenanceError):
                    relationship.analyze_supplied_organization_relationships(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = relationship.analyze_supplied_organization_relationships(self.model)
        changed = copy.deepcopy(self.model)
        changed["records"][1]["reported_state"] = "current"
        with self.assertRaises(relationship.OrganizationRelationshipProvenanceError):
            relationship.verify_supplied_organization_relationships(report, model=changed)
        with self.assertRaises(relationship.OrganizationRelationshipProvenanceError):
            relationship.verify_supplied_organization_relationships_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(relationship.OrganizationRelationshipProvenanceError):
            relationship.OrganizationRelationshipProvenanceReport({})
        with self.assertRaises(relationship.OrganizationRelationshipProvenanceError):
            relationship.verify_supplied_organization_relationships(
                report.to_dict(), model=self.model,
            )


if __name__ == "__main__":
    unittest.main()
