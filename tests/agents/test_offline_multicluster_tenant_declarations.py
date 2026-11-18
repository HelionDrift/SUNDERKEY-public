"""Supplied multicluster tenant declaration checks."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_multicluster_tenant_declarations import (
    MulticlusterTenantDeclarationError,
    analyze_supplied_multicluster_tenant_declarations,
    component_fixture,
    verify_supplied_multicluster_tenant_declarations,
    verify_supplied_multicluster_tenant_declarations_bytes,
)


class MulticlusterTenantDeclarationTests(unittest.TestCase):
    def test_matching_declarations_are_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_multicluster_tenant_declarations(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "supplied_membership_consistent")
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["cluster_rows"][0]["tenant_checks"][0]["reciprocal_match"])
        self.assertFalse(body["provider_contacted"])
        self.assertFalse(body["cluster_contacted"])
        self.assertFalse(body["tenant_identity_verified"])
        self.assertFalse(body["tenant_isolation_verified"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_multicluster_tenant_declarations(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_multicluster_tenant_declarations_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_complete_conflict_is_only_a_candidate_about_supplied_values(self) -> None:
        model = component_fixture()
        model["tenants"][0]["cluster_ids"] = ["cluster-other"]
        body = analyze_supplied_multicluster_tenant_declarations(model).to_dict()
        self.assertEqual(body["disposition"], "candidate_supplied_membership_mismatch")
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(
            {item["issue"] for item in body["mismatches"]},
            {"cluster_tenant_membership_mismatch", "tenant_cluster_membership_mismatch"},
        )
        self.assertFalse(body["finding_claimed"])

    def test_two_cluster_membership_is_only_supplied_consistency(self) -> None:
        model = component_fixture()
        model["clusters"].append({
            "cluster_id": "cluster-b", "managed_declared": False, "tenant_ids": ["tenant-a"]
        })
        model["tenants"][0]["cluster_ids"].append("cluster-b")
        body = analyze_supplied_multicluster_tenant_declarations(model).to_dict()
        self.assertEqual(body["disposition"], "supplied_membership_consistent")
        self.assertEqual(body["cluster_record_count"], 2)
        self.assertFalse(body["managed_status_verified"])
        self.assertFalse(body["tenant_isolation_verified"])

    def test_incomplete_and_empty_inventory_are_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["tenants"][0]["cluster_ids"] = ["cluster-other"]
        body = analyze_supplied_multicluster_tenant_declarations(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["mismatches"], [])
        self.assertIsNone(body["cluster_rows"][0]["tenant_checks"][0]["reciprocal_match"])
        empty = component_fixture()
        empty["clusters"] = []
        empty["tenants"] = []
        self.assertEqual(
            analyze_supplied_multicluster_tenant_declarations(empty).to_dict()["disposition"],
            "unknown",
        )
        no_memberships = component_fixture()
        no_memberships["clusters"][0]["tenant_ids"] = []
        no_memberships["tenants"][0]["cluster_ids"] = []
        body = analyze_supplied_multicluster_tenant_declarations(no_memberships).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unknown_count"], 1)

    def test_closed_subset_and_exact_native_types(self) -> None:
        cases = []
        for field, value in (("schema_version", True), ("inventory_complete", 1)):
            model = component_fixture()
            model[field] = value
            cases.append(model)
        model = component_fixture()
        model["clusters"][0]["managed_declared"] = 1
        cases.append(model)
        model = component_fixture()
        model["clusters"][0]["extra"] = "x"
        cases.append(model)
        model = component_fixture()
        model["clusters"][0]["tenant_ids"] = ["tenant-a", "tenant-a"]
        cases.append(model)
        model = component_fixture()
        model["tenants"].append(copy.deepcopy(model["tenants"][0]))
        cases.append(model)
        model = component_fixture()
        model["clusters"] *= 65
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_multicluster_tenant_declarations(model)

    def test_original_replay_rejects_changed_source_and_forged_export(self) -> None:
        model = component_fixture()
        report = analyze_supplied_multicluster_tenant_declarations(model)
        changed = copy.deepcopy(model)
        changed["clusters"][0]["managed_declared"] = False
        with self.assertRaises(MulticlusterTenantDeclarationError):
            verify_supplied_multicluster_tenant_declarations(report, model=changed)
        with self.assertRaises(MulticlusterTenantDeclarationError):
            verify_supplied_multicluster_tenant_declarations(report.to_dict(), model=model)
        tampered = report.to_dict()
        tampered["candidate_count"] = 10
        with self.assertRaises(MulticlusterTenantDeclarationError):
            verify_supplied_multicluster_tenant_declarations_bytes(
                json.dumps(tampered).encode("ascii"), model=model
            )
        duplicated = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_multicluster_tenant_declarations_bytes(
                duplicated.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()
