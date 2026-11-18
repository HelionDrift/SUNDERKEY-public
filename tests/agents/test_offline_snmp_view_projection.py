"""Synthetic tests for bounded supplied SNMP view declarations."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_snmp_view_projection as snmp


class SnmpViewProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = snmp.component_fixture()

    def report(self, model: dict) -> dict:
        return snmp.analyze_supplied_snmp_view(model).to_dict()

    def test_longest_prefix_difference_is_source_bound_and_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = snmp.analyze_supplied_snmp_view(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S15")
        self.assertEqual(
            document["summary"],
            {
                "query_count": 2,
                "candidate_count": 1,
                "unknown_count": 0,
            },
        )
        self.assertEqual(document["projections"][0]["projected_allowed"], True)
        self.assertEqual(document["projections"][1]["projected_allowed"], False)
        self.assertEqual(
            document["projections"][1]["issues"], ["declared_access_differs_from_policy"]
        )
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated",
            "device_configuration_observed",
            "snmp_request_sent",
            "snmp_response_observed",
            "authentication_verified",
            "access_bypass_proven",
            "finding_claimed",
            "full_candidate_assembled",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(snmp.verify_supplied_snmp_view(report, model=original).to_dict(), document)
        self.assertEqual(
            snmp.verify_supplied_snmp_view_bytes(
                report.to_json().encode("ascii"),
                model=original,
            ).to_dict(),
            document,
        )

    def test_unmatched_prefix_and_unbound_operation_project_deny(self) -> None:
        model = copy.deepcopy(self.model)
        model["queries"][0]["oid_arcs"] = [2, 9, 9]
        self.assertEqual(self.report(model)["projections"][0]["projected_allowed"], False)
        model["queries"][0]["operation"] = "write"
        self.assertEqual(self.report(model)["projections"][0]["projected_allowed"], False)
        model["queries"][0]["declared_allowed"] = False
        self.assertEqual(self.report(model)["projections"][0]["issues"], [])

    def test_incomplete_declarations_withhold_every_projection(self) -> None:
        for field in ("views_complete", "bindings_complete", "queries_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                document = self.report(model)
                self.assertEqual(
                    document["summary"],
                    {
                        "query_count": 2,
                        "candidate_count": 0,
                        "unknown_count": 2,
                    },
                )
                self.assertTrue(
                    all(row["projected_allowed"] is None for row in document["projections"])
                )
                self.assertTrue(all(not row["issues"] for row in document["projections"]))

    def test_closed_model_rejects_ambiguous_views_secrets_and_endpoints(self) -> None:
        cases = []
        duplicate_prefix = copy.deepcopy(self.model)
        duplicate_prefix["views"][0]["rules"].append({"prefix_arcs": [1, 3, 6], "included": False})
        cases.append(duplicate_prefix)
        duplicate_binding = copy.deepcopy(self.model)
        duplicate_binding["bindings"].append(duplicate_binding["bindings"][0])
        cases.append(duplicate_binding)
        bad_reference = copy.deepcopy(self.model)
        bad_reference["bindings"][0]["view_id"] = "synthetic:missing"
        cases.append(bad_reference)
        live_name = copy.deepcopy(self.model)
        live_name["bindings"][0]["principal_id"] = "actual-user"
        cases.append(live_name)
        endpoint = copy.deepcopy(self.model)
        endpoint["device_address"] = "192.0.2.1"
        cases.append(endpoint)
        secret = copy.deepcopy(self.model)
        secret["bindings"][0]["community"] = "forbidden"
        cases.append(secret)
        invalid_oid = copy.deepcopy(self.model)
        invalid_oid["queries"][0]["oid_arcs"] = [1, True]
        cases.append(invalid_oid)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(snmp.SnmpViewProjectionError):
                    snmp.analyze_supplied_snmp_view(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = snmp.analyze_supplied_snmp_view(self.model)
        changed = copy.deepcopy(self.model)
        changed["queries"][1]["declared_allowed"] = False
        with self.assertRaises(snmp.SnmpViewProjectionError):
            snmp.verify_supplied_snmp_view(report, model=changed)
        with self.assertRaises(snmp.SnmpViewProjectionError):
            snmp.verify_supplied_snmp_view_bytes(
                report.to_json().encode("ascii"),
                model=changed,
            )
        with self.assertRaises(snmp.SnmpViewProjectionError):
            snmp.SnmpViewProjectionReport({})
        with self.assertRaises(snmp.SnmpViewProjectionError):
            snmp.verify_supplied_snmp_view(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
