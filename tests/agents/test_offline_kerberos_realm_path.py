"""Source-replayed tests for synthetic Kerberos realm-path metadata."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_kerberos_realm_path as kerberos


class KerberosRealmPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = kerberos.component_fixture()

    def projection(self, model: dict) -> dict:
        return kerberos.analyze_supplied_kerberos_realm_path(model).to_dict()["projections"][0]

    def test_untrusted_transit_is_only_a_declared_candidate(self) -> None:
        original = copy.deepcopy(self.model)
        report = kerberos.analyze_supplied_kerberos_realm_path(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S06")
        self.assertEqual(document["summary"], {
            "observation_count": 1, "candidate_count": 1, "unknown_count": 0,
        })
        row = document["projections"][0]
        self.assertEqual(row["projected_decision"], "deny")
        self.assertEqual(row["basis"], "untrusted_declared_realm_path")
        self.assertEqual(row["assessment"], "candidate_declared_realm_path_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "realm_policy_authenticated",
            "ticket_metadata_authenticated", "reported_outcomes_authenticated",
            "ticket_crypto_validated", "service_authorization_validated",
            "effective_authentication_observed", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            kerberos.verify_supplied_kerberos_realm_path(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            kerberos.verify_supplied_kerberos_realm_path_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_trusted_path_never_proves_authentication_or_authorization(self) -> None:
        model = copy.deepcopy(self.model)
        model["trusted_realms"].append("synthetic:transit-realm")
        row = self.projection(model)
        self.assertEqual(row["projected_decision"], "unknown")
        self.assertEqual(row["basis"], "no_ticket_or_service_validation")

    def test_negative_service_and_time_invariants(self) -> None:
        cases = (
            (lambda m: m["observations"][0].update(
                expected_service_realm="synthetic:other-realm"
            ), "declared_service_realm_mismatch"),
            (lambda m: m["observations"][0].update(
                expected_service_id="synthetic:other-service"
            ), "declared_service_id_mismatch"),
            (lambda m: m["observations"][0].update(at_tick=9),
             "outside_declared_ticket_window"),
            (lambda m: m["observations"][0].update(at_tick=40),
             "outside_declared_ticket_window"),
            (lambda m: m["tickets"].clear(), "ticket_absent_from_complete_inventory"),
        )
        for mutate, basis in cases:
            model = copy.deepcopy(self.model)
            mutate(model)
            with self.subTest(basis=basis):
                self.assertEqual(self.projection(model)["basis"], basis)

    def test_incomplete_policy_preserves_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["realms_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "realm_policy_incomplete")
        model = copy.deepcopy(self.model)
        model["tickets"].clear()
        model["tickets_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "ticket_inventory_incomplete")
        for field in ("policy_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.projection(model)["basis"], "incomplete_policy_or_order")

    def test_closed_model_rejects_ticket_bytes_and_bad_metadata(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["tickets"][0]["ticket_bytes"] = "forbidden"
        cases.append(extra)
        real_id = copy.deepcopy(self.model)
        real_id["tickets"][0]["ticket_id"] = "krbtgt/REALM"
        cases.append(real_id)
        duplicate = copy.deepcopy(self.model)
        duplicate["tickets"][0]["transited_realms"].append("synthetic:transit-realm")
        cases.append(duplicate)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["observations"][0]["at_tick"] = True
        cases.append(bool_tick)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(kerberos.KerberosRealmPathError):
                    kerberos.analyze_supplied_kerberos_realm_path(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = kerberos.analyze_supplied_kerberos_realm_path(self.model)
        changed = copy.deepcopy(self.model)
        changed["trusted_realms"].append("synthetic:transit-realm")
        with self.assertRaises(kerberos.KerberosRealmPathError):
            kerberos.verify_supplied_kerberos_realm_path(report, model=changed)
        with self.assertRaises(kerberos.KerberosRealmPathError):
            kerberos.verify_supplied_kerberos_realm_path_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(kerberos.KerberosRealmPathError):
            kerberos.KerberosRealmPathReport({})
        with self.assertRaises(kerberos.KerberosRealmPathError):
            kerberos.verify_supplied_kerberos_realm_path(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
