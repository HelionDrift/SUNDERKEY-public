"""Original-source replay tests for synthetic biometric assurance declarations."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_biometric_assurance_projection as biometric


class BiometricAssuranceProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = biometric.component_fixture()

    def report(self, model: dict) -> dict:
        return biometric.analyze_supplied_biometric_assurance(model).to_dict()

    def test_declared_assurance_conflicts_are_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = biometric.analyze_supplied_biometric_assurance(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S17")
        self.assertEqual(document["summary"], {
            "record_count": 2, "candidate_count": 1, "unknown_count": 0,
        })
        self.assertEqual(document["projections"][0]["disposition"], "no_declared_conflict")
        self.assertEqual(document["projections"][1]["candidate_flags"], [
            "candidate_acceptance_without_declared_liveness",
            "candidate_acceptance_without_declared_device_binding",
            "candidate_acceptance_with_reused_nonce_label",
        ])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated", "biometric_material_processed",
            "liveness_verified", "device_attestation_verified", "nonce_freshness_verified",
            "authentication_attempt_performed", "presentation_attack_proven",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            biometric.verify_supplied_biometric_assurance(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            biometric.verify_supplied_biometric_assurance_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_rejected_record_does_not_create_acceptance_conflict(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][1]["reported_outcome"] = "rejected"
        self.assertEqual(self.report(model)["projections"][1]["candidate_flags"], [])

    def test_unknown_required_signal_suppresses_candidate(self) -> None:
        for field in ("declared_liveness", "declared_device_binding"):
            model = copy.deepcopy(self.model)
            model["records"][1][field] = "unknown"
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["projections"][1]["disposition"], "unknown")

    def test_incomplete_declarations_preserve_unknown(self) -> None:
        for field in ("policy_complete", "records_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                report = self.report(model)
                self.assertEqual(report["summary"]["candidate_count"], 0)
                self.assertEqual(report["summary"]["unknown_count"], 2)

    def test_nonce_reuse_is_based_on_supplied_label_only(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][1]["declared_liveness"] = "yes"
        model["records"][1]["declared_device_binding"] = "yes"
        self.assertEqual(self.report(model)["projections"][1]["candidate_flags"], [
            "candidate_acceptance_with_reused_nonce_label",
        ])

    def test_closed_model_refuses_material_real_identifiers_and_duplicates(self) -> None:
        cases = []
        material = copy.deepcopy(self.model)
        material["records"][0]["image"] = "forbidden"
        cases.append(material)
        real = copy.deepcopy(self.model)
        real["records"][0]["nonce_id"] = "real-nonce"
        cases.append(real)
        duplicate = copy.deepcopy(self.model)
        duplicate["records"][1]["record_id"] = "synthetic:first"
        cases.append(duplicate)
        invalid = copy.deepcopy(self.model)
        invalid["records"][0]["declared_liveness"] = True
        cases.append(invalid)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(biometric.BiometricAssuranceProjectionError):
                    biometric.analyze_supplied_biometric_assurance(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = biometric.analyze_supplied_biometric_assurance(self.model)
        changed = copy.deepcopy(self.model)
        changed["records"][1]["reported_outcome"] = "rejected"
        with self.assertRaises(biometric.BiometricAssuranceProjectionError):
            biometric.verify_supplied_biometric_assurance(report, model=changed)
        with self.assertRaises(biometric.BiometricAssuranceProjectionError):
            biometric.verify_supplied_biometric_assurance_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(biometric.BiometricAssuranceProjectionError):
            biometric.BiometricAssuranceProjectionReport({})
        with self.assertRaises(biometric.BiometricAssuranceProjectionError):
            biometric.verify_supplied_biometric_assurance(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
