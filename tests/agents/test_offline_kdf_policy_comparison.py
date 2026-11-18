"""Original-source replay tests for a synthetic KDF policy comparison."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_kdf_policy_comparison as kdf


class KdfPolicyComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = kdf.component_fixture()

    def report(self, model: dict) -> dict:
        return kdf.analyze_supplied_kdf_policy(model).to_dict()

    def test_declared_parameter_mismatch_is_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = kdf.analyze_supplied_kdf_policy(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GE-D22-S04")
        self.assertEqual(document["summary"], {
            "record_count": 1, "candidate_count": 1, "unknown_count": 0,
        })
        self.assertEqual(document["projections"][0]["candidate_flags"], [
            "candidate_memory_kib_below_supplied_minimum",
        ])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated", "deployed_configuration_observed",
            "password_or_hash_processed", "kdf_invoked", "cryptographic_strength_proven",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(kdf.verify_supplied_kdf_policy(report, model=original).to_dict(),
                         document)
        self.assertEqual(
            kdf.verify_supplied_kdf_policy_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_meeting_supplied_minima_does_not_prove_strength(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][0]["parameters"]["memory_kib"] = 65536
        report = self.report(model)
        self.assertEqual(report["projections"][0]["disposition"],
                         "no_declared_policy_mismatch")
        self.assertFalse(report["cryptographic_strength_proven"])

    def test_unlisted_active_algorithm_is_declared_mismatch(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][0]["algorithm"] = "pbkdf2_sha256"
        model["records"][0]["parameters"] = {"iterations": 1000}
        self.assertEqual(self.report(model)["projections"][0]["candidate_flags"], [
            "candidate_algorithm_absent_from_supplied_policy",
        ])

    def test_retired_and_incomplete_records_do_not_create_candidates(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][0]["active"] = False
        self.assertEqual(self.report(model)["projections"][0]["disposition"],
                         "not_assessed_retired")
        for field in ("policy_complete", "records_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["projections"][0]["disposition"],
                                 "unknown_incomplete_declarations")

    def test_algorithm_specific_parameter_shapes_are_closed(self) -> None:
        cases = []
        wrong = copy.deepcopy(self.model)
        wrong["records"][0]["parameters"]["password"] = "forbidden"
        cases.append(wrong)
        invalid_scrypt = copy.deepcopy(self.model)
        invalid_scrypt["records"][0]["algorithm"] = "scrypt"
        invalid_scrypt["records"][0]["parameters"] = {
            "cost_n": 3, "block_size": 8, "parallelism": 1,
        }
        cases.append(invalid_scrypt)
        bool_number = copy.deepcopy(self.model)
        bool_number["records"][0]["salt_bytes"] = True
        cases.append(bool_number)
        duplicate = copy.deepcopy(self.model)
        duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
        cases.append(duplicate)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(kdf.KdfPolicyComparisonError):
                    kdf.analyze_supplied_kdf_policy(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = kdf.analyze_supplied_kdf_policy(self.model)
        changed = copy.deepcopy(self.model)
        changed["records"][0]["parameters"]["memory_kib"] = 65536
        with self.assertRaises(kdf.KdfPolicyComparisonError):
            kdf.verify_supplied_kdf_policy(report, model=changed)
        with self.assertRaises(kdf.KdfPolicyComparisonError):
            kdf.verify_supplied_kdf_policy_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(kdf.KdfPolicyComparisonError):
            kdf.KdfPolicyComparisonReport({})
        with self.assertRaises(kdf.KdfPolicyComparisonError):
            kdf.verify_supplied_kdf_policy(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
