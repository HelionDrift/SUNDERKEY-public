"""Separate-source replay tests for synthetic nonce-label reuse."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_symmetric_nonce_reuse as nonce


class SymmetricNonceReuseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = nonce.component_fixture()

    def report(self, model: dict) -> dict:
        return nonce.analyze_supplied_symmetric_nonce_reuse(model).to_dict()

    def test_declared_reuse_is_nonqualifying_and_source_replayed(self) -> None:
        original = copy.deepcopy(self.model)
        report = nonce.analyze_supplied_symmetric_nonce_reuse(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GE-D22-S05")
        self.assertEqual(document["summary"], {
            "record_count": 3, "candidate_count": 1, "unknown_count": 0,
        })
        self.assertEqual(document["projections"][1]["disposition"],
                         "not_assessed_decryption")
        self.assertEqual(document["projections"][2]["disposition"],
                         "candidate_declared_nonce_reuse")
        self.assertEqual(document["projections"][2]["prior_encryption_record_id"],
                         "synthetic:encrypt-one")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated", "key_identity_verified",
            "nonce_value_verified", "operation_observed", "key_or_ciphertext_processed",
            "encryption_performed", "cryptographic_break_proven", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            nonce.verify_supplied_symmetric_nonce_reuse(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            nonce.verify_supplied_symmetric_nonce_reuse_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_different_key_or_mode_does_not_match_declared_pair(self) -> None:
        for field, value in (("key_id", "synthetic:key-two"), ("mode", "aes_ctr")):
            model = copy.deepcopy(self.model)
            model["records"][2][field] = value
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["projections"][2]["disposition"],
                                 "no_declared_nonce_reuse_conflict")

    def test_decryption_does_not_consume_encryption_nonce_slot(self) -> None:
        model = copy.deepcopy(self.model)
        model["records"][0]["operation"] = "decrypt"
        self.assertEqual(self.report(model)["summary"]["candidate_count"], 0)

    def test_incomplete_policy_records_or_order_suppresses_candidates(self) -> None:
        for field in ("policy_complete", "records_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["summary"]["unknown_count"], 3)

    def test_closed_model_rejects_key_material_and_real_identifiers(self) -> None:
        cases = []
        key = copy.deepcopy(self.model)
        key["records"][0]["key_bytes"] = "forbidden"
        cases.append(key)
        real = copy.deepcopy(self.model)
        real["records"][0]["key_id"] = "live-key"
        cases.append(real)
        duplicate = copy.deepcopy(self.model)
        duplicate["records"][1]["record_id"] = "synthetic:encrypt-one"
        cases.append(duplicate)
        invalid = copy.deepcopy(self.model)
        invalid["records"][0]["operation"] = "sign"
        cases.append(invalid)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(nonce.SymmetricNonceReuseError):
                    nonce.analyze_supplied_symmetric_nonce_reuse(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = nonce.analyze_supplied_symmetric_nonce_reuse(self.model)
        changed = copy.deepcopy(self.model)
        changed["records"][2]["key_id"] = "synthetic:key-two"
        with self.assertRaises(nonce.SymmetricNonceReuseError):
            nonce.verify_supplied_symmetric_nonce_reuse(report, model=changed)
        with self.assertRaises(nonce.SymmetricNonceReuseError):
            nonce.verify_supplied_symmetric_nonce_reuse_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(nonce.SymmetricNonceReuseError):
            nonce.SymmetricNonceReuseReport({})
        with self.assertRaises(nonce.SymmetricNonceReuseError):
            nonce.verify_supplied_symmetric_nonce_reuse(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
