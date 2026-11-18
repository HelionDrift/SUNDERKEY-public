"""Bounded supplied digest vector consistency checks."""

from __future__ import annotations

import copy
import hashlib
import unittest

from sunderkey.offline_digest_vector_consistency import (
    DigestVectorConsistencyError,
    DigestVectorConsistencyReport,
    analyze_supplied_digest_vectors,
    component_fixture,
    verify_supplied_digest_vectors,
)


class DigestVectorConsistencyTests(unittest.TestCase):
    def test_reference_comparison_is_not_implementation_verification(self) -> None:
        report = analyze_supplied_digest_vectors(component_fixture()).to_dict()
        self.assertEqual(report["supplied_vector_count"], 2)
        self.assertEqual(report["mismatch_vector_ids"], [])
        self.assertFalse(report["implementation_verified"])
        self.assertFalse(report["claimed_implementation_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)
        self.assertNotIn("input_hex", report["vector_projections"][0])
        self.assertNotIn("claimed_digest_hex", report["vector_projections"][0])

    def test_sha512_reference_and_bounded_input(self) -> None:
        model = component_fixture()
        model["vectors"] = [{
            "vector_id": "abc-sha512",
            "algorithm": "sha512",
            "input_hex": "616263",
            "claimed_digest_hex": hashlib.sha512(b"abc").hexdigest(),
        }]
        report = analyze_supplied_digest_vectors(model).to_dict()
        self.assertTrue(report["vector_projections"][0]["matches_reference_digest"])
        model["vectors"][0]["input_hex"] = "00" * 257
        with self.assertRaises(ValueError):
            analyze_supplied_digest_vectors(model)

    def test_mismatch_is_only_a_supplied_output_difference(self) -> None:
        model = component_fixture()
        model["vectors"][0]["claimed_digest_hex"] = "0" * 64
        report = analyze_supplied_digest_vectors(model).to_dict()
        self.assertEqual(report["mismatch_vector_ids"], ["empty-sha256"])
        self.assertFalse(report["implementation_verified"])
        self.assertFalse(report["finding_claimed"])

    def test_rejects_non_synthetic_duplicate_and_malformed_vectors(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(DigestVectorConsistencyError):
            analyze_supplied_digest_vectors(model)
        model = component_fixture()
        model["vectors"][1]["vector_id"] = model["vectors"][0]["vector_id"]
        with self.assertRaises(DigestVectorConsistencyError):
            analyze_supplied_digest_vectors(model)
        model = component_fixture()
        model["vectors"][0]["input_hex"] = "0"
        with self.assertRaises(DigestVectorConsistencyError):
            analyze_supplied_digest_vectors(model)
        model = component_fixture()
        model["vectors"][0]["claimed_digest_hex"] = "00"
        with self.assertRaises(DigestVectorConsistencyError):
            analyze_supplied_digest_vectors(model)
        model = component_fixture()
        model["vectors"][0]["algorithm"] = "md5"
        with self.assertRaises(ValueError):
            analyze_supplied_digest_vectors(model)

    def test_incomplete_inventory_and_original_model_replay(self) -> None:
        model = component_fixture()
        model["vector_inventory_complete"] = False
        report = analyze_supplied_digest_vectors(model)
        self.assertEqual(report.to_dict()["disposition"], "unknown")
        self.assertEqual(
            verify_supplied_digest_vectors(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["vectors"][0]["claimed_digest_hex"] = "0" * 64
        with self.assertRaises(DigestVectorConsistencyError):
            verify_supplied_digest_vectors(report, model=changed)
        with self.assertRaises(DigestVectorConsistencyError):
            DigestVectorConsistencyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
