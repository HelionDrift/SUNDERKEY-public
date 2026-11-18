"""Source-replayed tests for synthetic certificate-auth metadata."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_certificate_auth_metadata as cert_auth


class CertificateAuthMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = cert_auth.component_fixture()

    def projection(self, model: dict, index: int = 1) -> dict:
        return cert_auth.analyze_supplied_certificate_auth_metadata(model).to_dict()[
            "projections"
        ][index]

    def test_revocation_is_only_a_declared_candidate(self) -> None:
        original = copy.deepcopy(self.model)
        report = cert_auth.analyze_supplied_certificate_auth_metadata(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S07")
        self.assertEqual(document["summary"], {
            "observation_count": 2, "candidate_count": 1, "unknown_count": 1,
        })
        before, after = document["projections"]
        self.assertEqual(before["projected_decision"], "unknown")
        self.assertEqual(before["basis"], "no_signature_or_chain_validation")
        self.assertEqual(after["projected_decision"], "deny")
        self.assertEqual(after["basis"], "after_declared_revocation")
        self.assertEqual(after["assessment"], "candidate_declared_certificate_auth_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "certificate_metadata_authenticated",
            "issuer_trust_authenticated", "reported_outcomes_authenticated",
            "signature_or_chain_validated", "revocation_service_contacted",
            "effective_certificate_access_observed", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            cert_auth.verify_supplied_certificate_auth_metadata(
                report, model=original,
            ).to_dict(),
            document,
        )
        self.assertEqual(
            cert_auth.verify_supplied_certificate_auth_metadata_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_negative_subject_usage_validity_and_issuer_invariants(self) -> None:
        cases = (
            (lambda m: m["observations"][0].update(
                expected_subject_id="synthetic:other-service"
            ), "declared_subject_mismatch"),
            (lambda m: m["certificates"][0].update(client_auth_declared=False),
             "client_auth_usage_absent"),
            (lambda m: m["observations"][0].update(at_tick=9),
             "outside_declared_validity"),
            (lambda m: m["observations"][0].update(at_tick=50),
             "outside_declared_validity"),
            (lambda m: m["trusted_issuers"].clear(),
             "issuer_absent_from_complete_trust_set"),
            (lambda m: m["certificates"].clear(),
             "certificate_absent_from_complete_inventory"),
        )
        for mutate, basis in cases:
            model = copy.deepcopy(self.model)
            mutate(model)
            with self.subTest(basis=basis):
                self.assertEqual(self.projection(model, 0)["basis"], basis)

    def test_incomplete_inventories_or_policy_preserve_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["trusted_issuers"].clear()
        model["issuers_complete"] = False
        self.assertEqual(self.projection(model, 0)["basis"], "issuer_trust_set_incomplete")
        model = copy.deepcopy(self.model)
        model["certificates"].clear()
        model["certificates_complete"] = False
        self.assertEqual(self.projection(model, 0)["basis"], "certificate_inventory_incomplete")
        for field in ("policy_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.projection(model)["basis"], "incomplete_policy_or_order")

    def test_reported_denial_is_only_consistency(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][1]["reported_outcome"] = "rejected"
        self.assertEqual(self.projection(model)["assessment"], "declared_rejection_consistent")

    def test_closed_model_rejects_certificate_material_and_bad_metadata(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["certificates"][0]["pem"] = "not-allowed"
        cases.append(extra)
        real_id = copy.deepcopy(self.model)
        real_id["certificates"][0]["certificate_id"] = "real-serial-123"
        cases.append(real_id)
        duplicate = copy.deepcopy(self.model)
        duplicate["trusted_issuers"].append("synthetic:issuer-one")
        cases.append(duplicate)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["observations"][0]["at_tick"] = True
        cases.append(bool_tick)
        premature = copy.deepcopy(self.model)
        premature["certificates"][0]["revoked_at"] = 9
        cases.append(premature)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(cert_auth.CertificateAuthMetadataError):
                    cert_auth.analyze_supplied_certificate_auth_metadata(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = cert_auth.analyze_supplied_certificate_auth_metadata(self.model)
        changed = copy.deepcopy(self.model)
        changed["trusted_issuers"].clear()
        with self.assertRaises(cert_auth.CertificateAuthMetadataError):
            cert_auth.verify_supplied_certificate_auth_metadata(report, model=changed)
        with self.assertRaises(cert_auth.CertificateAuthMetadataError):
            cert_auth.verify_supplied_certificate_auth_metadata_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(cert_auth.CertificateAuthMetadataError):
            cert_auth.CertificateAuthMetadataReport({})
        with self.assertRaises(cert_auth.CertificateAuthMetadataError):
            cert_auth.verify_supplied_certificate_auth_metadata(
                report.to_dict(), model=self.model,
            )


if __name__ == "__main__":
    unittest.main()
