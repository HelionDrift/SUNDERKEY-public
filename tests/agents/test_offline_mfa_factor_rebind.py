"""Original-source replay tests for a synthetic MFA factor-rebind timeline."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_mfa_factor_rebind as rebind


class MfaFactorRebindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = rebind.component_fixture()

    def report(self, model: dict) -> dict:
        return rebind.analyze_supplied_mfa_factor_rebind(model).to_dict()

    def test_declared_rebind_and_revoked_use_are_only_candidates(self) -> None:
        original = copy.deepcopy(self.model)
        report = rebind.analyze_supplied_mfa_factor_rebind(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S02")
        self.assertEqual(document["summary"], {
            "event_count": 4, "candidate_count": 2, "unknown_count": 0,
        })
        self.assertEqual(document["projections"][1]["candidate_flags"], [
            "candidate_binding_without_declared_approval",
        ])
        self.assertEqual(document["projections"][3]["candidate_flags"], [
            "candidate_acceptance_without_declared_enrollment",
        ])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated", "factor_possession_proven",
            "recovery_approval_authenticated", "factor_enrollment_observed",
            "authentication_attempt_performed", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            rebind.verify_supplied_mfa_factor_rebind(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            rebind.verify_supplied_mfa_factor_rebind_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_declared_approval_for_same_factor_resolves_binding_flag(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"].insert(1, {
            "event_id": "synthetic:approved", "factor_id": "synthetic:factor-new",
            "at_tick": 1, "event_type": "recovery_approved", "reported_outcome": "none",
        })
        model["events"][0]["at_tick"] = 0
        document = self.report(model)
        self.assertEqual(document["projections"][2]["candidate_flags"], [])
        self.assertEqual(document["summary"]["candidate_count"], 1)

    def test_unrelated_approval_does_not_clear_rebind_flag(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"].insert(1, {
            "event_id": "synthetic:approved-other", "factor_id": "synthetic:other",
            "at_tick": 1, "event_type": "recovery_approved", "reported_outcome": "none",
        })
        model["events"][0]["at_tick"] = 0
        self.assertEqual(self.report(model)["projections"][2]["candidate_flags"], [
            "candidate_binding_without_declared_approval",
        ])

    def test_incomplete_premises_suppress_all_candidates(self) -> None:
        for field in ("policy_complete", "events_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                report = self.report(model)
                self.assertEqual(report["summary"]["candidate_count"], 0)
                self.assertEqual(report["summary"]["unknown_count"], 4)

    def test_rejected_use_is_not_claimed_as_positive_or_negative_proof(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"][3]["reported_outcome"] = "rejected"
        self.assertEqual(self.report(model)["projections"][3]["candidate_flags"], [])

    def test_closed_model_rejects_secrets_real_ids_and_invalid_order(self) -> None:
        cases = []
        secret = copy.deepcopy(self.model)
        secret["events"][0]["otp"] = "forbidden"
        cases.append(secret)
        real = copy.deepcopy(self.model)
        real["account_id"] = "real@example.com"
        cases.append(real)
        duplicate = copy.deepcopy(self.model)
        duplicate["events"][1]["event_id"] = "synthetic:use-old"
        cases.append(duplicate)
        unordered = copy.deepcopy(self.model)
        unordered["events"][1]["at_tick"] = 1
        cases.append(unordered)
        invalid = copy.deepcopy(self.model)
        invalid["events"][0]["reported_outcome"] = "none"
        cases.append(invalid)
        boolean_tick = copy.deepcopy(self.model)
        boolean_tick["events"][0]["at_tick"] = True
        cases.append(boolean_tick)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(rebind.MfaFactorRebindError):
                    rebind.analyze_supplied_mfa_factor_rebind(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = rebind.analyze_supplied_mfa_factor_rebind(self.model)
        changed = copy.deepcopy(self.model)
        changed["events"][3]["reported_outcome"] = "rejected"
        with self.assertRaises(rebind.MfaFactorRebindError):
            rebind.verify_supplied_mfa_factor_rebind(report, model=changed)
        with self.assertRaises(rebind.MfaFactorRebindError):
            rebind.verify_supplied_mfa_factor_rebind_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(rebind.MfaFactorRebindError):
            rebind.MfaFactorRebindReport({})
        with self.assertRaises(rebind.MfaFactorRebindError):
            rebind.verify_supplied_mfa_factor_rebind(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()
