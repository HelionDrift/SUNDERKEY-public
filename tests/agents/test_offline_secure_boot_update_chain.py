"""Bounded supplied Secure Boot and update-chain projection tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_secure_boot_update_chain import (
    SecureBootUpdateChainError,
    analyze_supplied_secure_boot_update_chain,
    component_fixture,
    verify_supplied_secure_boot_update_chain,
    verify_supplied_secure_boot_update_chain_bytes,
)


class SecureBootUpdateChainTests(unittest.TestCase):
    def test_below_floor_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_secure_boot_update_chain(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["update_observations"][0]["disposition"],
            "candidate_below_declared_rollback_floor",
        )
        self.assertFalse(body["platform_contacted"])
        self.assertFalse(body["signature_verified"])
        self.assertFalse(body["rollback_enforcement_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_secure_boot_update_chain(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_secure_boot_update_chain_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_declared_policy_and_chain_conflicts_are_candidates(self) -> None:
        model = component_fixture()
        model["reported_secure_boot_enabled"] = False
        model["boot_chain"][1]["predecessor_id"] = "wrong-artifact"
        model["proposed_updates"][0]["proposed_version"] = 9
        body = analyze_supplied_secure_boot_update_chain(model).to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["secure_boot_state_disposition"],
            "candidate_declared_policy_state_mismatch",
        )
        self.assertFalse(
            body["chain_observations"][1]["predecessor_consistent_with_supplied_order"]
        )
        self.assertEqual(
            body["chain_observations"][1]["validation_disposition"],
            "not_evaluated_for_loaded_secure_boot_image",
        )

    def test_loaded_rejected_and_unknown_validation_are_distinct(self) -> None:
        model = component_fixture()
        model["boot_chain"][0]["declared_validation"] = "rejected"
        model["boot_chain"][1]["declared_validation"] = "unknown"
        model["proposed_updates"][0]["proposed_version"] = 9
        body = analyze_supplied_secure_boot_update_chain(model).to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 1)
        self.assertEqual(
            body["chain_observations"][0]["validation_disposition"],
            "candidate_loaded_image_declared_rejected",
        )
        self.assertEqual(
            body["chain_observations"][1]["validation_disposition"],
            "unknown_loaded_image_validation",
        )

    def test_incomplete_chain_and_missing_target_remain_unknown(self) -> None:
        model = component_fixture()
        model["chain_complete"] = False
        model["proposed_updates"][0]["target_artifact_id"] = "omitted-artifact"
        body = analyze_supplied_secure_boot_update_chain(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 2)
        self.assertEqual(
            body["update_observations"][0]["disposition"],
            "unknown_target_not_in_supplied_chain",
        )

    def test_strict_closed_bounded_model(self) -> None:
        cases = []
        for field, invalid in (
            ("chain_complete", 1),
            ("reported_secure_boot_enabled", "true"),
        ):
            model = component_fixture()
            model[field] = invalid
            cases.append(model)
        model = component_fixture()
        model["boot_chain"][0]["declared_validation"] = "cryptographically_valid"
        cases.append(model)
        model = component_fixture()
        model["boot_chain"].append(copy.deepcopy(model["boot_chain"][0]))
        cases.append(model)
        model = component_fixture()
        model["proposed_updates"].append(copy.deepcopy(model["proposed_updates"][0]))
        cases.append(model)
        for field, invalid in (
            ("current_version", True),
            ("rollback_floor", -1),
            ("proposed_version", 1 << 32),
        ):
            model = component_fixture()
            model["proposed_updates"][0][field] = invalid
            cases.append(model)
        model = component_fixture()
        model["unexpected"] = "field"
        cases.append(model)
        model = component_fixture()
        model["boot_chain"] = []
        cases.append(model)
        model = component_fixture()
        model["proposed_updates"] = []
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_secure_boot_update_chain(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_secure_boot_update_chain(model)
        changed = copy.deepcopy(model)
        changed["proposed_updates"][0]["rollback_floor"] = 8
        with self.assertRaises(SecureBootUpdateChainError):
            verify_supplied_secure_boot_update_chain(report, model=changed)
        with self.assertRaises(SecureBootUpdateChainError):
            verify_supplied_secure_boot_update_chain(report.to_dict(), model=model)
        with self.assertRaises(SecureBootUpdateChainError):
            verify_supplied_secure_boot_update_chain_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_secure_boot_update_chain_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )


if __name__ == "__main__":
    unittest.main()
