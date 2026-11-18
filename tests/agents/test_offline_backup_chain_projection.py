"""Supplied backup chains never become claims of actual recoverability."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_backup_chain_projection import (
    BackupChainProjection,
    BackupChainProjectionError,
    analyze_supplied_backup_chain,
    verify_supplied_backup_chain,
)


def model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-backup-chain-v1",
        "dataset_ref": "dataset:sha256:" + "a" * 64,
        "as_of_tick": 100,
        "history_complete": False,
        "snapshots": [
            {
                "snapshot_id": "full",
                "recorded_tick": 20,
                "expires_tick": 120,
                "parent_snapshot_id": None,
                "declared_restorable": True,
            },
            {
                "snapshot_id": "incremental",
                "recorded_tick": 70,
                "expires_tick": 110,
                "parent_snapshot_id": "full",
                "declared_restorable": True,
            },
            {
                "snapshot_id": "expired",
                "recorded_tick": 80,
                "expires_tick": 90,
                "parent_snapshot_id": "full",
                "declared_restorable": True,
            },
        ],
        "objectives": [
            {"target_tick": 75, "maximum_lag_ticks": 10},
            {"target_tick": 95, "maximum_lag_ticks": 10},
            {"target_tick": 10, "maximum_lag_ticks": 5},
        ],
    }


class BackupChainProjectionTests(unittest.TestCase):
    def test_restorable_supplied_chain_expiry_and_unknown_history(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_backup_chain(source)
        rows = report.to_dict()["objectives"]
        self.assertEqual(source, original)
        self.assertEqual(rows[0]["selected_snapshot_id"], "incremental")
        self.assertEqual(rows[0]["declared_chain_ids"], ["full", "incremental"])
        self.assertEqual(rows[0]["lag_ticks"], 5)
        self.assertEqual(rows[0]["disposition"], "within_supplied_lag")
        self.assertEqual(rows[1]["selected_snapshot_id"], "incremental")
        self.assertEqual(rows[1]["disposition"], "exceeds_supplied_lag")
        self.assertEqual(rows[2]["disposition"], "unknown_incomplete_history")
        self.assertFalse(report.to_dict()["flags"]["recoverability_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_backup_chain(report, model=source).to_json(), report.to_json()
        )
        source["history_complete"] = True
        self.assertEqual(
            analyze_supplied_backup_chain(source).to_dict()["objectives"][2]["disposition"],
            "no_supplied_chain",
        )

    def test_missing_older_parent_bad_time_and_duplicate_objective_refused(self) -> None:
        source = model()
        source["snapshots"][1]["parent_snapshot_id"] = "missing"
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)
        source = model()
        source["snapshots"][0]["parent_snapshot_id"] = "incremental"
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)
        source = model()
        source["objectives"][1]["target_tick"] = 75
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)

    def test_invalid_types_tamper_and_replay_drift_refused(self) -> None:
        source = model()
        source["snapshots"][0]["declared_restorable"] = 1
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)
        source = model()
        source["dataset_ref"] = "real-dataset"
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)
        source = model()
        source["snapshots"][0]["expires_tick"] = object()
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)
        source = model()
        report = analyze_supplied_backup_chain(source)
        tampered = report.to_dict()
        tampered["flags"]["recoverability_proven"] = True
        with self.assertRaises(BackupChainProjectionError):
            BackupChainProjection(tampered)
        source["snapshots"][1]["expires_tick"] = 99
        with self.assertRaises(BackupChainProjectionError):
            verify_supplied_backup_chain(report, model=source)

    def test_declared_ceiling_is_bounded(self) -> None:
        source = model()
        source["snapshots"] = [
            {
                "snapshot_id": f"s{index}",
                "recorded_tick": index,
                "expires_tick": 1000,
                "parent_snapshot_id": None if index == 0 else f"s{index - 1}",
                "declared_restorable": True,
            }
            for index in range(256)
        ]
        source["as_of_tick"] = 500
        source["objectives"] = [{"target_tick": 255, "maximum_lag_ticks": 0}]
        report = analyze_supplied_backup_chain(source)
        self.assertEqual(len(report.to_dict()["objectives"][0]["declared_chain_ids"]), 256)
        self.assertLessEqual(len(report.to_json()), 524_288)
        source["snapshots"].append(copy.deepcopy(source["snapshots"][0]))
        with self.assertRaises(BackupChainProjectionError):
            analyze_supplied_backup_chain(source)


if __name__ == "__main__":
    unittest.main()
