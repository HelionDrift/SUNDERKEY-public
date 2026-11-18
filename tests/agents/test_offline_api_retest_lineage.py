"""Synthetic API retest source and world lineage composition."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.run_offline_api_assessment import _native_adapter, _prepare_case, run_case
from sunderkey.offline_api_assessment import OfflineApiCaseSource, build_offline_api_batch
from sunderkey.offline_api_retest_lineage import (
    OfflineApiRetestLineageError,
    append_offline_api_retest_lineage,
    build_initial_offline_api_retest_lineage,
    verify_offline_api_retest_lineage,
)
from sunderkey.offline_api_world_projection import build_offline_api_world_projection

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "offline-api-assessment"
EXPIRES = "2026-09-25T12:00:00Z"


class OfflineApiRetestLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()
        values = []
        for name in (
            "corroborated-synthetic-case.json",
            "denied-synthetic-retest-case.json",
        ):
            raw = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
            case_id, invocation, evidence = _prepare_case(raw, cls.adapter)
            source = OfflineApiCaseSource(case_id, invocation, evidence, run_case(raw))
            batch = build_offline_api_batch(adapter=cls.adapter, sources=(source,)).to_dict()
            values.append((source, batch))
        cls.values = tuple(values)

    def options(self, index: int) -> dict:
        source, batch = self.values[index]
        observed_at = f"2026-09-24T12:0{index}:00Z"
        projection = build_offline_api_world_projection(
            adapter=self.adapter,
            sources=(source,),
            batch=batch,
            observed_at=observed_at,
            expires_at=EXPIRES,
        )
        return {
            "adapter": self.adapter,
            "sources": (source,),
            "batch": batch,
            "projection": projection,
            "observed_at": observed_at,
            "expires_at": EXPIRES,
        }

    def test_positive_to_negative_retest_is_one_custody_bound_child(self) -> None:
        first = build_initial_offline_api_retest_lineage(**self.options(0))
        child = append_offline_api_retest_lineage(prior=first, **self.options(1))
        self.assertEqual(child, verify_offline_api_retest_lineage(child, prior=first))
        self.assertEqual(child["step_index"], 2)
        self.assertEqual(child["parent_lineage_sha256"], first["lineage_sha256"])
        self.assertEqual(
            child["world_snapshot"]["parent_sha256"],
            first["world_snapshot"]["snapshot_sha256"],
        )
        self.assertEqual(len(child["world_snapshot"]["conflicts"]), 1)
        self.assertEqual(child["effects"]["execution"], "none")
        self.assertEqual(child["world_state"], "hypothesis_only")

    def test_prior_batch_replay_and_lineage_tamper_fail(self) -> None:
        first = build_initial_offline_api_retest_lineage(**self.options(0))
        with self.assertRaisesRegex(OfflineApiRetestLineageError, "retest sources"):
            append_offline_api_retest_lineage(prior=first, **self.options(0))
        child = append_offline_api_retest_lineage(prior=first, **self.options(1))
        changed = copy.deepcopy(child)
        changed["parent_lineage_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(OfflineApiRetestLineageError, "does not extend"):
            verify_offline_api_retest_lineage(changed, prior=first)
        changed = copy.deepcopy(child)
        changed["world_snapshot"]["edges"] = []
        with self.assertRaises(OfflineApiRetestLineageError):
            verify_offline_api_retest_lineage(changed, prior=first)


if __name__ == "__main__":
    unittest.main()
