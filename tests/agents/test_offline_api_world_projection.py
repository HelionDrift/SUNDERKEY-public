"""Synthetic API outcomes projected to hypothesis-only attack paths."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.run_offline_api_assessment import _native_adapter, _prepare_case, run_case
from sunderkey.attack_world_model import AttackWorldSnapshot, query_candidate_attack_paths
from sunderkey.offline_api_assessment import OfflineApiCaseSource, build_offline_api_batch
from sunderkey.offline_api_world_projection import (
    OfflineApiWorldProjectionError,
    append_offline_api_world_projection,
    build_offline_api_world_projection,
    verify_offline_api_world_projection,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "offline-api-assessment"
OBSERVED = "2026-09-24T12:00:00Z"
EXPIRES = "2026-09-25T12:00:00Z"


class OfflineApiWorldProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()
        sources = []
        for name in (
            "corroborated-synthetic-case.json",
            "denied-synthetic-retest-case.json",
        ):
            raw = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
            result = run_case(raw)
            case_id, invocation, evidence = _prepare_case(raw, cls.adapter)
            sources.append(OfflineApiCaseSource(case_id, invocation, evidence, result))
        cls.sources = tuple(sources)
        cls.batch = build_offline_api_batch(adapter=cls.adapter, sources=cls.sources).to_dict()

    def options(self) -> dict:
        return {
            "adapter": self.adapter,
            "sources": self.sources,
            "batch": self.batch,
            "observed_at": OBSERVED,
            "expires_at": EXPIRES,
        }

    def test_mixed_synthetic_observations_create_conflict_not_verified_path(self) -> None:
        options = self.options()
        projection = build_offline_api_world_projection(**options)
        self.assertEqual(
            projection,
            build_offline_api_world_projection(**{**options, "sources": self.sources[::-1]}),
        )
        snapshot = AttackWorldSnapshot.from_dict(projection["snapshot"])
        self.assertEqual(len(snapshot.nodes), 2)
        self.assertEqual(len(snapshot.edges), 2)
        self.assertEqual(len(snapshot.conflicts), 1)
        self.assertEqual(
            {edge.evidence.verification_state.value for edge in snapshot.edges},
            {"hypothesis", "negative"},
        )
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=(
                next(
                    node.node_id for node in snapshot.nodes if node.node_kind.value == "principal"
                ),
            ),
            target_node_ids=(
                next(node.node_id for node in snapshot.nodes if node.node_kind.value == "asset"),
            ),
            as_of="2026-09-24T12:00:01Z",
        )
        self.assertFalse(result.verified_paths)
        self.assertFalse(result.hypothesis_paths)
        self.assertNotIn("principal.other", json.dumps(projection))
        self.assertNotIn("object.example.7", json.dumps(projection))
        self.assertEqual(
            verify_offline_api_world_projection(projection=projection, **options), projection
        )

    def test_positive_synthetic_case_is_hypothesis_only(self) -> None:
        source = self.sources[0]
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        projection = build_offline_api_world_projection(
            **{**self.options(), "sources": (source,), "batch": batch}
        )
        snapshot = AttackWorldSnapshot.from_dict(projection["snapshot"])
        start = next(node.node_id for node in snapshot.nodes if node.node_kind.value == "principal")
        target = next(node.node_id for node in snapshot.nodes if node.node_kind.value == "asset")
        paths = query_candidate_attack_paths(
            snapshot,
            start_node_ids=(start,),
            target_node_ids=(target,),
            as_of="2026-09-24T12:00:01Z",
        )
        self.assertEqual(len(paths.hypothesis_paths), 1)
        self.assertFalse(paths.verified_paths)
        self.assertEqual(paths.hypothesis_paths[0].confidence, 0.0)

    def test_review_required_case_is_skipped_and_tampering_fails(self) -> None:
        raw = json.loads(
            (EXAMPLES / "corroborated-synthetic-case.json").read_text(encoding="utf-8")
        )
        raw["responses"][1]["body"] = {"record": "different-synthetic-view"}
        result = run_case(raw)
        self.assertEqual(result["disposition"], "review_required")
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        source = OfflineApiCaseSource(case_id, invocation, evidence, result)
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        options = {**self.options(), "sources": (source,), "batch": batch}
        projection = build_offline_api_world_projection(**options)
        self.assertFalse(projection["snapshot"]["edges"])
        self.assertEqual(projection["skipped_case_ids"], [case_id])
        changed = copy.deepcopy(projection)
        changed["path_verification"] = "established"
        with self.assertRaisesRegex(OfflineApiWorldProjectionError, "does not match"):
            verify_offline_api_world_projection(projection=changed, **options)
        changed_batch = copy.deepcopy(batch)
        changed_batch["review_candidate_case_ids"] = []
        with self.assertRaisesRegex(OfflineApiWorldProjectionError, "batch"):
            build_offline_api_world_projection(**{**options, "batch": changed_batch})

    def test_retest_appends_child_facts_without_redefining_stable_nodes(self) -> None:
        positive = self.sources[0]
        negative = self.sources[1]
        positive_batch = build_offline_api_batch(
            adapter=self.adapter, sources=(positive,)
        ).to_dict()
        first = build_offline_api_world_projection(
            **{**self.options(), "sources": (positive,), "batch": positive_batch}
        )
        parent = AttackWorldSnapshot.from_dict(first["snapshot"])
        negative_batch = build_offline_api_batch(
            adapter=self.adapter, sources=(negative,)
        ).to_dict()
        later = "2026-09-24T12:01:00Z"
        retest = build_offline_api_world_projection(
            **{
                **self.options(),
                "sources": (negative,),
                "batch": negative_batch,
                "observed_at": later,
            }
        )
        options = {
            **self.options(),
            "parent_snapshot": parent,
            "projection": retest,
            "sources": (negative,),
            "batch": negative_batch,
            "observed_at": later,
        }
        child = append_offline_api_world_projection(**options)
        self.assertEqual(child.parent_sha256, parent.snapshot_sha256)
        self.assertEqual(len(child.nodes), len(parent.nodes))
        self.assertEqual(len(child.edges), 2)
        self.assertEqual(len(child.conflicts), 1)
        self.assertEqual(AttackWorldSnapshot.from_dict(child.to_dict()), child)
        with self.assertRaisesRegex(OfflineApiWorldProjectionError, "no new world facts"):
            append_offline_api_world_projection(
                **{
                    **self.options(),
                    "parent_snapshot": parent,
                    "projection": first,
                    "sources": (positive,),
                    "batch": positive_batch,
                }
            )
        raw = json.loads(
            (EXAMPLES / "denied-synthetic-retest-case.json").read_text(encoding="utf-8")
        )
        raw["scope_id"] = "SCOPE-OTHER-SYNTHETIC-001"
        result = run_case(raw)
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        other = OfflineApiCaseSource(case_id, invocation, evidence, result)
        other_batch = build_offline_api_batch(
            adapter=self.adapter, sources=(other,)
        ).to_dict()
        other_projection = build_offline_api_world_projection(
            **{**self.options(), "sources": (other,), "batch": other_batch}
        )
        with self.assertRaisesRegex(OfflineApiWorldProjectionError, "scope is absent"):
            append_offline_api_world_projection(
                **{
                    **self.options(),
                    "parent_snapshot": parent,
                    "projection": other_projection,
                    "sources": (other,),
                    "batch": other_batch,
                }
            )


if __name__ == "__main__":
    unittest.main()
