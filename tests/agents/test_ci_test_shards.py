"""Validate complete, deterministic CI test sharding."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from scripts import run_ci_test_shard


class SyntheticCase(unittest.TestCase):
    def case_a(self) -> None:
        pass

    def case_b(self) -> None:
        pass

    def case_c(self) -> None:
        pass

    def case_d(self) -> None:
        pass


class CiShardTests(unittest.TestCase):
    def test_active_duration_profile_is_the_checked_three_run_revision(self) -> None:
        self.assertEqual(run_ci_test_shard.PROFILE_PATH.name, "ci_test_durations_v2.json")
        profile = json.loads(run_ci_test_shard.PROFILE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(profile["profile_revision"], 2)
        self.assertEqual(
            profile["source_ci_run_ids"],
            [37129612514, 37132153286, 37134132215],
        )
        self.assertEqual(profile["module_count"], len(profile["seconds_by_module"]))
        self.assertEqual(
            run_ci_test_shard.load_profile().keys(),
            profile["seconds_by_module"].keys(),
        )

    def test_heavy_module_is_split_without_loss(self) -> None:
        cases = [
            SyntheticCase("case_a"),
            SyntheticCase("case_b"),
            SyntheticCase("case_c"),
            SyntheticCase("case_d"),
        ]
        shards, estimates = run_ci_test_shard.build_shards(
            cases, {"test_ci_test_shards": 240.0}, 4
        )
        self.assertEqual([len(shard) for shard in shards], [1, 1, 1, 1])
        self.assertEqual(estimates, [60.0] * 4)
        self.assertEqual({id(case) for shard in shards for case in shard}, {
            id(case) for case in cases
        })

    def test_function_case_module_is_normalized(self) -> None:
        def sample() -> None:
            return None

        sample.__module__ = "tests.agents.test_ci_test_shards"
        case = unittest.FunctionTestCase(sample)
        self.assertEqual(run_ci_test_shard.case_module(case), "test_ci_test_shards")
        result = run_ci_test_shard.ModuleQualifiedTextTestResult(None, True, 2)
        self.assertEqual(
            result.getDescription(case), "agents.test_ci_test_shards.sample"
        )

    def test_regular_case_output_retains_module_and_method(self) -> None:
        result = run_ci_test_shard.ModuleQualifiedTextTestResult(None, True, 2)
        self.assertEqual(
            result.getDescription(SyntheticCase("case_a")),
            f"{SyntheticCase.__module__}.SyntheticCase.case_a",
        )

    def test_structurally_expanded_module_splits_without_changing_observation(self) -> None:
        cases = [SyntheticCase(f"case_{letter}") for letter in "abcd"]
        profile = {"test_ci_test_shards": 1.0}
        with mock.patch.object(
            run_ci_test_shard, "CASE_SPLIT_MODULES", frozenset({"test_ci_test_shards"})
        ):
            shards, estimates = run_ci_test_shard.build_shards(cases, profile, 4)
        self.assertEqual(profile, {"test_ci_test_shards": 1.0})
        self.assertEqual([len(shard) for shard in shards], [1, 1, 1, 1])
        self.assertEqual(estimates, [0.25] * 4)
        self.assertEqual(
            {id(case) for shard in shards for case in shard}, {id(case) for case in cases}
        )

    def test_invalid_shard_count_fails(self) -> None:
        with self.assertRaisesRegex(run_ci_test_shard.CiShardError, "positive"):
            run_ci_test_shard.build_shards([self], {}, 0)

    def test_discovery_and_plan_cover_every_case_once(self) -> None:
        cases = run_ci_test_shard.discover_cases()
        shards, estimates = run_ci_test_shard.build_shards(
            cases, run_ci_test_shard.load_profile(), 8
        )
        self.assertEqual(sum(map(len, shards)), len(cases))
        self.assertEqual(
            {id(case) for shard in shards for case in shard},
            {id(case) for case in cases},
        )
        position = {id(case): index for index, case in enumerate(cases)}
        for shard in shards:
            self.assertEqual(
                [position[id(case)] for case in shard],
                sorted(position[id(case)] for case in shard),
            )
        self.assertLess(max(estimates) - min(estimates), 2.0)

    def test_new_slow_pattern_modules_are_distributed_across_shards(self) -> None:
        cases = run_ci_test_shard.discover_cases()
        shards, _ = run_ci_test_shard.build_shards(
            cases, run_ci_test_shard.load_profile(), 8
        )
        for module in (
            "test_offline_pattern_task_relations_cli",
            "test_offline_pattern_claim_graph",
            "test_offline_pattern_claim_delta",
        ):
            with self.subTest(module=module):
                assigned = {
                    index
                    for index, shard in enumerate(shards)
                    for case in shard
                    if run_ci_test_shard.case_module(case) == module
                }
                self.assertGreater(len(assigned), 1)

    def test_large_component_dispatch_module_is_distributed_across_shards(self) -> None:
        cases = run_ci_test_shard.discover_cases()
        shards, _ = run_ci_test_shard.build_shards(
            cases, run_ci_test_shard.load_profile(), 8
        )
        assigned = {
            index
            for index, shard in enumerate(shards)
            for case in shard
            if run_ci_test_shard.case_module(case) == "test_offline_specialist_components"
        }
        self.assertGreater(len(assigned), 1)

    def test_expensive_shared_fixtures_run_once_per_class(self) -> None:
        cases = run_ci_test_shard.discover_cases()
        shards, _ = run_ci_test_shard.build_shards(
            cases, run_ci_test_shard.load_profile(), 8
        )
        for class_key in run_ci_test_shard.FIXTURE_AFFINITY_CLASSES:
            module, class_name = class_key.split(".", 1)
            assigned = {
                index
                for index, shard in enumerate(shards)
                for case in shard
                if run_ci_test_shard.case_module(case) == module
                and case.__class__.__name__ == class_name
            }
            with self.subTest(class_key=class_key):
                self.assertEqual(len(assigned), 1)
                shard = shards[next(iter(assigned))]
                positions = [
                    position
                    for position, case in enumerate(shard)
                    if run_ci_test_shard.case_module(case) == module
                    and case.__class__.__name__ == class_name
                ]
                self.assertEqual(
                    positions, list(range(positions[0], positions[-1] + 1))
                )

    def test_shared_signed_replacement_baseline_runs_on_one_shard(self) -> None:
        class_keys = {
            "test_authenticated_collaboration_plan_replacement_phase186d."
            "AuthenticatedCollaborationPlanReplacementPhase186DTests",
            "test_collaboration_plan_replacement_operations_phase190."
            "CollaborationPlanReplacementOperationsPhase190Tests",
            "test_mission_policy_signed_replacement_anchor."
            "MissionPolicySignedReplacementAnchorStoreTests",
        }
        self.assertIn(
            "test_authenticated_collaboration_plan_replacement_phase186d",
            run_ci_test_shard.CASE_SPLIT_MODULES,
        )
        self.assertEqual(
            {
                key
                for key, value in run_ci_test_shard.SHARED_FIXTURE_GROUP_BY_CLASS.items()
                if value == "signed_replacement_baseline"
            },
            class_keys,
        )
        self.assertEqual(
            run_ci_test_shard.SHARED_FIXTURE_PLANNING_SECONDS["signed_replacement_baseline"],
            200.0,
        )
        cases = run_ci_test_shard.discover_cases()
        shards, _ = run_ci_test_shard.build_shards(cases, run_ci_test_shard.load_profile(), 8)
        assignments = []
        grouped_case_count = 0
        for class_key in sorted(class_keys):
            module, class_name = class_key.split(".", 1)
            grouped_case_count += sum(
                run_ci_test_shard.case_module(case) == module
                and case.__class__.__name__ == class_name
                for case in cases
            )
            assigned = {
                index
                for index, shard in enumerate(shards)
                for case in shard
                if run_ci_test_shard.case_module(case) == module
                and case.__class__.__name__ == class_name
            }
            self.assertEqual(len(assigned), 1, class_key)
            assignments.extend(assigned)
        self.assertEqual(grouped_case_count, 24)
        self.assertEqual(len(set(assignments)), 1)


if __name__ == "__main__":
    unittest.main()
