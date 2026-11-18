"""Run a complete, duration-balanced partition of the unittest suite."""

from __future__ import annotations

import argparse
import json
import math
import sys
import unittest
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "tests"
TEST_MODULE_ROOT = TEST_ROOT / "agents"
PROFILE_PATH = ROOT / "scripts" / "ci_test_durations_v2.json"
HEAVY_MODULE_SECONDS = 120.0
# These fixtures grew materially after the recorded CI profile was collected,
# or are slow new modules absent from it. Split cases without relabeling
# historical observations as new measurements.
CASE_SPLIT_MODULES = frozenset(
    {
        "test_authenticated_collaboration_plan_replacement_phase186d",
        "test_mission_policy_signed_replacement_anchor",
        "test_offline_pattern_task_relations",
        "test_offline_pattern_task_relations_cli",
        "test_offline_pattern_claim_graph",
        "test_offline_pattern_review_handoff",
        "test_offline_pattern_claim_delta",
        "test_offline_specialist_components",
    }
)
# These classes build costly shared source reports in setUpClass. Keep each
# class on one shard so the fixture is not rebuilt by separate runner jobs.
# Other classes in the same modules can still be split for balance.
FIXTURE_AFFINITY_CLASSES = frozenset(
    {
        "test_offline_pattern_claim_graph.PatternClaimGraphTests",
        "test_offline_pattern_claim_delta.PatternClaimDeltaTests",
        "test_offline_pattern_task_relations.PatternTaskRelationsTests",
        "test_offline_pattern_review_handoff.PatternReviewHandoffTests",
    }
)
# These classes in separate modules use the same lazily built SQLite baseline.
# Keep them in one runner process so a later consumer does not rebuild it on
# another shard after the defining module's own cases have been grouped.
SHARED_FIXTURE_GROUP_BY_CLASS = {
    (
        "test_authenticated_collaboration_plan_replacement_phase186d."
        "AuthenticatedCollaborationPlanReplacementPhase186DTests"
    ): "signed_replacement_baseline",
    (
        "test_collaboration_plan_replacement_operations_phase190."
        "CollaborationPlanReplacementOperationsPhase190Tests"
    ): "signed_replacement_baseline",
    (
        "test_mission_policy_signed_replacement_anchor."
        "MissionPolicySignedReplacementAnchorStoreTests"
    ): "signed_replacement_baseline",
}
# The 24 grouped cases passed locally in 186.6 seconds on 2026-10-16.
# This is a planner estimate, not a replacement for recorded CI timings.
SHARED_FIXTURE_PLANNING_SECONDS = {"signed_replacement_baseline": 200.0}


class CiShardError(ValueError):
    """The test suite or shard plan is incomplete."""


class ModuleQualifiedTextTestResult(unittest.TextTestResult):
    """Keep each completion's source module visible in timestamped CI logs."""

    def getDescription(self, test: unittest.TestCase) -> str:
        if isinstance(test, unittest.FunctionTestCase):
            return f"agents.{case_module(test)}.{test.id()}"
        return test.id()


@dataclass(frozen=True)
class TestGroup:
    key: str
    cases: tuple[unittest.TestCase, ...]
    estimated_seconds: float


def flatten_suite(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten_suite(item)
        else:
            yield item


def case_module(case: unittest.TestCase) -> str:
    if isinstance(case, unittest.FunctionTestCase):
        raw = case._testFunc.__module__
    else:
        raw = case.__class__.__module__
    if raw.startswith("tests.agents."):
        module = raw.removeprefix("tests.agents.")
    elif raw.startswith("agents."):
        module = raw.removeprefix("agents.")
    else:
        raise CiShardError(f"test has an unexpected module: {case.id()} ({raw})")
    if not module.startswith("test_") or not (TEST_MODULE_ROOT / f"{module}.py").is_file():
        raise CiShardError(f"test module is not a discovered file: {module}")
    return module


def discover_cases() -> list[unittest.TestCase]:
    sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(TEST_ROOT),
        pattern="test_*.py",
        top_level_dir=str(TEST_ROOT),
    )
    if loader.errors:
        raise CiShardError("test discovery failed: " + "\n".join(loader.errors))
    cases = list(flatten_suite(suite))
    if not cases:
        raise CiShardError("test discovery found no cases")
    modules = {case_module(case) for case in cases}
    files = {path.stem for path in TEST_MODULE_ROOT.glob("test_*.py")}
    if modules != files:
        raise CiShardError(
            f"test module coverage differs: missing={sorted(files - modules)}, "
            f"unexpected={sorted(modules - files)}"
        )
    return cases


def load_profile() -> dict[str, float]:
    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1 or not isinstance(
        raw.get("seconds_by_module"), dict
    ):
        raise CiShardError("CI duration profile has an invalid schema")
    profile: dict[str, float] = {}
    for module, value in raw["seconds_by_module"].items():
        if (
            not isinstance(module, str)
            or not module.startswith("test_")
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise CiShardError("CI duration profile has an invalid entry")
        profile[module] = float(value)
    return profile


def build_shards(
    cases: list[unittest.TestCase],
    profile: dict[str, float],
    shard_count: int,
) -> tuple[list[list[unittest.TestCase]], list[float]]:
    if shard_count < 1:
        raise CiShardError("shard count must be positive")
    original_position = {id(case): index for index, case in enumerate(cases)}
    if len(original_position) != len(cases):
        raise CiShardError("test discovery reused a case object")
    by_module: dict[str, list[unittest.TestCase]] = defaultdict(list)
    for case in cases:
        by_module[case_module(case)].append(case)

    groups: list[TestGroup] = []
    shared_fixture_cases: dict[str, list[unittest.TestCase]] = defaultdict(list)
    for module, module_cases in sorted(by_module.items()):
        estimated = max(0.1, profile.get(module, len(module_cases) * 0.5))
        split_cases = (
            estimated >= HEAVY_MODULE_SECONDS
            or module in CASE_SPLIT_MODULES
            or any(
                f"{module}.{case.__class__.__name__}" in SHARED_FIXTURE_GROUP_BY_CLASS
                for case in module_cases
            )
        )
        if split_cases:
            per_case = max(0.1, estimated / len(module_cases))
            fixture_cases: dict[str, list[unittest.TestCase]] = defaultdict(list)
            for index, case in enumerate(module_cases):
                class_key = f"{module}.{case.__class__.__name__}"
                if class_key in SHARED_FIXTURE_GROUP_BY_CLASS:
                    group_key = SHARED_FIXTURE_GROUP_BY_CLASS[class_key]
                    shared_fixture_cases[group_key].append(case)
                elif class_key in FIXTURE_AFFINITY_CLASSES:
                    fixture_cases[class_key].append(case)
                else:
                    groups.append(TestGroup(f"{module}#{index:04d}", (case,), per_case))
            groups.extend(
                TestGroup(class_key, tuple(class_cases), per_case * len(class_cases))
                for class_key, class_cases in sorted(fixture_cases.items())
            )
        else:
            groups.append(TestGroup(module, tuple(module_cases), estimated))
    groups.extend(
        TestGroup(
            f"shared_fixture:{group_key}",
            tuple(group_cases),
            SHARED_FIXTURE_PLANNING_SECONDS[group_key],
        )
        for group_key, group_cases in sorted(shared_fixture_cases.items())
    )

    shards: list[list[unittest.TestCase]] = [[] for _ in range(shard_count)]
    estimated_seconds = [0.0] * shard_count
    for group in sorted(groups, key=lambda item: (-item.estimated_seconds, item.key)):
        index = min(range(shard_count), key=lambda item: (estimated_seconds[item], item))
        shards[index].extend(group.cases)
        estimated_seconds[index] += group.estimated_seconds

    if sum(map(len, shards)) != len(cases):
        raise CiShardError("shard plan omitted or duplicated test cases")
    if any(not shard for shard in shards):
        raise CiShardError("shard plan contains an empty shard")
    for shard in shards:
        shard.sort(key=lambda case: original_position[id(case)])
    return shards, estimated_seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard-count", type=int, default=8)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--check-plan", action="store_true")
    args = parser.parse_args()
    if args.check_plan == (args.shard_index is not None):
        parser.error("select either --check-plan or --shard-index")

    try:
        cases = discover_cases()
        shards, estimates = build_shards(cases, load_profile(), args.shard_count)
        if args.shard_index is not None and not 0 <= args.shard_index < len(shards):
            raise CiShardError("shard index is outside the plan")
    except CiShardError as error:
        print(f"CI shard error: {error}", file=sys.stderr)
        return 1

    summary = {
        "test_count": len(cases),
        "shard_count": len(shards),
        "shards": [
            {
                "index": index,
                "test_count": len(shard),
                "estimated_seconds": round(estimates[index], 1),
            }
            for index, shard in enumerate(shards)
        ],
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    if args.check_plan:
        return 0
    return 0 if unittest.TextTestRunner(
        verbosity=2, resultclass=ModuleQualifiedTextTestResult
    ).run(
        unittest.TestSuite(shards[args.shard_index])
    ).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
