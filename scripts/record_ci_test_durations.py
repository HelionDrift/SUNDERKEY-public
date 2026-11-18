"""Observe a complete local test run and propose a CI shard duration profile."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import sys
import time
import unittest
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
shard = importlib.import_module("scripts.run_ci_test_shard")

RECORDER_PATH = ROOT / "scripts" / "record_ci_test_durations.py"
SHARDER_PATH = ROOT / "scripts" / "run_ci_test_shard.py"


class DurationObservationError(ValueError):
    """The run cannot support a complete duration-profile observation."""


def _source_snapshot() -> dict[str, str]:
    paths = [RECORDER_PATH, SHARDER_PATH]
    paths.extend(sorted(shard.TEST_MODULE_ROOT.glob("test_*.py")))
    return {
        path.relative_to(ROOT).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def _groups(
    cases: list[unittest.TestCase], expected_modules: tuple[str, ...]
) -> tuple[tuple[str, tuple[unittest.TestCase, ...]], ...]:
    if not expected_modules or len(set(expected_modules)) != len(expected_modules):
        raise DurationObservationError("Expected test modules are empty or duplicated")
    expected = set(expected_modules)
    groups: list[tuple[str, list[unittest.TestCase]]] = []
    closed: set[str] = set()
    case_ids: set[str] = set()
    for case in cases:
        module = shard.case_module(case)
        if module not in expected:
            raise DurationObservationError("Discovered a test outside the current module set")
        case_id = case.id()
        if case_id in case_ids:
            raise DurationObservationError("A test case was discovered more than once")
        case_ids.add(case_id)
        if not groups or groups[-1][0] != module:
            if module in closed:
                raise DurationObservationError("A test module is not contiguous in discovery order")
            groups.append((module, []))
            closed.add(module)
        groups[-1][1].append(case)
    if {module for module, _ in groups} != expected:
        raise DurationObservationError("Current test module coverage is incomplete")
    return tuple((module, tuple(module_cases)) for module, module_cases in groups)


def _run_module(module: str, cases: tuple[unittest.TestCase, ...]) -> unittest.TestResult:
    print(f"Observing {module} ({len(cases)} cases)", file=sys.stderr, flush=True)
    result = unittest.TestResult()
    unittest.TestSuite(cases).run(result)
    return result


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value):
        raise DurationObservationError("The observation clock returned a nonfinite value")
    return float(value)


def _observe_complete_run(
    cases: list[unittest.TestCase],
    expected_modules: tuple[str, ...],
    *,
    before_sources: dict[str, str],
    after_sources: Callable[[], dict[str, str]],
    run_module: Callable[[str, tuple[unittest.TestCase, ...]], unittest.TestResult],
    clock: Callable[[], float],
) -> dict[str, object]:
    """Measure actual module suites; never accept caller-supplied durations."""
    groups = _groups(cases, expected_modules)
    observations: list[dict[str, object]] = []
    for module, module_cases in groups:
        started = _clock_value(clock)
        result = run_module(module, module_cases)
        finished = _clock_value(clock)
        elapsed = finished - started
        if elapsed < 0 or not math.isfinite(elapsed):
            raise DurationObservationError("The observation clock regressed")
        if not isinstance(result, unittest.TestResult) or result.testsRun != len(module_cases):
            raise DurationObservationError("A module did not run every discovered test")
        if not result.wasSuccessful():
            raise DurationObservationError(f"The {module} module did not pass")
        observations.append(
            {
                "module": module,
                "test_count": len(module_cases),
                "skipped_count": len(result.skipped),
                "expected_failure_count": len(result.expectedFailures),
                "elapsed_seconds": elapsed,
            }
        )
    if after_sources() != before_sources:
        raise DurationObservationError("Test or recorder source changed during the run")
    seconds = {
        item["module"]: item["elapsed_seconds"]
        for item in sorted(observations, key=lambda item: item["module"])
    }
    total = math.fsum(item["elapsed_seconds"] for item in observations)
    if not math.isfinite(total):
        raise DurationObservationError("Total observed time is nonfinite")
    return {
        "schema_version": 1,
        "source_ci_run_id": None,
        "source_kind": "local_complete_module_observation",
        "observed_total_seconds": total,
        "observed_test_count": len(cases),
        "observed_skip_count": sum(item["skipped_count"] for item in observations),
        "seconds_by_module": seconds,
        "module_observations": observations,
        "source_sha256": dict(sorted(before_sources.items())),
    }


def _write_proposal(profile: dict[str, object], output: Path) -> None:
    """Create an explicit proposal, never overwrite the checked profile."""
    if output.resolve() == shard.PROFILE_PATH.resolve():
        raise DurationObservationError("The checked duration profile cannot be replaced")
    content = json.dumps(profile, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        before = _source_snapshot()
        expected = tuple(sorted(path.stem for path in shard.TEST_MODULE_ROOT.glob("test_*.py")))
        cases = shard.discover_cases()
        profile = _observe_complete_run(
            cases,
            expected,
            before_sources=before,
            after_sources=_source_snapshot,
            run_module=_run_module,
            clock=time.perf_counter,
        )
        _write_proposal(profile, args.output)
    except (DurationObservationError, shard.CiShardError, OSError) as error:
        print(f"CI duration observation refused: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "local_proposal_created": True,
                "module_count": len(profile["seconds_by_module"]),
                "observed_test_count": profile["observed_test_count"],
                "observed_skip_count": profile["observed_skip_count"],
                "checked_profile_changed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
