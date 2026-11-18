"""Propose module timings from one complete successful PR shard run."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import FunctionTestCase

if __package__:
    from .run_ci_test_shard import CiShardError, case_module, discover_cases
else:
    from run_ci_test_shard import CiShardError, case_module, discover_cases

SHARD_COUNT = 8
MAX_LOG_BYTES = 32_000_000
ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LINE = re.compile(
    r"^test-shard \((?P<shard>[0-7])\)\t"
    r"(?:Run python scripts/run_ci_test_shard\.py --shard-index (?P<index>[0-7]) "
    r"--shard-count 8|UNKNOWN STEP)\t\ufeff?"
    r"(?P<timestamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) "
    r"(?P<message>.*)$"
)
_TEST = re.compile(
    r"^test_[A-Za-z0-9_]+ \((?:tests\.)?agents\."
    r"(?P<module>test_[A-Za-z0-9_]+)\.[^)]+\) \.\.\. "
    r"(?P<outcome>ok|skipped .+|expected failure)$"
)
_QUALIFIED = re.compile(
    r"^(?:tests\.)?agents\.(?P<module>test_[A-Za-z0-9_]+)\."
    r"[A-Za-z0-9_.]+ \.\.\. (?P<outcome>ok|skipped .+|expected failure)$"
)
_QUALIFIED_START = re.compile(
    r"^(?:tests\.)?agents\.(?P<module>test_[A-Za-z0-9_]+)\."
    r"[A-Za-z0-9_.]+ \.\.\. .*$"
)
_FUNCTION = re.compile(
    r"^unittest\.case\.FunctionTestCase \((?P<case>test_[A-Za-z0-9_]+)\) "
    r"\.\.\. (?P<outcome>ok|skipped .+|expected failure)$"
)
_LEGACY_HEADER = re.compile(
    r"^test_[A-Za-z0-9_]+ \((?:tests\.)?agents\."
    r"(?P<module>test_[A-Za-z0-9_]+)\.[^)]+\)$"
)
_LEGACY_START = re.compile(
    r"^test_[A-Za-z0-9_]+ \((?:tests\.)?agents\."
    r"(?P<module>test_[A-Za-z0-9_]+)\.[^)]+\) \.\.\. .*$"
)
_LEGACY_OUTCOME = re.compile(r"^.+ \.\.\. (?P<outcome>ok|skipped .+|expected failure)$")
_SPLIT_OUTCOME = re.compile(r"^(?P<outcome>ok|skipped .+|expected failure)$")
_FOOTER = re.compile(r"^Ran (?P<count>\d+) tests? in (?P<seconds>\d+(?:\.\d+)?)s$")


class CiShardDurationError(ValueError):
    """A run or log cannot support a complete duration proposal."""


def _instant(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CiShardDurationError("Shard log timestamp is invalid") from exc
    if result.utcoffset() != timezone.utc.utcoffset(result):
        raise CiShardDurationError("Shard log timestamp is not UTC")
    return result


def parse_shard_log(
    text: str, shard_index: int,
    *, function_modules: dict[str, str | set[str]] | None = None,
) -> dict[str, Any]:
    """Attribute each elapsed interval to the test completion ending it."""

    if type(text) is not str or not 0 <= shard_index < SHARD_COUNT:
        raise CiShardDurationError("Exact shard text and index are required")
    if len(text) > MAX_LOG_BYTES or len(text.encode("utf-8")) > MAX_LOG_BYTES:
        raise CiShardDurationError("Shard log exceeds its byte limit")
    summary = None
    started = previous = completed = None
    footer = None
    records: list[dict[str, Any]] = []
    function_cases = 0
    pending_module = None
    function_modules = {} if function_modules is None else function_modules
    for line in text.splitlines():
        match = _LINE.fullmatch(line)
        if match is None:
            continue
        if int(match["shard"]) != shard_index or (
            match["index"] is not None and int(match["index"]) != shard_index
        ):
            raise CiShardDurationError("Shard log prefix differs from the requested index")
        at = _instant(match["timestamp"])
        message = match["message"]
        if message.startswith('{"shard_count":'):
            if summary is not None:
                raise CiShardDurationError("Shard log repeats its plan summary")
            try:
                summary = json.loads(message)
            except json.JSONDecodeError as exc:
                raise CiShardDurationError("Shard plan summary is invalid") from exc
            if (
                type(summary) is not dict
                or summary.get("shard_count") != SHARD_COUNT
                or type(summary.get("shards")) is not list
                or len(summary["shards"]) != SHARD_COUNT
                or type(summary.get("test_count")) is not int
                or summary["test_count"] < SHARD_COUNT
            ):
                raise CiShardDurationError("Shard plan summary is incomplete")
            for index, row in enumerate(summary["shards"]):
                if (
                    type(row) is not dict
                    or row.get("index") != index
                    or type(row.get("test_count")) is not int
                    or row["test_count"] < 1
                ):
                    raise CiShardDurationError("Shard plan entries are invalid")
            if sum(row["test_count"] for row in summary["shards"]) != summary["test_count"]:
                raise CiShardDurationError("Shard plan case counts do not reconcile")
            started = previous = at
            continue
        test = _TEST.fullmatch(message) or _QUALIFIED.fullmatch(message)
        function = _FUNCTION.fullmatch(message) if test is None else None
        header = _LEGACY_HEADER.fullmatch(message)
        if header is None and test is None and function is None:
            header = _LEGACY_START.fullmatch(message) or _QUALIFIED_START.fullmatch(message)
        if header is not None:
            if pending_module is not None or summary is None or footer is not None:
                raise CiShardDurationError("Legacy test description is incomplete")
            pending_module = header["module"]
            continue
        legacy_outcome = (
            _LEGACY_OUTCOME.fullmatch(message) or _SPLIT_OUTCOME.fullmatch(message)
            if test is None and function is None and pending_module is not None
            else None
        )
        if test is not None or function is not None or legacy_outcome is not None:
            if summary is None or footer is not None or previous is None:
                raise CiShardDurationError("Test completion is outside the bounded run")
            if pending_module is not None and legacy_outcome is None:
                raise CiShardDurationError("Legacy test description lacks its outcome")
            interval = (at - previous).total_seconds()
            if not 0 <= interval <= 3600:
                raise CiShardDurationError("Test completion time is nonmonotonic or unbounded")
            if function is not None:
                supplied = function_modules.get(function["case"])
                candidates = {supplied} if type(supplied) is str else supplied
                if (
                    type(candidates) is not set
                    or not candidates
                    or any(
                        type(item) is not str
                        or re.fullmatch(r"test_[A-Za-z0-9_]+", item) is None
                        for item in candidates
                    )
                ):
                    raise CiShardDurationError(
                        "FunctionTestCase lacks a bounded local discovery mapping"
                    )
                module = next(iter(candidates)) if len(candidates) == 1 else None
                function_cases += 1
                outcome = function["outcome"]
            elif legacy_outcome is not None:
                module = pending_module
                candidates = {module}
                outcome = legacy_outcome["outcome"]
                pending_module = None
            else:
                module = test["module"]
                candidates = {module}
                outcome = test["outcome"]
            records.append({
                "module": module,
                "candidates": candidates,
                "seconds": interval,
                "skipped": outcome.startswith("skipped "),
                "legacy_function": function is not None,
            })
            previous = completed = at
            continue
        matched_footer = _FOOTER.fullmatch(message)
        if matched_footer is not None:
            if summary is None or completed is None or footer is not None or pending_module:
                raise CiShardDurationError("Unittest footer is missing or repeated")
            footer = (int(matched_footer["count"]), float(matched_footer["seconds"]))
            if abs((at - started).total_seconds() - footer[1]) > 0.5:
                raise CiShardDurationError("Timestamped run disagrees with unittest elapsed time")
    if summary is None or footer is None or completed is None or pending_module is not None:
        raise CiShardDurationError("Shard log lacks a complete plan, cases, or footer")
    observed = len(records)
    expected = summary["shards"][shard_index]["test_count"]
    if observed != expected or footer[0] != expected:
        raise CiShardDurationError(
            f"Timestamped completions do not cover every shard case: "
            f"observed={observed}, expected={expected}, footer={footer[0]}"
        )
    if abs(sum(row["seconds"] for row in records) - footer[1]) > 0.5:
        raise CiShardDurationError("Per-test intervals do not reconcile with unittest time")
    inferred = 0
    inferred_seconds = 0.0
    for index, row in enumerate(records):
        if not row["legacy_function"]:
            continue
        before = next(
            (item["module"] for item in reversed(records[:index]) if item["module"] is not None),
            None,
        )
        after = next(
            (item["module"] for item in records[index + 1:] if item["module"] is not None),
            None,
        )
        if row["module"] is not None:
            if before is not None and before == after and before != row["module"]:
                raise CiShardDurationError(
                    "Local FunctionTestCase mapping conflicts with both neighbors"
                )
            continue
        if before is None or before != after or before not in row["candidates"]:
            raise CiShardDurationError(
                "Ambiguous FunctionTestCase cannot be attributed from both neighbors"
            )
        row["module"] = before
        inferred += 1
        inferred_seconds += row["seconds"]
    seconds: dict[str, float] = defaultdict(float)
    for row in records:
        seconds[row["module"]] += row["seconds"]
    return {
        "plan": summary,
        "case_count": observed,
        "function_case_count": function_cases,
        "legacy_inferred_case_count": inferred,
        "legacy_inferred_seconds": inferred_seconds,
        "skipped_count": sum(row["skipped"] for row in records),
        "seconds_by_module": dict(seconds),
        "observed_seconds": footer[1],
    }


def build_proposal(
    run: dict[str, Any], logs: dict[int, str], run_id: int,
    *, function_modules: dict[str, str | set[str]] | None = None,
) -> dict[str, Any]:
    """Require one successful complete PR run and all eight matching logs."""

    if type(run_id) is not int or run_id < 1 or type(run) is not dict:
        raise CiShardDurationError("Exact CI run metadata is required")
    if (
        run.get("conclusion") != "success"
        or run.get("event") != "pull_request"
        or type(run.get("headSha")) is not str
        or _SHA.fullmatch(run["headSha"]) is None
        or type(run.get("jobs")) is not list
    ):
        raise CiShardDurationError("Only a complete successful PR run is supported")
    jobs = {}
    for job in run["jobs"]:
        if type(job) is not dict:
            raise CiShardDurationError("CI job metadata is invalid")
        name = job.get("name")
        match = re.fullmatch(r"test-shard \(([0-7])\)", name) if type(name) is str else None
        if match is None:
            continue
        index = int(match[1])
        if (
            index in jobs
            or job.get("conclusion") != "success"
            or type(job.get("databaseId")) is not int
            or job["databaseId"] < 1
        ):
            raise CiShardDurationError("Shard jobs are duplicated or incomplete")
        jobs[index] = job["databaseId"]
    if set(jobs) != set(range(SHARD_COUNT)) or set(logs) != set(jobs):
        raise CiShardDurationError("All eight successful shard logs are required")
    observed = []
    for index in range(SHARD_COUNT):
        try:
            observed.append(
                parse_shard_log(logs[index], index, function_modules=function_modules)
            )
        except CiShardDurationError as exc:
            raise CiShardDurationError(f"Shard {index}: {exc}") from exc
    plan = observed[0]["plan"]
    if any(row["plan"] != plan for row in observed):
        raise CiShardDurationError("Shard jobs disagree about the complete test plan")
    seconds: dict[str, float] = defaultdict(float)
    for row in observed:
        for module, value in row["seconds_by_module"].items():
            seconds[module] += value
    case_count = sum(row["case_count"] for row in observed)
    if case_count != plan["test_count"]:
        raise CiShardDurationError("Complete run case count does not reconcile")
    return {
        "schema_version": 1,
        "proposal_only": True,
        "source_ci_run_id": run_id,
        "source_head_sha": run["headSha"],
        "source_method": "timestamped_successful_pr_shard_logs",
        "shard_job_ids": [jobs[index] for index in range(SHARD_COUNT)],
        "case_count": case_count,
        "function_case_count": sum(row["function_case_count"] for row in observed),
        "legacy_inferred_case_count": sum(
            row["legacy_inferred_case_count"] for row in observed
        ),
        "legacy_inferred_seconds": round(
            sum(row["legacy_inferred_seconds"] for row in observed), 3
        ),
        "module_count": len(seconds),
        "skipped_count": sum(row["skipped_count"] for row in observed),
        "observed_total_seconds": round(sum(row["observed_seconds"] for row in observed), 1),
        "seconds_by_module": {name: round(value, 1) for name, value in sorted(seconds.items())},
        "limitations": [
            "Log timestamps include test fixture and output overhead, not isolated test CPU time.",
            "The proposal is one PR run, not a serial run or a verified billing report.",
            "Legacy FunctionTestCase attribution can use local discovery and two neighbors; "
            "it is not CI source authentication.",
            "It does not alter the checked duration profile or CI shard assignment.",
        ],
    }


def _gh(*args: str) -> str:
    try:
        result = subprocess.run(
            ["gh", *args], capture_output=True, text=True, encoding="utf-8",
            check=True, timeout=120,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise CiShardDurationError("GitHub CLI could not read the selected CI run") from exc
    if len(result.stdout) > MAX_LOG_BYTES:
        raise CiShardDurationError("GitHub CLI output exceeds the byte limit")
    return result.stdout


def discover_function_modules() -> dict[str, set[str]]:
    """Resolve unittest's module-free FunctionTestCase display names locally."""

    candidates: dict[str, set[str]] = defaultdict(set)
    sys.path.insert(0, str(ROOT / "src"))
    try:
        for case in discover_cases():
            if isinstance(case, FunctionTestCase):
                name = case._testFunc.__name__
                candidates[name].add(case_module(case))
    except CiShardError as exc:
        raise CiShardDurationError("Local test discovery cannot map function cases") from exc
    return dict(candidates)


def proposal_from_gh(run_id: int, repo: str) -> dict[str, Any]:
    """Read one selected completed run without writing or starting a workflow."""

    if type(run_id) is not int or run_id < 1:
        raise CiShardDurationError("A positive exact run ID is required")
    if type(repo) is not str or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None:
        raise CiShardDurationError("An exact owner/repository name is required")
    run = json.loads(_gh("run", "view", str(run_id), "--repo", repo,
                         "--json", "jobs,conclusion,event,headSha"))
    if run.get("conclusion") != "success" or run.get("event") != "pull_request":
        raise CiShardDurationError("Only a complete successful PR run is supported")
    logs = {
        int(match[1]): _gh("run", "view", str(run_id), "--repo", repo,
                           "--job", str(job["databaseId"]), "--log")
        for job in run.get("jobs", [])
        if type(job) is dict
        and type(job.get("name")) is str
        and (match := re.fullmatch(r"test-shard \(([0-7])\)", job["name"])) is not None
    }
    return build_proposal(run, logs, run_id, function_modules=discover_function_modules())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--repo", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be an exact owner/repository name")
    try:
        proposal = proposal_from_gh(args.run_id, args.repo)
    except (CiShardDurationError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"CI duration proposal error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(proposal, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
