"""Require complete, reconciled PR shard logs before proposing CI timings."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from scripts import propose_ci_shard_durations as durations

RUN_ID = 37134132215
HEAD_SHA = "a" * 40


def fixture(index: int) -> str:
    plan = {
        "shard_count": 8,
        "shards": [
            {"estimated_seconds": 2.0, "index": item, "test_count": 2}
            for item in range(8)
        ],
        "test_count": 16,
    }
    prefix = (
        f"test-shard ({index})\tRun python scripts/run_ci_test_shard.py "
        f"--shard-index {index} --shard-count 8\t"
    )
    return "\n".join(
        (
            prefix + "2026-10-03T00:00:00.0000000Z " + json.dumps(plan),
            prefix
            + "2026-10-03T00:00:01.0000000Z "
            + "test_one (agents.test_alpha.Cases.test_one) ... ok",
            prefix
            + "2026-10-03T00:00:02.0000000Z "
            + "test_two (tests.agents.test_beta.Cases.test_two) ... skipped 'fixture'",
            prefix + "2026-10-03T00:00:02.0000000Z Ran 2 tests in 2.000s",
        )
    )


def run() -> dict:
    return {
        "conclusion": "success",
        "event": "pull_request",
        "headSha": HEAD_SHA,
        "jobs": [
            {"name": f"test-shard ({index})", "conclusion": "success", "databaseId": 100 + index}
            for index in range(8)
        ],
    }


class CiShardDurationProposalTests(unittest.TestCase):
    def test_complete_logs_produce_bounded_unsigned_proposal(self) -> None:
        logs = {index: fixture(index) for index in range(8)}
        result = durations.build_proposal(run(), logs, RUN_ID)
        self.assertTrue(result["proposal_only"])
        self.assertEqual(result["source_ci_run_id"], RUN_ID)
        self.assertEqual(result["source_head_sha"], HEAD_SHA)
        self.assertEqual(result["case_count"], 16)
        self.assertEqual(result["function_case_count"], 0)
        self.assertEqual(result["legacy_inferred_case_count"], 0)
        self.assertEqual(result["legacy_inferred_seconds"], 0.0)
        self.assertEqual(result["skipped_count"], 8)
        self.assertEqual(result["observed_total_seconds"], 16.0)
        self.assertEqual(result["seconds_by_module"], {"test_alpha": 8.0, "test_beta": 8.0})
        self.assertEqual(result["shard_job_ids"], list(range(100, 108)))

    def test_single_shard_requires_exact_count_footer_and_monotonic_time(self) -> None:
        good = fixture(3)
        for bad in (
            good.replace("Ran 2 tests", "Ran 1 test"),
            good.replace("in 2.000s", "in 3.000s"),
            good.replace("00:00:02.0000000Z test_two", "00:00:00.0000000Z test_two"),
            good.replace("test_two (tests.agents", "test_two (foreign.agents"),
            good.replace("--shard-index 3", "--shard-index 4"),
            good.replace("... ok", "... FAIL"),
        ):
            with self.subTest(bad=bad[-80:]):
                with self.assertRaises(durations.CiShardDurationError):
                    durations.parse_shard_log(bad, 3)

    def test_complete_run_rejects_missing_failed_duplicate_or_foreign_jobs(self) -> None:
        logs = {index: fixture(index) for index in range(8)}
        cases = []
        missing = copy.deepcopy(run())
        missing["jobs"].pop()
        cases.append((missing, logs))
        failed = copy.deepcopy(run())
        failed["jobs"][0]["conclusion"] = "failure"
        cases.append((failed, logs))
        duplicate = copy.deepcopy(run())
        duplicate["jobs"].append(copy.deepcopy(duplicate["jobs"][0]))
        cases.append((duplicate, logs))
        foreign = copy.deepcopy(run())
        foreign["event"] = "push"
        cases.append((foreign, logs))
        cases.append((run(), {index: fixture(index) for index in range(7)}))
        for metadata, supplied in cases:
            with self.subTest(metadata=metadata, log_count=len(supplied)):
                with self.assertRaises(durations.CiShardDurationError):
                    durations.build_proposal(metadata, supplied, RUN_ID)

    def test_function_case_requires_one_explicit_module_mapping(self) -> None:
        log = fixture(2).replace(
            "test_two (tests.agents.test_beta.Cases.test_two)",
            "unittest.case.FunctionTestCase (test_two)",
        )
        with self.assertRaises(durations.CiShardDurationError):
            durations.parse_shard_log(log, 2)
        parsed = durations.parse_shard_log(
            log, 2, function_modules={"test_two": "test_beta"}
        )
        self.assertEqual(parsed["function_case_count"], 1)
        self.assertEqual(parsed["legacy_inferred_case_count"], 0)
        self.assertEqual(parsed["seconds_by_module"], {"test_alpha": 1.0, "test_beta": 1.0})

    def test_legacy_ambiguous_function_requires_matching_neighbors(self) -> None:
        plan = json.loads(fixture(2).splitlines()[0].split("Z ", 1)[1])
        plan["shards"][2]["test_count"] = 3
        plan["test_count"] = 17
        prefix = (
            "test-shard (2)\tRun python scripts/run_ci_test_shard.py "
            "--shard-index 2 --shard-count 8\t"
        )
        log = "\n".join((
            prefix + "2026-10-03T00:00:00.0000000Z " + json.dumps(plan),
            prefix + "2026-10-03T00:00:01.0000000Z agents.test_beta.Cases.test_one ... ok",
            prefix + "2026-10-03T00:00:02.0000000Z "
            + "unittest.case.FunctionTestCase (test_shared) ... ok",
            prefix + "2026-10-03T00:00:03.0000000Z agents.test_beta.Cases.test_three ... ok",
            prefix + "2026-10-03T00:00:03.0000000Z Ran 3 tests in 3.000s",
        ))
        parsed = durations.parse_shard_log(
            log, 2, function_modules={"test_shared": {"test_beta", "test_gamma"}}
        )
        self.assertEqual(parsed["legacy_inferred_case_count"], 1)
        self.assertEqual(parsed["legacy_inferred_seconds"], 1.0)
        self.assertEqual(parsed["seconds_by_module"], {"test_beta": 3.0})
        for candidate, changed_log in (
            ({"test_gamma"}, log),
            ({"test_beta", "test_gamma"}, log.replace("test_three", "test_other").replace(
                "agents.test_beta.Cases.test_other", "agents.test_gamma.Cases.test_other"
            )),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(durations.CiShardDurationError):
                    durations.parse_shard_log(
                        changed_log, 2, function_modules={"test_shared": candidate}
                    )

    def test_module_qualified_runner_output_requires_no_local_mapping(self) -> None:
        log = fixture(4).replace(
            "test_two (tests.agents.test_beta.Cases.test_two)",
            "agents.test_beta.test_two",
        )
        parsed = durations.parse_shard_log(log, 4)
        self.assertEqual(parsed["case_count"], 2)
        self.assertEqual(parsed["function_case_count"], 0)
        self.assertEqual(parsed["seconds_by_module"], {"test_alpha": 1.0, "test_beta": 1.0})

    def test_legacy_unknown_step_requires_same_job_prefix_and_complete_cases(self) -> None:
        log = fixture(7).replace(
            "Run python scripts/run_ci_test_shard.py --shard-index 7 --shard-count 8",
            "UNKNOWN STEP",
        )
        self.assertEqual(durations.parse_shard_log(log, 7)["case_count"], 2)
        with self.assertRaises(durations.CiShardDurationError):
            durations.parse_shard_log(log.replace("test-shard (7)", "test-shard (6)"), 7)

    def test_legacy_multiline_description_keeps_header_module(self) -> None:
        log = fixture(6).replace(
            "test_two (tests.agents.test_beta.Cases.test_two) ... skipped 'fixture'",
            "test_two (tests.agents.test_beta.Cases.test_two)\n"
            + "test-shard (6)\tRun python scripts/run_ci_test_shard.py "
            + "--shard-index 6 --shard-count 8\t"
            + "2026-10-03T00:00:02.0000000Z Description with source context. ... ok",
        )
        parsed = durations.parse_shard_log(log, 6)
        self.assertEqual(parsed["case_count"], 2)
        self.assertEqual(parsed["seconds_by_module"], {"test_alpha": 1.0, "test_beta": 1.0})
        with self.assertRaises(durations.CiShardDurationError):
            durations.parse_shard_log(log.replace("Description with source context. ... ok", ""), 6)

    def test_legacy_interleaved_stdout_and_split_ok_are_attributed(self) -> None:
        log = fixture(1).replace(
            "test_two (tests.agents.test_beta.Cases.test_two) ... skipped 'fixture'",
            "test_two (tests.agents.test_beta.Cases.test_two) ... fixture output\n"
            + "test-shard (1)\tRun python scripts/run_ci_test_shard.py "
            + "--shard-index 1 --shard-count 8\t"
            + "2026-10-03T00:00:02.0000000Z ok",
        )
        parsed = durations.parse_shard_log(log, 1)
        self.assertEqual(parsed["case_count"], 2)
        self.assertEqual(parsed["seconds_by_module"], {"test_alpha": 1.0, "test_beta": 1.0})

    def test_qualified_runner_output_with_interleaved_text_and_split_ok(self) -> None:
        prefix = (
            "test-shard (1)\tRun python scripts/run_ci_test_shard.py "
            "--shard-index 1 --shard-count 8\t"
        )
        log = fixture(1).replace(
            "test_two (tests.agents.test_beta.Cases.test_two) ... skipped 'fixture'",
            "agents.test_beta.Cases.test_two ... Diagnostic text\n"
            + prefix + "2026-10-03T00:00:02.0000000Z ok",
        )
        parsed = durations.parse_shard_log(log, 1)
        self.assertEqual(parsed["case_count"], 2)
        self.assertEqual(parsed["seconds_by_module"], {"test_alpha": 1.0, "test_beta": 1.0})
        with self.assertRaises(durations.CiShardDurationError):
            durations.parse_shard_log(log.replace("Z ok", "Z not_ok"), 1)

    def test_cli_reads_only_selected_completed_run(self) -> None:
        metadata = run()

        def fake_gh(*args: str) -> str:
            if "--json" in args:
                return json.dumps(metadata)
            job_id = int(args[args.index("--job") + 1])
            return fixture(job_id - 100)

        with (
            patch.object(durations, "_gh", side_effect=fake_gh) as gh,
            patch.object(durations, "discover_function_modules", return_value={}),
            patch("sys.argv", ["proposal", "--run-id", str(RUN_ID), "--repo", "owner/repo"]),
            patch("sys.stdout") as output,
        ):
            self.assertEqual(durations.main(), 0)
        self.assertEqual(gh.call_count, 9)
        self.assertIn('"proposal_only": true', output.write.call_args_list[0].args[0])


if __name__ == "__main__":
    unittest.main()
