"""Separate caller access assertions must agree with replayed synthetic evidence."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_sdk import load_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.offline_api_access_expectations import (
    OfflineApiAccessExpectationError,
    bind_offline_api_case_to_access_expectations,
    bind_offline_api_retest_to_access_expectations,
    build_offline_api_access_expectations,
    verify_offline_api_access_expectation_binding,
    verify_offline_api_access_expectations,
    verify_offline_api_retest_expectation_binding,
)
from sunderkey.offline_api_assessment import (
    OfflineApiCaseSource,
    evaluate_offline_api_case,
)
from sunderkey.reference_adapters import build_reference_adapters
from tests.agents.test_offline_api_assessment import invocation, response

ROOT = Path(__file__).resolve().parents[2]


class OfflineApiAccessExpectationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            ROOT / "registry" / "candidate-implementation-strategy-v1.json"
        )
        catalog = load_candidate_adapter_catalog(
            ROOT / "registry" / "candidate-adapters-reference-v1.json",
            strategy,
            load_blueprints(),
            ROOT,
        )
        cls.adapter = build_reference_adapters(catalog)["AOE-GB-D06-S09"]

    def fixture(self):
        records = (
            response("owner", "principal.owner", True, 200, b'"owner-data"'),
            response("other", "principal.other", False, 200, b'"owner-data"'),
        )
        run = invocation(self.adapter, records)
        case = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.access.001",
            invocation=run,
            evidence=records,
        )
        source = OfflineApiCaseSource("case.access.001", run, records, case.to_dict())
        expectations = build_offline_api_access_expectations(
            expectation_id="expectation.001",
            mission_id=run.mission_id,
            target_id=run.target_id,
            scope_id=run.scope_id,
            object_id="object.7",
            action="read",
            principal_expectations=[
                {"principal_id": "principal.other", "expected_access": False},
                {"principal_id": "principal.owner", "expected_access": True},
            ],
        )
        return source, expectations

    def test_exact_policy_binding_is_reproducible_and_non_authorizing(self) -> None:
        source, expectations = self.fixture()
        self.assertEqual(verify_offline_api_access_expectations(expectations), expectations)
        binding = bind_offline_api_case_to_access_expectations(
            adapter=self.adapter, source=source, expectations=expectations
        )
        self.assertEqual(
            verify_offline_api_access_expectation_binding(
                adapter=self.adapter,
                source=source,
                expectations=expectations,
                binding=binding,
            ),
            binding,
        )
        self.assertEqual(binding["principal_count"], 2)
        self.assertEqual(binding["case_result_sha256"], source.result["result_sha256"])
        self.assertFalse(binding["target_authorization_verified"])
        self.assertFalse(binding["pre_observation_commitment_verified"])
        self.assertEqual(binding["effects"]["target_interaction"], "none")

    def test_changed_expectation_labels_and_context_are_rejected(self) -> None:
        source, expectations = self.fixture()
        changed = copy.deepcopy(expectations)
        changed["principal_expectations"][0]["expected_access"] = True
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "does not match"):
            verify_offline_api_access_expectations(changed)
        changed = build_offline_api_access_expectations(
            expectation_id="expectation.002",
            mission_id=source.invocation.mission_id,
            target_id=source.invocation.target_id,
            scope_id=source.invocation.scope_id,
            object_id="object.7",
            action="read",
            principal_expectations=[
                {"principal_id": "principal.other", "expected_access": True},
                {"principal_id": "principal.owner", "expected_access": True},
            ],
        )
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "expected_access"):
            bind_offline_api_case_to_access_expectations(
                adapter=self.adapter, source=source, expectations=changed
            )
        changed = copy.deepcopy(expectations)
        changed["target_id"] = "other.target"
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "does not match"):
            bind_offline_api_case_to_access_expectations(
                adapter=self.adapter, source=source, expectations=changed
            )

    def test_missing_extra_duplicate_and_unsorted_principals_are_rejected(self) -> None:
        source, expectations = self.fixture()
        args = {
            key: expectations[key]
            for key in (
                "expectation_id", "mission_id", "target_id", "scope_id",
                "object_id", "action",
            )
        }
        for principals in (
            list(reversed(expectations["principal_expectations"])),
            [expectations["principal_expectations"][0]] * 2,
        ):
            with self.assertRaisesRegex(OfflineApiAccessExpectationError, "sorted and unique"):
                build_offline_api_access_expectations(
                    **args, principal_expectations=principals
                )
        missing = build_offline_api_access_expectations(
            **args,
            principal_expectations=[expectations["principal_expectations"][0]],
        )
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "not declared"):
            bind_offline_api_case_to_access_expectations(
                adapter=self.adapter, source=source, expectations=missing
            )
        extra = build_offline_api_access_expectations(
            **args,
            principal_expectations=[
                {"principal_id": "principal.extra", "expected_access": False},
                *expectations["principal_expectations"],
            ],
        )
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "no evidence"):
            bind_offline_api_case_to_access_expectations(
                adapter=self.adapter, source=source, expectations=extra
            )

    def test_replayed_case_and_binding_claim_tampering_are_rejected(self) -> None:
        source, expectations = self.fixture()
        binding = bind_offline_api_case_to_access_expectations(
            adapter=self.adapter, source=source, expectations=expectations
        )
        changed = copy.deepcopy(binding)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "does not match"):
            verify_offline_api_access_expectation_binding(
                adapter=self.adapter, source=source, expectations=expectations,
                binding=changed,
            )
        forged = OfflineApiCaseSource(
            source.case_id,
            source.invocation,
            source.evidence,
            {**source.result, "disposition": "negative_synthetic_result"},
        )
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "replay failed"):
            bind_offline_api_case_to_access_expectations(
                adapter=self.adapter, source=forged, expectations=expectations
            )

    def test_retest_binding_uses_one_expectation_set_for_both_cases(self) -> None:
        prior, expectations = self.fixture()
        second_records = (
            response("owner-second", "principal.owner", True, 200, b'"owner-data"'),
            response("other-second", "principal.other", False, 403, b'"denied"'),
        )
        second_run = replace(
            invocation(self.adapter, second_records),
            invocation_id="INV-SYNTHETIC-API-002",
        )
        second_result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.access.002",
            invocation=second_run,
            evidence=second_records,
        )
        second = OfflineApiCaseSource(
            "case.access.002", second_run, second_records, second_result.to_dict()
        )
        binding = bind_offline_api_retest_to_access_expectations(
            adapter=self.adapter,
            prior_source=prior,
            second_source=second,
            expectations=expectations,
        )
        self.assertEqual(
            binding["observation_change"],
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertFalse(binding["pre_observation_commitment_verified"])
        self.assertEqual(
            verify_offline_api_retest_expectation_binding(
                adapter=self.adapter,
                prior_source=prior,
                second_source=second,
                expectations=expectations,
                binding=binding,
            ),
            binding,
        )
        changed = copy.deepcopy(binding)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "does not match"):
            verify_offline_api_retest_expectation_binding(
                adapter=self.adapter,
                prior_source=prior,
                second_source=second,
                expectations=expectations,
                binding=changed,
            )
        changed_expectations = build_offline_api_access_expectations(
            expectation_id="expectation.changed",
            mission_id=prior.invocation.mission_id,
            target_id=prior.invocation.target_id,
            scope_id=prior.invocation.scope_id,
            object_id="object.7",
            action="read",
            principal_expectations=expectations["principal_expectations"],
        )
        with self.assertRaisesRegex(OfflineApiAccessExpectationError, "does not match"):
            verify_offline_api_retest_expectation_binding(
                adapter=self.adapter,
                prior_source=prior,
                second_source=second,
                expectations=changed_expectations,
                binding=binding,
            )


if __name__ == "__main__":
    unittest.main()
