from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.evaluation_baseline_adapters import (
    NO_EFFECTS,
    AdapterKind,
    BaselineBudget,
    BaselineObservation,
    BaselineReplayContractError,
    BaselineReplayEnvelope,
    BaselineStatus,
    ContaminationAttestation,
    ContaminationStatus,
    ReplayProvenance,
    ScoringImportStatus,
    build_baseline_observation,
    parse_baseline_replay_envelope,
    replay_baseline_observation,
)
from sunderkey.evaluation_scoring_runtime import (
    METRIC_VALUE_FIELDS,
)
from sunderkey.evaluation_scoring_runtime import ResultStatus as ScoringResultStatus

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-baseline-replay-envelope-v1.schema.json"


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _metrics() -> dict[str, int]:
    values = {field: 1 for field in METRIC_VALUE_FIELDS}
    values.update(
        {
            "completed_evaluation_runs": 1,
            "elapsed_milliseconds_to_first_verified_finding": 10,
            "evaluation_cost_micro_usd": 100,
            "unauthorized_target_actions": 0,
        }
    )
    return values


def _budget(*, unavailable: bool = False) -> BaselineBudget:
    return BaselineBudget(
        maximum_cost_microusd=1_000,
        maximum_latency_ms=5_000,
        maximum_requests=5,
        maximum_tokens=5_000,
        maximum_tool_calls=1,
        used_cost_microusd=0 if unavailable else 100,
        used_latency_ms=0 if unavailable else 10,
        used_requests=0 if unavailable else 1,
        used_tokens=0 if unavailable else 50,
        used_tool_calls=0,
    )


def _contamination(
    status: ContaminationStatus = ContaminationStatus.CLEAN,
) -> ContaminationAttestation:
    return ContaminationAttestation(
        partition_type="public",
        status=status,
        evidence_sha256=_sha("contamination"),
        checker_identity_id="identity-contamination-checker",
        checked_at="2026-09-20T05:00:00Z",
    )


def _provenance() -> ReplayProvenance:
    return ReplayProvenance(
        source_artifact_id="artifact-baseline-capture-1",
        source_artifact_sha256=_sha("source-artifact"),
        custody_manifest_sha256=_sha("custody-manifest"),
        producer_identity_id="identity-baseline-producer",
        captured_at="2026-09-20T05:10:00Z",
    )


def _observation(
    *,
    adapter_kind: AdapterKind = AdapterKind.DETERMINISTIC_RULES,
    subject_role: str = "deterministic",
    status: BaselineStatus = BaselineStatus.COMPLETED,
    contamination: ContaminationAttestation | None = None,
) -> BaselineObservation:
    unavailable = status is BaselineStatus.UNAVAILABLE
    return build_baseline_observation(
        adapter_kind=adapter_kind,
        subject_role=subject_role,
        subject_id=f"baseline-{subject_role}",
        subject_sha256=_sha(f"subject-{subject_role}"),
        subject_owner_identity_id=f"owner-{subject_role}",
        case_id="case-public-001",
        case_sha256=_sha("case-public-001"),
        partition_type="public",
        implementation_id=f"implementation-{adapter_kind.value}",
        implementation_revision="2026.09.20.1",
        implementation_sha256=_sha(f"implementation-{adapter_kind.value}"),
        prompt_sha256=_sha("prompt"),
        policy_sha256=_sha("policy"),
        expected_output_sha256=_sha("expected-output"),
        observed_output_sha256=None if unavailable else _sha("observed-output"),
        tools_allowed=False,
        result_status=status,
        budget=_budget(unavailable=unavailable),
        contamination=contamination or _contamination(),
        evaluator_identity_id="identity-independent-evaluator",
        provenance=_provenance(),
        metric_values=_metrics() if status is BaselineStatus.COMPLETED else None,
    )


def _envelope(observation: BaselineObservation | None = None) -> BaselineReplayEnvelope:
    return replay_baseline_observation(
        observation=observation or _observation(),
        replay_adapter_id="adapter-baseline-replay",
        replay_adapter_revision="1.0.0",
        replay_controller_identity_id="identity-replay-controller",
        replayed_at="2026-09-20T05:20:00Z",
    )


class EvaluationBaselineAdapterTests(unittest.TestCase):
    def test_observation_boolean_or_float_schema_version_is_rejected(self) -> None:
        original = _observation()
        for replacement in (True, 1.0):
            changed = original.to_dict()
            changed["schema_version"] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaises(BaselineReplayContractError):
                    BaselineObservation.from_dict(changed)

    def test_envelope_and_nested_observation_require_integer_schema_versions(self) -> None:
        for location in ("envelope", "observation"):
            for replacement in (True, 1.0):
                changed = _envelope().to_dict()
                node = changed if location == "envelope" else changed["observation"]
                node["schema_version"] = replacement
                for entry in ("mapping", "public_mapping", "json"):
                    with self.subTest(location=location, replacement=replacement, entry=entry):
                        with self.assertRaises(BaselineReplayContractError):
                            if entry == "mapping":
                                BaselineReplayEnvelope.from_dict(changed)
                            elif entry == "public_mapping":
                                parse_baseline_replay_envelope(changed)
                            else:
                                BaselineReplayEnvelope.from_json(
                                    json.dumps(changed, sort_keys=True, separators=(",", ":"))
                                )

    def test_four_adapter_families_replay_deterministically(self) -> None:
        cases = (
            (AdapterKind.DETERMINISTIC_RULES, "deterministic"),
            (AdapterKind.STORED_MODEL_SNAPSHOT, "generalist"),
            (AdapterKind.STRATEGY_VARIANT, "prior_release"),
            (AdapterKind.HUMAN_REFERENCE_INPUT, "generalist"),
        )
        for kind, role in cases:
            with self.subTest(kind=kind):
                observation = _observation(adapter_kind=kind, subject_role=role)
                envelope = _envelope(observation)
                self.assertEqual(envelope, _envelope(observation))
                self.assertEqual(envelope.to_dict()["effects"], dict(NO_EFFECTS))
                self.assertEqual(envelope.to_dict()["qualification_effect"], "none")
                self.assertEqual(observation.scoring_import_status, ScoringImportStatus.AVAILABLE)

    def test_schema_round_trip_and_canonical_json(self) -> None:
        envelope = _envelope()
        raw = envelope.to_dict()
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(raw)
        self.assertEqual(parse_baseline_replay_envelope(raw), envelope)
        self.assertEqual(BaselineReplayEnvelope.from_json(envelope.document_json), envelope)
        self.assertEqual(BaselineObservation.from_dict(raw["observation"]), envelope.observation)

    def test_completed_replay_converts_to_scoring_observation(self) -> None:
        observation = _observation()
        scored = observation.to_scored_observation()
        self.assertEqual(scored.result_status, ScoringResultStatus.COMPLETED)
        self.assertEqual(scored.evidence_manifest_sha256, observation.observation_sha256)
        self.assertEqual(scored.metric_values, _metrics())
        self.assertEqual(scored.budget.used_tool_calls, 0)

    def test_failed_and_unavailable_are_distinct_scoring_states(self) -> None:
        failed = _observation(status=BaselineStatus.FAILED)
        unavailable = _observation(status=BaselineStatus.UNAVAILABLE)
        self.assertEqual(failed.scoring_import_status, ScoringImportStatus.FAILED)
        self.assertEqual(unavailable.scoring_import_status, ScoringImportStatus.UNAVAILABLE)
        self.assertEqual(failed.to_scored_observation().result_status, ScoringResultStatus.FAILED)
        self.assertEqual(
            unavailable.to_scored_observation().result_status,
            ScoringResultStatus.ABSTAINED,
        )
        self.assertIsNotNone(failed.observed_output_sha256)
        self.assertIsNone(unavailable.observed_output_sha256)

    def test_unavailable_rejects_claimed_usage_or_output(self) -> None:
        unavailable = _observation(status=BaselineStatus.UNAVAILABLE)
        with self.assertRaisesRegex(BaselineReplayContractError, "cannot claim output"):
            replace(unavailable, observed_output_sha256=_sha("claimed"))
        with self.assertRaisesRegex(BaselineReplayContractError, "cannot claim usage"):
            replace(unavailable, budget=_budget())

    def test_self_evaluation_and_controller_overlap_fail_closed(self) -> None:
        observation = _observation()
        with self.assertRaisesRegex(BaselineReplayContractError, "overlap"):
            replace(
                observation,
                evaluator_identity_id=observation.subject_owner_identity_id,
            )
        with self.assertRaisesRegex(BaselineReplayContractError, "independent"):
            replay_baseline_observation(
                observation=observation,
                replay_adapter_id="adapter-baseline-replay",
                replay_adapter_revision="1.0.0",
                replay_controller_identity_id=observation.evaluator_identity_id,
                replayed_at="2026-09-20T05:20:00Z",
            )

    def test_tools_and_moving_revisions_are_rejected(self) -> None:
        observation = _observation()
        with self.assertRaisesRegex(BaselineReplayContractError, "tools_allowed"):
            replace(observation, tools_allowed=True)
        values = _budget().to_dict()
        values["used_tool_calls"] = 1
        with self.assertRaisesRegex(BaselineReplayContractError, "forbids tool"):
            BaselineBudget.from_dict(values)
        with self.assertRaisesRegex(BaselineReplayContractError, "exact revision"):
            replace(observation, implementation_revision="latest")

    def test_role_adapter_mismatch_and_candidate_role_are_rejected(self) -> None:
        deterministic = _observation()
        with self.assertRaisesRegex(BaselineReplayContractError, "adapter kind"):
            replace(deterministic, adapter_kind=AdapterKind.STORED_MODEL_SNAPSHOT)
        with self.assertRaisesRegex(BaselineReplayContractError, "baseline role"):
            replace(deterministic, subject_role="candidate")

    def test_contamination_is_explicit_and_blocks_lossy_scoring_import(self) -> None:
        observation = _observation(contamination=_contamination(ContaminationStatus.UNKNOWN))
        self.assertEqual(
            observation.scoring_import_status,
            ScoringImportStatus.BLOCKED_CONTAMINATION,
        )
        with self.assertRaisesRegex(BaselineReplayContractError, "cannot enter scoring"):
            observation.to_scored_observation()

    def test_completed_requires_exact_metrics_and_output(self) -> None:
        observation = _observation()
        with self.assertRaisesRegex(BaselineReplayContractError, "observed output"):
            replace(observation, observed_output_sha256=None)
        missing = dict(_metrics())
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(BaselineReplayContractError, "every exact"):
            replace(observation, metric_values=missing)
        with self.assertRaisesRegex(BaselineReplayContractError, "cannot claim scoring"):
            replace(
                _observation(status=BaselineStatus.FAILED),
                metric_values=_metrics(),
            )

    def test_exact_field_parsing_rejects_credentials_and_unknown_fields(self) -> None:
        raw = _envelope().to_dict()
        raw["provider_api_key"] = "not-allowed"
        with self.assertRaisesRegex(BaselineReplayContractError, "fields"):
            parse_baseline_replay_envelope(raw)
        raw = _envelope().to_dict()
        raw["observation"]["source_path"] = "not-allowed"
        with self.assertRaisesRegex(BaselineReplayContractError, "fields"):
            parse_baseline_replay_envelope(raw)

    def test_tampering_with_nested_provenance_or_status_is_rejected(self) -> None:
        raw = _envelope().to_dict()
        changed = copy.deepcopy(raw)
        changed["observation"]["provenance"]["source_artifact_sha256"] = _sha("changed")
        with self.assertRaisesRegex(BaselineReplayContractError, "identity does not match"):
            parse_baseline_replay_envelope(changed)
        changed = copy.deepcopy(raw)
        changed["observation"]["scoring_import_status"] = "unavailable"
        with self.assertRaisesRegex(BaselineReplayContractError, "status does not match"):
            parse_baseline_replay_envelope(changed)

    def test_noncanonical_json_and_envelope_tampering_are_rejected(self) -> None:
        envelope = _envelope()
        noncanonical = json.dumps(envelope.to_dict(), indent=2, sort_keys=True)
        with self.assertRaisesRegex(BaselineReplayContractError, "not canonical"):
            BaselineReplayEnvelope.from_json(noncanonical)
        raw = envelope.to_dict()
        raw["replayed_at"] = "2026-09-20T05:20:01Z"
        with self.assertRaisesRegex(BaselineReplayContractError, "identity does not match"):
            parse_baseline_replay_envelope(raw)

    def test_public_package_exports_baseline_replay_boundary(self) -> None:
        self.assertIs(
            sunderkey.build_evaluation_baseline_observation,
            build_baseline_observation,
        )
        self.assertIs(
            sunderkey.replay_evaluation_baseline_observation,
            replay_baseline_observation,
        )
        self.assertIs(
            sunderkey.parse_evaluation_baseline_replay_envelope,
            parse_baseline_replay_envelope,
        )


if __name__ == "__main__":
    unittest.main()
