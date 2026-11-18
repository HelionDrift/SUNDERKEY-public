from __future__ import annotations

import copy
import itertools
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.evaluation_program_contracts import (
    CORPUS_PARTITIONS,
    CRITICAL_FAILURE_GATES,
    NO_EFFECTS,
    SCENARIO_VARIANTS,
    SCORECARD_MEASURES,
    SUBJECT_ROLES,
    EvaluationProgramContract,
    EvaluationProgramContractError,
    build_evaluation_program_contract,
    canonical_sha256,
    recommended_comparison_policy,
    recommended_metric_definitions,
    verify_evaluation_program_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-program-contract-v1.schema.json"


def _sha(index: int) -> str:
    return "sha256:" + format(index % 16, "x") * 64


def _inputs() -> dict[str, object]:
    governance = {
        "candidate_identity_id": "identity-candidate",
        "corpus_custodian_identity_id": "identity-corpus-custodian",
        "evaluator_identity_ids": ["identity-evaluator-a", "identity-evaluator-b"],
        "execution_controller_identity_id": "identity-execution-controller",
        "ground_truth_custodian_identity_id": "identity-ground-truth-custodian",
        "plan_author_identity_id": "identity-plan-author",
    }
    partitions = []
    for index, partition in enumerate(CORPUS_PARTITIONS, start=1):
        private = partition != "public"
        prefix = "vaultref" if private else "artifactref"
        partitions.append(
            {
                "case_count": 10,
                "content_sha256": _sha(index + 8),
                "content_reference": f"{prefix}:corpus-{partition}",
                "ground_truth_reference": f"{prefix}:truth-{partition}",
                "ground_truth_sha256": _sha(index + 5),
                "manifest_sha256": _sha(index + 1),
                "membership_commitment_sha256": _sha(index + 9),
                "partition_type": partition,
                "provenance_sha256": _sha(index + 2),
                "secrecy": "reference_only" if private else "public_manifest",
                "suite_id": f"suite-{partition}",
                "suite_version": "1.0.0",
                "variant_ids": list(SCENARIO_VARIANTS),
            }
        )
    provenance = [
        {
            "custodian_identity_id": "identity-corpus-custodian",
            "derivation_sha256": _sha(index + 3),
            "partition_type": partition,
            "recorded_at": "2026-09-20T00:00:00Z",
            "source_id": f"source-{partition}",
            "source_sha256": _sha(index + 4),
            "source_version": "1.0.0",
        }
        for index, partition in enumerate(CORPUS_PARTITIONS, start=1)
    ]
    for partition, provenance_record in zip(partitions, provenance, strict=True):
        partition["provenance_sha256"] = canonical_sha256(provenance_record)
    contamination = [
        {
            "candidate_identity_id": "identity-candidate",
            "check_version": "1.0.0",
            "checked_at": "2026-09-20T01:00:00Z",
            "evidence_sha256": _sha(index + 7),
            "overlap_count": 0,
            "partition_type": partition,
            "status": "clean",
        }
        for index, partition in enumerate(CORPUS_PARTITIONS, start=1)
    ]
    overlaps = [
        {
            "checked_at": "2026-09-20T02:00:00Z",
            "checker_identity_id": "identity-ground-truth-custodian",
            "evidence_sha256": _sha(index),
            "left_partition_type": left,
            "overlap_count": 0,
            "right_partition_type": right,
            "scanner_version": "1.0.0",
        }
        for index, (left, right) in enumerate(
            itertools.combinations(CORPUS_PARTITIONS, 2), start=1
        )
    ]
    subjects = [
        {
            "artifact_sha256": _sha(index + 1),
            "configuration_sha256": _sha(index + 6),
            "owner_identity_id": (
                "identity-candidate" if role == "candidate" else f"identity-owner-{role}"
            ),
            "role": role,
            "subject_id": f"subject-{role}",
            "subject_version": "1.0.0",
        }
        for index, role in enumerate(SUBJECT_ROLES, start=1)
    ]
    bindings = [
        {
            "assignment_reference": f"vaultref:assignment-{suffix}",
            "assignment_sha256": _sha(index + 2),
            "binding_version": "1.0.0",
            "evaluator_identity_id": f"identity-evaluator-{suffix}",
            "partition_aliases": [f"blind-{suffix}-partition-{item}" for item in range(5)],
            "revealed_private_partition_references": [],
            "revealed_subject_roles": [],
            "subject_aliases": [f"blind-{suffix}-subject-{item}" for item in range(4)],
        }
        for index, suffix in enumerate(("a", "b"), start=1)
    ]
    pins = [
        {
            "artifact_sha256": _sha(index + 4),
            "component_id": component,
            "component_version": "1.0.0",
        }
        for index, component in enumerate(
            (
                "capability_roadmap",
                "evaluation_policy",
                "qualification_plans",
                "qualification_standard",
                "specialist_scenario_corpus",
            ),
            start=1,
        )
    ]
    return {
        "blind_evaluator_bindings": bindings,
        "budget": {
            "maximum_cases": 50,
            "maximum_cost_microusd": 10_000_000,
            "maximum_requests": 100,
            "maximum_tokens": 100_000,
            "maximum_wall_seconds": 3_600,
        },
        "comparison_policy": recommended_comparison_policy(),
        "contamination_records": contamination,
        "corpus_version": "1.0.0",
        "exposure_records": [
            {
                "access_status": "active",
                "evidence_sha256": _sha(15),
                "exposed_at": "2026-09-20T03:00:00Z",
                "exposed_identity_id": "identity-corpus-custodian",
                "exposure_scope": "full_content",
                "partition_type": "private_holdout",
            }
        ],
        "governance": governance,
        "metrics": recommended_metric_definitions(),
        "overlap_attestations": overlaps,
        "partitions": partitions,
        "plan_version": "1.0.0",
        "program_version": "1.0.0",
        "provenance": provenance,
        "scorecard_version": "1.0.0",
        "subjects": subjects,
        "version_pins": pins,
    }


def _contract() -> EvaluationProgramContract:
    return build_evaluation_program_contract(**_inputs())  # type: ignore[arg-type]


class EvaluationProgramContractTests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.build_evaluation_program_contract,
            build_evaluation_program_contract,
        )
        self.assertIs(
            sunderkey.verify_evaluation_program_contract,
            verify_evaluation_program_contract,
        )

    def test_round_trip_is_deterministic_and_schema_valid(self) -> None:
        contract = _contract()
        verify_evaluation_program_contract(contract)
        self.assertEqual(contract, EvaluationProgramContract.from_json(contract.document_json))
        self.assertEqual(contract, build_evaluation_program_contract(**_inputs()))  # type: ignore[arg-type]
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(contract.to_dict())

    def test_complete_roadmap_measure_variant_and_gate_sets_are_bound(self) -> None:
        raw = _contract().to_dict()
        self.assertEqual(
            tuple(item["measure_id"] for item in raw["scorecard"]["metrics"]),
            SCORECARD_MEASURES,
        )
        self.assertEqual(
            tuple(raw["scorecard"]["critical_failure_gate_ids"]), CRITICAL_FAILURE_GATES
        )
        self.assertTrue(
            all(
                tuple(partition["variant_ids"]) == SCENARIO_VARIANTS
                for partition in raw["corpus"]["partitions"]
            )
        )
        self.assertEqual(raw["effects"], dict(NO_EFFECTS))

    def test_missing_metric_and_critical_gate_fail_closed(self) -> None:
        inputs = _inputs()
        inputs["metrics"] = list(inputs["metrics"])[:-1]  # type: ignore[arg-type]
        with self.assertRaisesRegex(EvaluationProgramContractError, "eleven"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        metrics = copy.deepcopy(inputs["metrics"])
        metrics[8]["critical_gate_ids"] = []  # type: ignore[index]
        inputs["metrics"] = metrics
        with self.assertRaisesRegex(EvaluationProgramContractError, "critical gates"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_denominator_ambiguity_and_metric_gaming_fail_closed(self) -> None:
        inputs = _inputs()
        metrics = copy.deepcopy(inputs["metrics"])
        metrics[0]["denominator"] = metrics[0]["numerator"]  # type: ignore[index]
        inputs["metrics"] = metrics
        with self.assertRaisesRegex(EvaluationProgramContractError, "denominator"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        metrics = copy.deepcopy(inputs["metrics"])
        metrics[0]["anti_gaming_controls"] = []  # type: ignore[index]
        inputs["metrics"] = metrics
        with self.assertRaisesRegex(EvaluationProgramContractError, "anti-gaming"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_private_holdout_must_remain_reference_only(self) -> None:
        inputs = _inputs()
        partitions = copy.deepcopy(inputs["partitions"])
        partitions[1]["content_reference"] = "artifactref:private-inline"  # type: ignore[index]
        inputs["partitions"] = partitions
        with self.assertRaisesRegex(EvaluationProgramContractError, "vaultref"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        partitions = copy.deepcopy(inputs["partitions"])
        partitions[1]["secrecy"] = "public_manifest"  # type: ignore[index]
        inputs["partitions"] = partitions
        with self.assertRaisesRegex(EvaluationProgramContractError, "secrecy"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_contamination_overlap_and_leakage_fail_closed(self) -> None:
        inputs = _inputs()
        partitions = copy.deepcopy(inputs["partitions"])
        partitions[0]["provenance_sha256"] = _sha(15)  # type: ignore[index]
        inputs["partitions"] = partitions
        with self.assertRaisesRegex(EvaluationProgramContractError, "provenance digest"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        records = copy.deepcopy(inputs["contamination_records"])
        records[1]["overlap_count"] = 1  # type: ignore[index]
        records[1]["status"] = "contaminated"  # type: ignore[index]
        inputs["contamination_records"] = records
        with self.assertRaisesRegex(EvaluationProgramContractError, "contamination"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        overlaps = copy.deepcopy(inputs["overlap_attestations"])
        overlaps[0]["overlap_count"] = 1  # type: ignore[index]
        inputs["overlap_attestations"] = overlaps
        with self.assertRaisesRegex(EvaluationProgramContractError, "overlap"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        exposures = copy.deepcopy(inputs["exposure_records"])
        exposures[0]["exposed_identity_id"] = "identity-candidate"  # type: ignore[index]
        inputs["exposure_records"] = exposures
        with self.assertRaisesRegex(EvaluationProgramContractError, "leakage"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_identity_separation_and_blinding_fail_closed(self) -> None:
        inputs = _inputs()
        governance = copy.deepcopy(inputs["governance"])
        governance["evaluator_identity_ids"][0] = governance["candidate_identity_id"]  # type: ignore[index]
        inputs["governance"] = governance
        with self.assertRaisesRegex(EvaluationProgramContractError, "distinct"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        bindings = copy.deepcopy(inputs["blind_evaluator_bindings"])
        bindings[0]["revealed_subject_roles"] = ["candidate"]  # type: ignore[index]
        inputs["blind_evaluator_bindings"] = bindings
        with self.assertRaisesRegex(EvaluationProgramContractError, "reveals"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_moving_versions_and_incomplete_budget_fail_closed(self) -> None:
        inputs = _inputs()
        subjects = copy.deepcopy(inputs["subjects"])
        subjects[3]["subject_version"] = "latest"  # type: ignore[index]
        inputs["subjects"] = subjects
        with self.assertRaisesRegex(EvaluationProgramContractError, "exact immutable"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

        inputs = _inputs()
        budget = copy.deepcopy(inputs["budget"])
        budget["maximum_cases"] = 49  # type: ignore[index]
        inputs["budget"] = budget
        with self.assertRaisesRegex(EvaluationProgramContractError, "complete corpus"):
            build_evaluation_program_contract(**inputs)  # type: ignore[arg-type]

    def test_plan_cannot_claim_results_and_hash_tampering_is_rejected(self) -> None:
        raw = _contract().to_dict()
        raw["evaluation_plan"]["result_claims"] = ["candidate_passed"]
        with self.assertRaisesRegex(EvaluationProgramContractError, "cannot claim"):
            EvaluationProgramContract.from_dict(raw)

        raw = _contract().to_dict()
        raw["corpus"]["partitions"][0]["case_count"] += 1
        with self.assertRaises(EvaluationProgramContractError):
            EvaluationProgramContract.from_dict(raw)


if __name__ == "__main__":
    unittest.main()
