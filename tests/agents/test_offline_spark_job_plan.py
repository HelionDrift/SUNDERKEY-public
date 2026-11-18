"""Supplied Spark job arithmetic does not prove cluster behavior or access."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_spark_job_plan import (
    SparkJobPlan,
    SparkJobPlanError,
    analyze_supplied_spark_job_plan,
    verify_supplied_spark_job_plan,
)

ROOT = Path(__file__).resolve().parents[2]


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    datasets = [_ref("dataset", letter) for letter in "cdef"]
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-spark-job-plan-v1",
        "declarations_complete": False,
        "policy": {
            "max_executor_cores": 4,
            "max_executor_memory_mib": 8192,
            "max_executors": 10,
            "max_total_cores": 20,
            "max_total_memory_mib": 81920,
        },
        "datasets": [
            {"dataset_ref": datasets[0], "tenant_ref": tenant_a},
            {"dataset_ref": datasets[1], "tenant_ref": tenant_b},
            {"dataset_ref": datasets[2], "tenant_ref": tenant_b},
            {"dataset_ref": datasets[3], "tenant_ref": tenant_a},
        ],
        "jobs": [
            {
                "job_id": "mixed-job",
                "run_as_tenant_ref": tenant_a,
                "input_dataset_refs": [datasets[0], datasets[1]],
                "output_dataset_ref": datasets[2],
                "executor_cores": 6,
                "executor_memory_mib": 4096,
                "executors": 5,
            },
            {
                "job_id": "aligned-job",
                "run_as_tenant_ref": tenant_a,
                "input_dataset_refs": [datasets[0]],
                "output_dataset_ref": datasets[3],
                "executor_cores": 2,
                "executor_memory_mib": 2048,
                "executors": 2,
            },
            {
                "job_id": "resource-job",
                "run_as_tenant_ref": tenant_a,
                "input_dataset_refs": [datasets[0]],
                "output_dataset_ref": datasets[3],
                "executor_cores": 4,
                "executor_memory_mib": 8192,
                "executors": 10,
            },
        ],
    }


class SparkJobPlanTests(unittest.TestCase):
    def test_tenant_resource_and_unknown_declarations(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_spark_job_plan(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_tenant_and_resource_mismatch",
                "unknown_incomplete_declarations",
                "declared_resource_mismatch",
            ],
        )
        self.assertEqual(
            findings[0]["mismatched_input_refs"],
            [source["datasets"][1]["dataset_ref"]],
        )
        self.assertTrue(findings[0]["output_tenant_mismatch"])
        self.assertEqual(
            findings[0]["exceeded_policy_limits"],
            ["max_executor_cores", "max_total_cores"],
        )
        self.assertEqual(findings[0]["requested_total_cores"], 30)
        self.assertEqual(findings[2]["exceeded_policy_limits"], ["max_total_cores"])
        self.assertFalse(report.to_dict()["flags"]["job_executed"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_spark_job_plan(report, model=source).to_json(),
            report.to_json(),
        )
        source["declarations_complete"] = True
        self.assertEqual(
            analyze_supplied_spark_job_plan(source).to_dict()["findings"][1]["disposition"],
            "no_supplied_mismatch",
        )

    def test_invalid_inputs_and_resource_types_refused(self) -> None:
        source = model()
        source["jobs"][0]["input_dataset_refs"].append(source["jobs"][0]["input_dataset_refs"][0])
        with self.assertRaises(SparkJobPlanError):
            analyze_supplied_spark_job_plan(source)
        source = model()
        source["jobs"][0]["input_dataset_refs"] = [["not-hashable"]]
        with self.assertRaises(SparkJobPlanError):
            analyze_supplied_spark_job_plan(source)
        source = model()
        source["jobs"][0]["executor_cores"] = True
        with self.assertRaises(SparkJobPlanError):
            analyze_supplied_spark_job_plan(source)
        source = model()
        source["jobs"][0]["output_dataset_ref"] = _ref("dataset", "0")
        with self.assertRaises(SparkJobPlanError):
            analyze_supplied_spark_job_plan(source)
        source = model()
        source["jobs"][1]["job_id"] = "mixed-job"
        with self.assertRaises(SparkJobPlanError):
            analyze_supplied_spark_job_plan(source)

    def test_tampering_and_changed_source_refused(self) -> None:
        source = model()
        report = analyze_supplied_spark_job_plan(source)
        tampered = report.to_dict()
        tampered["flags"]["job_executed"] = True
        with self.assertRaises(SparkJobPlanError):
            SparkJobPlan(tampered)
        source["jobs"][0]["executors"] = 4
        with self.assertRaises(SparkJobPlanError):
            verify_supplied_spark_job_plan(report, model=source)

    def test_closed_component_dispatch_and_resource_denial(self) -> None:
        request = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-spark-job-plan-component.json"
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(
            result["analysis"]["findings"][0]["disposition"],
            "declared_tenant_and_resource_mismatch",
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            components.verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        request["resources"]["network"] = ["forbidden"]
        with self.assertRaises(components.OfflineSpecialistComponentError):
            components.run_offline_specialist_component(
                request, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
