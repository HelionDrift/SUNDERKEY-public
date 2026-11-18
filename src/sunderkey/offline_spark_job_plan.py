"""Project supplied Spark job tenancy and resource declarations offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_spark_job_plan"
PROFILE_ID = "AOE-GB-D07-S10"
CAPABILITY_ID = "army.gb.d07.s10"
VECTOR_ID = "AV-GB-D07-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:1fba5fcf78cf7703665e8d8aae0d37c66af32c9d59bda5f7041ec4ae9621e0df"
SEMANTICS_PROFILE = "supplied-spark-job-plan-v1"
DOMAIN = "sunderkey.offline-spark-job-plan.v1"
MAX_DATASETS = 128
MAX_JOBS = 16
MAX_INPUTS_PER_JOB = 64
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DATASET = re.compile(r"dataset:sha256:[0-9a-f]{64}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "cluster",
        "credential",
        "data_movement",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class SparkJobPlanError(ValueError):
    """A supplied Spark plan or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise SparkJobPlanError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise SparkJobPlanError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise SparkJobPlanError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise SparkJobPlanError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise SparkJobPlanError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise SparkJobPlanError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise SparkJobPlanError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise SparkJobPlanError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SparkJobPlanError(f"{label} must be an opaque digest reference")
    return value


def _positive(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise SparkJobPlanError(f"{label} must be a bounded positive integer")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version", "semantics_profile", "declarations_complete",
            "policy", "datasets", "jobs",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SparkJobPlanError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise SparkJobPlanError("Semantics profile is invalid")
    if type(model["declarations_complete"]) is not bool:
        raise SparkJobPlanError("Completeness must be an exact boolean")
    policy = model["policy"]
    limits = {
        "max_executor_cores": 1024,
        "max_executor_memory_mib": 1_048_576,
        "max_executors": 16_384,
        "max_total_cores": 16_777_216,
        "max_total_memory_mib": 17_179_869_184,
    }
    _fields(policy, set(limits), "policy")
    for key, maximum in limits.items():
        _positive(policy[key], maximum, key)
    datasets = model["datasets"]
    jobs = model["jobs"]
    if type(datasets) is not list or not 1 <= len(datasets) <= MAX_DATASETS:
        raise SparkJobPlanError("Dataset count is invalid")
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        raise SparkJobPlanError("Job count is invalid")
    known: set[str] = set()
    for row in datasets:
        _fields(row, {"dataset_ref", "tenant_ref"}, "dataset")
        dataset = _ref(row["dataset_ref"], _DATASET, "Dataset")
        if dataset in known:
            raise SparkJobPlanError("Duplicate dataset reference")
        known.add(dataset)
        _ref(row["tenant_ref"], _TENANT, "Dataset tenant")
    job_ids: set[str] = set()
    for row in jobs:
        _fields(
            row,
            {
                "job_id", "run_as_tenant_ref", "input_dataset_refs", "output_dataset_ref",
                "executor_cores", "executor_memory_mib", "executors",
            },
            "job",
        )
        job_id = row["job_id"]
        if type(job_id) is not str or _ID.fullmatch(job_id) is None or job_id in job_ids:
            raise SparkJobPlanError("Job identifier is invalid or duplicated")
        job_ids.add(job_id)
        _ref(row["run_as_tenant_ref"], _TENANT, "Job tenant")
        inputs = row["input_dataset_refs"]
        if type(inputs) is not list or not 1 <= len(inputs) <= MAX_INPUTS_PER_JOB:
            raise SparkJobPlanError("Job input count is invalid")
        checked_inputs = []
        for item in inputs:
            dataset_ref = _ref(item, _DATASET, "Job input")
            if dataset_ref not in known:
                raise SparkJobPlanError("Job input is undeclared")
            checked_inputs.append(dataset_ref)
        if len(set(checked_inputs)) != len(checked_inputs):
            raise SparkJobPlanError("Duplicate job input")
        if _ref(row["output_dataset_ref"], _DATASET, "Job output") not in known:
            raise SparkJobPlanError("Job output is undeclared")
        _positive(row["executor_cores"], 1024, "Executor cores")
        _positive(row["executor_memory_mib"], 1_048_576, "Executor memory")
        _positive(row["executors"], 16_384, "Executor count")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    datasets = {row["dataset_ref"]: row["tenant_ref"] for row in plan["datasets"]}
    policy = plan["policy"]
    findings = []
    for job in plan["jobs"]:
        tenant = job["run_as_tenant_ref"]
        mismatched_inputs = sorted(
            item for item in job["input_dataset_refs"] if datasets[item] != tenant
        )
        output_mismatch = datasets[job["output_dataset_ref"]] != tenant
        total_cores = job["executor_cores"] * job["executors"]
        total_memory = job["executor_memory_mib"] * job["executors"]
        exceeded = [
            key
            for key, actual in (
                ("max_executor_cores", job["executor_cores"]),
                ("max_executor_memory_mib", job["executor_memory_mib"]),
                ("max_executors", job["executors"]),
                ("max_total_cores", total_cores),
                ("max_total_memory_mib", total_memory),
            )
            if actual > policy[key]
        ]
        tenant_mismatch = bool(mismatched_inputs or output_mismatch)
        if tenant_mismatch and exceeded:
            disposition = "declared_tenant_and_resource_mismatch"
        elif tenant_mismatch:
            disposition = "declared_tenant_mismatch"
        elif exceeded:
            disposition = "declared_resource_mismatch"
        elif plan["declarations_complete"]:
            disposition = "no_supplied_mismatch"
        else:
            disposition = "unknown_incomplete_declarations"
        findings.append(
            {
                "job_id": job["job_id"],
                "disposition": disposition,
                "mismatched_input_refs": mismatched_inputs,
                "output_tenant_mismatch": output_mismatch,
                "exceeded_policy_limits": exceeded,
                "requested_total_cores": total_cores,
                "requested_total_memory_mib": total_memory,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "cluster_policy_verified": False,
            "dataset_tenancy_verified": False,
            "job_executed": False,
            "data_access_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Jobs, dataset tags, limits, and completeness are caller-supplied.",
            "Resource arithmetic is a declared request comparison, not scheduler behavior.",
            "Tenant mismatch does not prove effective access or data processing.",
            "No Spark, Hadoop, provider, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "SJP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class SparkJobPlan:
    """Immutable report replayed from a supplied Spark job model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise SparkJobPlanError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise SparkJobPlanError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_spark_job_plan(model: Any) -> SparkJobPlan:
    """Compare a supplied job plan with supplied dataset and policy labels."""
    return SparkJobPlan(_derive(model))


def verify_supplied_spark_job_plan(report: Any, *, model: Any) -> SparkJobPlan:
    if type(report) is not SparkJobPlan:
        raise SparkJobPlanError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise SparkJobPlanError("Report differs from supplied model replay")
    return SparkJobPlan(expected)
