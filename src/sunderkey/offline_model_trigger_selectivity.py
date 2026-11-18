"""Compare supplied clean and trigger-conditioned model outcomes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_trigger_selectivity"
PROFILE_ID = "AOE-GD-D20-S03"
CAPABILITY_ID = "army.gd.d20.s03"
VECTOR_ID = "AV-GD-D20-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S03"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:f0e7175268b81cf7e39d876b37d8d649fd87cdfeb2f61bfc30119ebbbf2ed773"
DOMAIN = "sunderkey.offline-model-trigger-selectivity.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_TRIALS = 100_000
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class ModelTriggerSelectivityError(ValueError):
    """A supplied trigger outcome model or replay is invalid."""


def _integer(value: Any, label: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ModelTriggerSelectivityError(f"{label} must be a bounded native integer")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "model_ref", "minimum_samples_per_group",
            "minimum_rate_gap_basis_points", "comparisons",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ModelTriggerSelectivityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["model_ref"], "model reference")
    _integer(model["minimum_samples_per_group"], "sample minimum", 1, MAX_TRIALS)
    _integer(model["minimum_rate_gap_basis_points"], "rate gap", 0, 10_000)
    comparisons = core.bounded_list(model["comparisons"], 128, "comparisons")
    if not comparisons:
        raise ModelTriggerSelectivityError("Comparisons must not be empty")
    seen: set[str] = set()
    for item in comparisons:
        row = core.exact(
            item,
            {
                "comparison_id", "target_label", "clean_trials", "clean_target_count",
                "trigger_trials", "trigger_target_count", "comparability_declared",
                "context_complete",
            },
            "comparison",
        )
        comparison_id = core.identifier(row["comparison_id"], "comparison ID")
        if comparison_id in seen:
            raise ModelTriggerSelectivityError("Duplicate comparison ID")
        seen.add(comparison_id)
        core.identifier(row["target_label"], "target label")
        clean_trials = _integer(row["clean_trials"], "clean trials", 1, MAX_TRIALS)
        trigger_trials = _integer(row["trigger_trials"], "trigger trials", 1, MAX_TRIALS)
        _integer(row["clean_target_count"], "clean target count", 0, clean_trials)
        _integer(row["trigger_target_count"], "trigger target count", 0, trigger_trials)
        core.boolean(row["comparability_declared"], "comparability")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    threshold = model["minimum_rate_gap_basis_points"]
    minimum = model["minimum_samples_per_group"]
    for item in model["comparisons"]:
        denominator = item["clean_trials"] * item["trigger_trials"]
        numerator = (
            item["trigger_target_count"] * item["clean_trials"]
            - item["clean_target_count"] * item["trigger_trials"]
        ) * 10_000
        enough = item["clean_trials"] >= minimum and item["trigger_trials"] >= minimum
        exceeds = numerator > threshold * denominator
        if not item["context_complete"] or not item["comparability_declared"]:
            disposition = "unknown"
        elif not enough:
            disposition = "unknown_insufficient_samples"
        elif exceeds:
            disposition = "candidate_declared_trigger_selectivity"
        else:
            disposition = "within_declared_rate_gap"
        projections.append({
            "comparison_id": item["comparison_id"],
            "target_label": item["target_label"],
            "clean_trials": item["clean_trials"],
            "clean_target_count": item["clean_target_count"],
            "trigger_trials": item["trigger_trials"],
            "trigger_target_count": item["trigger_target_count"],
            "signed_rate_gap_numerator_basis_points": numerator,
            "rate_gap_denominator": denominator,
            "minimum_samples_met": enough,
            "exceeds_declared_rate_gap": exceeds,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "comparison_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in projections),
        "source_authenticated": False,
        "model_evaluation_performed": False,
        "trigger_generation_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Counts, labels, grouping and comparability are caller declarations.",
            "A rate gap may reflect benign distribution shift or test-design bias.",
            "No trigger content is accepted and no model is evaluated or modified.",
            "A candidate is statistical selectivity, not proof of a backdoor or poisoning.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MTS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ModelTriggerSelectivityReport:
    """Unsigned rate projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ModelTriggerSelectivityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ModelTriggerSelectivityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_model_trigger_selectivity(model: Any) -> ModelTriggerSelectivityReport:
    return ModelTriggerSelectivityReport._owned(_derive(model))


def verify_supplied_model_trigger_selectivity(
    report: Any, *, model: Any
) -> ModelTriggerSelectivityReport:
    if type(report) is not ModelTriggerSelectivityReport:
        raise ModelTriggerSelectivityError("Exact trigger-selectivity wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ModelTriggerSelectivityError("Report differs from separate original model")
    return ModelTriggerSelectivityReport._owned(expected)


def verify_supplied_model_trigger_selectivity_bytes(
    report_bytes: bytes, *, model: Any
) -> ModelTriggerSelectivityReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ModelTriggerSelectivityError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ModelTriggerSelectivityError("Exported report differs from original replay")
    return ModelTriggerSelectivityReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-trigger-selectivity",
        "model_ref": "model-one",
        "minimum_samples_per_group": 10,
        "minimum_rate_gap_basis_points": 5_000,
        "comparisons": [
            {
                "comparison_id": "large-gap", "target_label": "class-b",
                "clean_trials": 100, "clean_target_count": 1,
                "trigger_trials": 100, "trigger_target_count": 80,
                "comparability_declared": True, "context_complete": True,
            },
            {
                "comparison_id": "small-gap", "target_label": "class-b",
                "clean_trials": 100, "clean_target_count": 2,
                "trigger_trials": 100, "trigger_target_count": 3,
                "comparability_declared": True, "context_complete": True,
            },
            {
                "comparison_id": "few-samples", "target_label": "class-b",
                "clean_trials": 4, "clean_target_count": 0,
                "trigger_trials": 4, "trigger_target_count": 4,
                "comparability_declared": True, "context_complete": True,
            },
            {
                "comparison_id": "unknown", "target_label": "class-b",
                "clean_trials": 100, "clean_target_count": 1,
                "trigger_trials": 100, "trigger_target_count": 80,
                "comparability_declared": False, "context_complete": True,
            },
        ],
    }
