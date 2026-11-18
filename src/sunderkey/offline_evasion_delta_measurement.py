"""Measure supplied integer perturbations and declared label changes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_evasion_delta_measurement"
PROFILE_ID = "AOE-GD-D20-S04"
CAPABILITY_ID = "army.gd.d20.s04"
VECTOR_ID = "AV-GD-D20-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S04"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:fe4405ad53c7655c46d8c5c556ce2a4b1c12ce3a577e75c9f97b701b69be9397"
DOMAIN = "sunderkey.offline-evasion-delta-measurement.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_COORDINATE = 10_000
MAX_L2_SQUARED = 25_600_000_000
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class EvasionDeltaMeasurementError(ValueError):
    """A supplied vector trial or replay is invalid."""


def _integer(value: Any, label: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise EvasionDeltaMeasurementError(f"{label} must be a bounded native integer")
    return value


def _vector(value: Any, label: str) -> list[int]:
    rows = core.bounded_list(value, 64, label)
    if not rows:
        raise EvasionDeltaMeasurementError(f"{label} must not be empty")
    return [
        _integer(item, label, -MAX_COORDINATE, MAX_COORDINATE) for item in rows
    ]


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "model_ref", "maximum_linf_delta",
            "maximum_l2_squared", "trials",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EvasionDeltaMeasurementError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["model_ref"], "model reference")
    _integer(model["maximum_linf_delta"], "L-infinity ceiling", 0, 2 * MAX_COORDINATE)
    _integer(model["maximum_l2_squared"], "L2-squared ceiling", 0, MAX_L2_SQUARED)
    trials = core.bounded_list(model["trials"], 128, "trials")
    if not trials:
        raise EvasionDeltaMeasurementError("Trials must not be empty")
    trial_ids: set[str] = set()
    dimension = None
    for item in trials:
        row = core.exact(
            item,
            {
                "trial_id", "baseline_vector", "candidate_vector", "baseline_label",
                "candidate_label", "evaluation_declared", "context_complete",
            },
            "trial",
        )
        trial_id = core.identifier(row["trial_id"], "trial ID")
        if trial_id in trial_ids:
            raise EvasionDeltaMeasurementError("Duplicate trial ID")
        trial_ids.add(trial_id)
        baseline = _vector(row["baseline_vector"], "baseline vector")
        candidate = _vector(row["candidate_vector"], "candidate vector")
        if len(baseline) != len(candidate):
            raise EvasionDeltaMeasurementError("Paired vector dimensions differ")
        if dimension is None:
            dimension = len(baseline)
        elif len(baseline) != dimension:
            raise EvasionDeltaMeasurementError("Trial vector dimensions differ")
        core.identifier(row["baseline_label"], "baseline label")
        core.identifier(row["candidate_label"], "candidate label")
        core.boolean(row["evaluation_declared"], "evaluation declaration")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for item in model["trials"]:
        deltas = [
            abs(candidate - baseline)
            for baseline, candidate in zip(
                item["baseline_vector"], item["candidate_vector"], strict=True
            )
        ]
        linf = max(deltas)
        l2_squared = sum(delta * delta for delta in deltas)
        changed = sum(delta > 0 for delta in deltas)
        within = (
            linf <= model["maximum_linf_delta"]
            and l2_squared <= model["maximum_l2_squared"]
        )
        if not item["context_complete"] or not item["evaluation_declared"]:
            disposition = "unknown"
        elif item["baseline_label"] == item["candidate_label"]:
            disposition = "declared_label_unchanged"
        elif changed == 0:
            disposition = "unknown_identical_vector_label_conflict"
        elif not within:
            disposition = "declared_label_change_outside_budget"
        else:
            disposition = "candidate_declared_within_budget_label_change"
        projections.append({
            "trial_id": item["trial_id"],
            "linf_delta": linf,
            "l2_squared_delta": l2_squared,
            "changed_coordinate_count": changed,
            "within_declared_budget": within,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "trial_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in projections),
        "model_evaluation_performed": False,
        "input_generation_performed": False,
        "source_authenticated": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Vectors, budgets, labels and evaluation status are caller declarations.",
            "Integer L-infinity and squared-L2 arithmetic avoids floating-point ambiguity.",
            "No model is queried and no candidate input is generated or sent to a target.",
            "Conflicting labels for identical vectors remain unknown, not an evasion candidate.",
            "A candidate is a declared label change, not verified evasion or impact.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EDM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class EvasionDeltaMeasurementReport:
    """Unsigned arithmetic requiring separately retained original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EvasionDeltaMeasurementError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EvasionDeltaMeasurementReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_evasion_deltas(model: Any) -> EvasionDeltaMeasurementReport:
    return EvasionDeltaMeasurementReport._owned(_derive(model))


def verify_supplied_evasion_deltas(
    report: Any, *, model: Any
) -> EvasionDeltaMeasurementReport:
    if type(report) is not EvasionDeltaMeasurementReport:
        raise EvasionDeltaMeasurementError("Exact evasion-delta wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EvasionDeltaMeasurementError("Report differs from separate original model")
    return EvasionDeltaMeasurementReport._owned(expected)


def verify_supplied_evasion_deltas_bytes(
    report_bytes: bytes, *, model: Any
) -> EvasionDeltaMeasurementReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise EvasionDeltaMeasurementError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise EvasionDeltaMeasurementError("Exported report differs from original replay")
    return EvasionDeltaMeasurementReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-evasion-deltas",
        "model_ref": "model-one",
        "maximum_linf_delta": 1,
        "maximum_l2_squared": 1,
        "trials": [
            {
                "trial_id": "within-flip", "baseline_vector": [0, 0],
                "candidate_vector": [1, 0], "baseline_label": "class-a",
                "candidate_label": "class-b", "evaluation_declared": True,
                "context_complete": True,
            },
            {
                "trial_id": "outside-flip", "baseline_vector": [0, 0],
                "candidate_vector": [2, 0], "baseline_label": "class-a",
                "candidate_label": "class-b", "evaluation_declared": True,
                "context_complete": True,
            },
            {
                "trial_id": "no-flip", "baseline_vector": [0, 0],
                "candidate_vector": [1, 0], "baseline_label": "class-a",
                "candidate_label": "class-a", "evaluation_declared": True,
                "context_complete": True,
            },
            {
                "trial_id": "unknown", "baseline_vector": [0, 0],
                "candidate_vector": [1, 0], "baseline_label": "class-a",
                "candidate_label": "class-b", "evaluation_declared": False,
                "context_complete": True,
            },
        ],
    }
