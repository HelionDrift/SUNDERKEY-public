"""Compare supplied training label shares with exact integer arithmetic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "training_supplied_label_share_drift"
PROFILE_ID = "AOE-GD-D20-S02"
CAPABILITY_ID = "army.gd.d20.s02"
VECTOR_ID = "AV-GD-D20-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S02"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:ae8d0aaabe676ab5ec9e6083f98b6b28f39047d22fe6fdbb901528bc1eb1e5d4"
DOMAIN = "sunderkey.offline-training-label-drift.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_COUNT = 100_000
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class TrainingLabelDriftError(ValueError):
    """A supplied training distribution or replay is invalid."""


def _counts(value: Any, label: str) -> dict[str, int]:
    rows = core.bounded_list(value, 32, label)
    if not rows:
        raise TrainingLabelDriftError(f"{label} must not be empty")
    result: dict[str, int] = {}
    for item in rows:
        row = core.exact(item, {"label_id", "count"}, label)
        label_id = core.identifier(row["label_id"], "label ID")
        if label_id in result:
            raise TrainingLabelDriftError("Duplicate label ID")
        count = row["count"]
        if type(count) is not int or not 0 <= count <= MAX_COUNT:
            raise TrainingLabelDriftError("Label count must be a bounded native integer")
        result[label_id] = count
    if sum(result.values()) == 0:
        raise TrainingLabelDriftError("Dataset total must be positive")
    return result


def _model(value: Any) -> tuple[dict, str, dict[str, int], dict[str, int]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "baseline_dataset_id", "candidate_dataset_id",
            "maximum_share_delta_basis_points", "declaration_complete",
            "baseline_counts", "candidate_counts",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TrainingLabelDriftError("Unsupported model version")
    for key in ("source_id", "baseline_dataset_id", "candidate_dataset_id"):
        core.identifier(model[key], key)
    if model["baseline_dataset_id"] == model["candidate_dataset_id"]:
        raise TrainingLabelDriftError("Dataset identifiers must differ")
    threshold = model["maximum_share_delta_basis_points"]
    if type(threshold) is not int or not 0 <= threshold <= 10_000:
        raise TrainingLabelDriftError("Share delta limit must be basis points")
    core.boolean(model["declaration_complete"], "declaration completeness")
    baseline = _counts(model["baseline_counts"], "baseline counts")
    candidate = _counts(model["candidate_counts"], "candidate counts")
    return model, core.canonical(model), baseline, candidate


def _derive(value: Any) -> dict:
    model, model_text, baseline, candidate = _model(value)
    baseline_total = sum(baseline.values())
    candidate_total = sum(candidate.values())
    denominator = baseline_total * candidate_total
    threshold = model["maximum_share_delta_basis_points"]
    projections = []
    for label_id in sorted(set(baseline) | set(candidate)):
        first = baseline.get(label_id, 0)
        second = candidate.get(label_id, 0)
        numerator = abs(second * baseline_total - first * candidate_total) * 10_000
        exceeds = numerator > threshold * denominator
        disposition = (
            "unknown"
            if not model["declaration_complete"] else
            "candidate_declared_label_share_drift"
            if exceeds else "within_declared_share_limit"
        )
        projections.append({
            "label_id": label_id,
            "baseline_count": first,
            "candidate_count": second,
            "absolute_share_delta_numerator": numerator,
            "absolute_share_delta_denominator": denominator,
            "exceeds_declared_limit": exceeds,
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "baseline_total": baseline_total,
        "candidate_total": candidate_total,
        "label_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "training_data_read": False,
        "model_training_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Counts, dataset identity and completeness are caller-supplied declarations.",
            "Exact share arithmetic does not explain legitimate distribution shifts.",
            "No record, training data, model or provider is read or trained.",
            "A candidate is declared drift, not observed data poisoning.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TLD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class TrainingLabelDriftReport:
    """Unsigned distribution projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TrainingLabelDriftError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TrainingLabelDriftReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_training_label_drift(model: Any) -> TrainingLabelDriftReport:
    return TrainingLabelDriftReport._owned(_derive(model))


def verify_supplied_training_label_drift(
    report: Any, *, model: Any
) -> TrainingLabelDriftReport:
    if type(report) is not TrainingLabelDriftReport:
        raise TrainingLabelDriftError("Exact label-drift wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise TrainingLabelDriftError("Report differs from separate original model")
    return TrainingLabelDriftReport._owned(expected)


def verify_supplied_training_label_drift_bytes(
    report_bytes: bytes, *, model: Any
) -> TrainingLabelDriftReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise TrainingLabelDriftError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise TrainingLabelDriftError("Exported report differs from original replay")
    return TrainingLabelDriftReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-training-labels",
        "baseline_dataset_id": "dataset-before",
        "candidate_dataset_id": "dataset-after",
        "maximum_share_delta_basis_points": 1_000,
        "declaration_complete": True,
        "baseline_counts": [
            {"label_id": "class-a", "count": 80},
            {"label_id": "class-b", "count": 20},
        ],
        "candidate_counts": [
            {"label_id": "class-a", "count": 60},
            {"label_id": "class-b", "count": 40},
        ],
    }
