"""Compute bounded integer cadence correlation from two synthetic series."""

from __future__ import annotations

import json
from dataclasses import dataclass
from math import isqrt
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_traffic_cadence_projection"
PROFILE_ID = "AOE-GC-D13-S18"
CAPABILITY_ID = "army.gc.d13.s18"
VECTOR_ID = "AV-GC-D13-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S18"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7c185be20071e08c437b8c16b32a5148933894210224106abc73adecde1720e0"
DOMAIN = "sunderkey.offline-traffic-cadence-projection.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class TrafficCadenceProjectionError(ValueError):
    """The supplied series or original-model replay is invalid."""


def _counts(value: Any) -> list[int]:
    rows = core.bounded_list(value, 64, "bucket counts")
    if len(rows) < 4:
        raise TrafficCadenceProjectionError("At least four buckets are required")
    if any(type(row) is not int or not 0 <= row <= 1000 for row in rows):
        raise TrafficCadenceProjectionError("Counts must be bounded nonnegative integers")
    return rows


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "aligned_equal_duration_buckets_asserted", "threshold_basis_points", "series",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TrafficCadenceProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise TrafficCadenceProjectionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    if not core.boolean(
        model["aligned_equal_duration_buckets_asserted"], "bucket alignment"
    ):
        raise TrafficCadenceProjectionError(
            "Only asserted aligned equal-duration buckets are modeled"
        )
    threshold = model["threshold_basis_points"]
    if type(threshold) is not int or not 0 <= threshold <= 10000:
        raise TrafficCadenceProjectionError("Threshold must be 0 through 10000 basis points")
    series = core.bounded_list(model["series"], 2, "series")
    if len(series) != 2:
        raise TrafficCadenceProjectionError("Exactly two series are required")
    normalized = []
    seen = set()
    for item in series:
        row = core.exact(item, {"series_id", "bucket_counts"}, "series")
        series_id = core.identifier(row["series_id"], "series ID")
        if series_id in seen:
            raise TrafficCadenceProjectionError("Duplicate series ID")
        seen.add(series_id)
        normalized.append((series_id, _counts(row["bucket_counts"])))
    normalized.sort(key=lambda row: row[0])
    left_id, left = normalized[0]
    right_id, right = normalized[1]
    if len(left) != len(right):
        raise TrafficCadenceProjectionError("Series must have equal bucket counts")
    n = len(left)
    sum_left = sum(left)
    sum_right = sum(right)
    covariance = n * sum(a * b for a, b in zip(left, right, strict=True)) - sum_left * sum_right
    variance_left = n * sum(a * a for a in left) - sum_left * sum_left
    variance_right = n * sum(b * b for b in right) - sum_right * sum_right
    zero_variance = variance_left == 0 or variance_right == 0
    score = None if zero_variance else min(
        10000,
        isqrt((covariance * covariance * 100_000_000) // (variance_left * variance_right)),
    )
    unknown = []
    if not complete:
        unknown.append("supplied_traffic_inventory_incomplete")
    if zero_variance:
        unknown.append("zero_variance_prevents_correlation")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "aligned_equal_duration_buckets_asserted": True,
        "series_ids": [left_id, right_id],
        "supplied_bucket_count": n,
        "threshold_basis_points": threshold,
        "absolute_correlation_basis_points": score,
        "correlation_direction": "unknown" if zero_variance else (
            "positive" if covariance > 0 else "negative" if covariance < 0 else "zero"
        ),
        "declared_threshold_met": None if score is None else score >= threshold,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_cadence_arithmetic_projection",
        "source_authenticated": False,
        "traffic_capture_verified": False,
        "channel_identified": False,
        "tunnel_identified": False,
        "exfiltration_inferred": False,
        "network_call_performed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Bucket alignment, equal duration, counts, threshold, and completeness are assertions.",
            "Correlation alone cannot establish a covert channel, tunnel, or causal link.",
            "Only zero-lag count correlation is modeled; payloads and packet data are absent.",
            "No traffic is captured or sent, and no network or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TCP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class TrafficCadenceProjectionReport:
    """Unsigned arithmetic projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TrafficCadenceProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TrafficCadenceProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_traffic_cadence(model: Any) -> TrafficCadenceProjectionReport:
    return TrafficCadenceProjectionReport._owned(_derive(model))


def verify_supplied_traffic_cadence(
    report: Any, *, model: Any
) -> TrafficCadenceProjectionReport:
    if type(report) is not TrafficCadenceProjectionReport:
        raise TrafficCadenceProjectionError("Exact cadence wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise TrafficCadenceProjectionError("Report differs from separate original model")
    return TrafficCadenceProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-traffic-cadence",
        "synthetic_fixture": True, "inventory_complete": True,
        "aligned_equal_duration_buckets_asserted": True,
        "threshold_basis_points": 9000,
        "series": [
            {"series_id": "a", "bucket_counts": [1, 2, 3, 4]},
            {"series_id": "b", "bucket_counts": [2, 4, 6, 8]},
        ],
    }
