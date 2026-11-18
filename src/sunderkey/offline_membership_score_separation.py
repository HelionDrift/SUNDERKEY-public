"""Measure declared membership-score separation with exact integer counts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_membership_score_separation"
PROFILE_ID = "AOE-GD-D20-S06"
CAPABILITY_ID = "army.gd.d20.s06"
VECTOR_ID = "AV-GD-D20-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S06"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:2b2b3c3134be4c577110b91f4e35cd0f0e0c1aaff099a272f7e9fb76395cdd1e"
DOMAIN = "sunderkey.offline-membership-score-separation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class MembershipScoreSeparationError(ValueError):
    """A supplied score distribution or replay is invalid."""


def _scores(value: Any, label: str) -> list[int]:
    scores = core.bounded_list(value, 256, label)
    if not scores:
        raise MembershipScoreSeparationError(f"{label} must not be empty")
    if any(type(score) is not int or not 0 <= score <= 10_000 for score in scores):
        raise MembershipScoreSeparationError("Scores must be integer basis points")
    return scores


def _model(value: Any) -> tuple[dict, str, list[int], list[int]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "member_group_id",
            "nonmember_group_id",
            "threshold_basis_points",
            "minimum_samples_per_group",
            "minimum_advantage_basis_points",
            "same_scoring_conditions",
            "member_scores_basis_points",
            "nonmember_scores_basis_points",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MembershipScoreSeparationError("Unsupported model version")
    for key in ("source_id", "member_group_id", "nonmember_group_id"):
        core.identifier(model[key], key)
    if model["member_group_id"] == model["nonmember_group_id"]:
        raise MembershipScoreSeparationError("Group identifiers must differ")
    for key in ("threshold_basis_points", "minimum_advantage_basis_points"):
        if type(model[key]) is not int or not 0 <= model[key] <= 10_000:
            raise MembershipScoreSeparationError("Thresholds must be integer basis points")
    minimum = model["minimum_samples_per_group"]
    if type(minimum) is not int or not 1 <= minimum <= 256:
        raise MembershipScoreSeparationError("Minimum sample count is invalid")
    core.boolean(model["same_scoring_conditions"], "same scoring conditions")
    members = _scores(model["member_scores_basis_points"], "member scores")
    nonmembers = _scores(model["nonmember_scores_basis_points"], "nonmember scores")
    return model, core.canonical(model), members, nonmembers


def _derive(value: Any) -> dict:
    model, model_text, members, nonmembers = _model(value)
    threshold = model["threshold_basis_points"]
    member_positive = sum(score >= threshold for score in members)
    nonmember_positive = sum(score >= threshold for score in nonmembers)
    numerator = member_positive * len(nonmembers) - nonmember_positive * len(members)
    denominator = len(members) * len(nonmembers)
    enough = min(len(members), len(nonmembers)) >= model["minimum_samples_per_group"]
    exceeds = (
        numerator > 0 and numerator * 10_000 > model["minimum_advantage_basis_points"] * denominator
    )
    disposition = (
        "unknown"
        if not enough or not model["same_scoring_conditions"]
        else "candidate_declared_membership_separation"
        if exceeds
        else "no_declared_membership_separation"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "member_count": len(members),
        "nonmember_count": len(nonmembers),
        "member_positive_count": member_positive,
        "nonmember_positive_count": nonmember_positive,
        "rate_advantage_numerator": numerator,
        "rate_advantage_denominator": denominator,
        "disposition": disposition,
        "candidate_count": int(disposition.startswith("candidate_")),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "model_queried": False,
        "individual_membership_inferred": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Scores, group membership and equal scoring conditions are caller-supplied.",
            "The caller selects a threshold, so selection bias and calibration are not measured.",
            "Aggregate rate separation does not infer individual membership or prove disclosure.",
            "No model, training record, provider or target is queried.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MSS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class MembershipScoreSeparationReport:
    """Unsigned aggregate projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MembershipScoreSeparationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MembershipScoreSeparationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_membership_scores(model: Any) -> MembershipScoreSeparationReport:
    return MembershipScoreSeparationReport._owned(_derive(model))


def verify_supplied_membership_scores(
    report: Any, *, model: Any
) -> MembershipScoreSeparationReport:
    if type(report) is not MembershipScoreSeparationReport:
        raise MembershipScoreSeparationError("Exact score-separation wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MembershipScoreSeparationError("Report differs from separate original model")
    return MembershipScoreSeparationReport._owned(expected)


def verify_supplied_membership_scores_bytes(
    report_bytes: bytes, *, model: Any
) -> MembershipScoreSeparationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise MembershipScoreSeparationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise MembershipScoreSeparationError("Exported report differs from original replay")
    return MembershipScoreSeparationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-membership-scores",
        "member_group_id": "members",
        "nonmember_group_id": "nonmembers",
        "threshold_basis_points": 6_000,
        "minimum_samples_per_group": 3,
        "minimum_advantage_basis_points": 2_000,
        "same_scoring_conditions": True,
        "member_scores_basis_points": [9_000, 8_000, 7_000, 2_000],
        "nonmember_scores_basis_points": [1_000, 3_000, 5_000, 7_000],
    }
