"""Project supplied synthetic power recovery-test dates against a pinned cadence."""

from __future__ import annotations

import calendar
import json
from dataclasses import dataclass
from datetime import date
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "industrial_supplied_power_recovery_cadence_review"
PROFILE_ID = "AOE-GD-D19-S09"
CAPABILITY_ID = "army.gd.d19.s09"
VECTOR_ID = "AV-GD-D19-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S09"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:f9c43dda7587e483d7fd710ef497c01b9e47648451de5a9de222e358c3328b7b"
DOMAIN = "sunderkey.offline-power-recovery-cadence-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PowerRecoveryCadenceReviewError(ValueError):
    """A synthetic recovery record or original-model replay is invalid."""


def _date(value: Any, label: str) -> date:
    if type(value) is not str or len(value) != 10:
        raise PowerRecoveryCadenceReviewError(f"ISO {label} date required")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise PowerRecoveryCadenceReviewError(f"Invalid {label} date") from exc
    if parsed.isoformat() != value:
        raise PowerRecoveryCadenceReviewError(f"Canonical {label} date required")
    return parsed


def _months_before(value: date, months: int) -> date:
    month_index = value.year * 12 + value.month - 1 - months
    year, zero_month = divmod(month_index, 12)
    month = zero_month + 1
    if year < 1:
        raise PowerRecoveryCadenceReviewError("Review date is outside supported range")
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "as_of_date",
         "plan_exercise_date", "recovery_information_sample_date",
         "sample_usable_and_compatible_declared"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PowerRecoveryCadenceReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PowerRecoveryCadenceReviewError("Only synthetic fixtures are accepted")
    as_of = _date(model["as_of_date"], "as-of")
    exercise = _date(model["plan_exercise_date"], "plan exercise")
    sample = _date(model["recovery_information_sample_date"], "sample test")
    if exercise > as_of or sample > as_of:
        raise PowerRecoveryCadenceReviewError("Future test date is not evidence")
    if type(model["sample_usable_and_compatible_declared"]) is not bool:
        raise PowerRecoveryCadenceReviewError("Sample declaration must be Boolean")
    cutoff = _months_before(as_of, 15)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "reference_standard": "NERC CIP-009-6 R2.1 and R2.2",
        "as_of_date": as_of.isoformat(),
        "fifteen_calendar_month_cutoff": cutoff.isoformat(),
        "declared_plan_exercise_in_window": exercise >= cutoff,
        "declared_sample_test_in_window": sample >= cutoff,
        "sample_usable_and_compatible_declared": model[
            "sample_usable_and_compatible_declared"
        ],
        "record_review_cues": [
            label for label, present in (
                ("plan_exercise_date_outside_window", exercise >= cutoff),
                ("sample_test_date_outside_window", sample >= cutoff),
                ("sample_usability_or_compatibility_not_declared", model[
                    "sample_usable_and_compatible_declared"
                ]),
            ) if not present
        ],
        "candidate_count": 0,
        "uncertainty": [
            "standard_applicability_and_asset_class_unverified",
            "test_records_and_sample_results_unauthenticated",
            "recovery_capability_and_plan_completeness_unobserved",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "standard_compliance_verified": False,
        "recovery_test_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only supplied synthetic dates are projected against CIP-009-6 R2 cadence.",
            "The responsible entity, applicable BES systems, and current "
            "standard are not established.",
            "Neither a date nor a declared sample result proves test execution or recoverability.",
            "No backup is opened, restored, or tested and no power asset is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PowerRecoveryCadenceReviewReport:
    """Unsigned cadence projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PowerRecoveryCadenceReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PowerRecoveryCadenceReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_power_recovery_cadence(model: Any) -> PowerRecoveryCadenceReviewReport:
    return PowerRecoveryCadenceReviewReport._owned(_derive(model))


def verify_supplied_power_recovery_cadence(
    report: Any, *, model: Any
) -> PowerRecoveryCadenceReviewReport:
    if type(report) is not PowerRecoveryCadenceReviewReport:
        raise PowerRecoveryCadenceReviewError("Exact power recovery wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PowerRecoveryCadenceReviewError("Report differs from separate original model")
    return PowerRecoveryCadenceReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-power-recovery-cadence",
        "synthetic_fixture": True,
        "as_of_date": "2026-10-01",
        "plan_exercise_date": "2025-10-01",
        "recovery_information_sample_date": "2025-09-01",
        "sample_usable_and_compatible_declared": True,
    }
