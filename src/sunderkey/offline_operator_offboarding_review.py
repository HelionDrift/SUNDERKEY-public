"""Review a supplied synthetic offboarding and privileged-event chronology."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_operator_offboarding_review"
PROFILE_ID = "AOE-GA-D02-S13"
CAPABILITY_ID = "army.ga.d02.s13"
VECTOR_ID = "AV-GA-D02-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S13"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GA-D02-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:aedcfa6ebd8164febd2958903b584b1bf048c20c5e46fe20957cfebedfeb6b32"
DOMAIN = "sunderkey.offline-operator-offboarding-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OperatorOffboardingReviewError(ValueError):
    """A synthetic offboarding record or original-model replay is invalid."""


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or UTC_SECOND.fullmatch(value) is None:
        raise OperatorOffboardingReviewError(f"UTC-second {label} time required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperatorOffboardingReviewError(f"Invalid {label} time") from exc


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "person_ref",
         "account_ref", "termination_time", "account_disable_time",
         "privileged_event_time", "event_source"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OperatorOffboardingReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise OperatorOffboardingReviewError("Only synthetic fixtures are accepted")
    person = core.identifier(model["person_ref"], "person reference")
    account = core.identifier(model["account_ref"], "account reference")
    if model["event_source"] != "synthetic-privileged-audit":
        raise OperatorOffboardingReviewError("Closed synthetic event source required")
    termination = _utc(model["termination_time"], "termination")
    disable = _utc(model["account_disable_time"], "account disable")
    event = _utc(model["privileged_event_time"], "privileged event")
    after_termination = event > termination
    after_disable = event > disable
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
        "person_ref_sha256": _digest(person),
        "account_ref_sha256": _digest(account),
        "event_after_declared_termination": after_termination,
        "event_after_declared_disable": after_disable,
        "disable_after_declared_termination": disable > termination,
        "record_review_cues": [
            label for label, present in (
                ("privileged_event_after_termination", after_termination),
                ("privileged_event_after_account_disable", after_disable),
            ) if present
        ],
        "candidate_count": 0,
        "uncertainty": [
            "employment_and_account_records_unauthenticated",
            "event_origin_and_clock_alignment_unverified",
            "person_account_binding_and_authorized_exception_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "insider_activity_verified": False,
        "account_control_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only three declared synthetic timestamps and two opaque references are compared.",
            "A sequence difference is not proof of account use or insider intent.",
            "Source authenticity, clock alignment, authorized exceptions, and "
            "account ownership are unknown.",
            "No personnel record, account, or audit service is queried or changed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OOR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OperatorOffboardingReviewReport:
    """Unsigned chronology projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OperatorOffboardingReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OperatorOffboardingReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_operator_offboarding(model: Any) -> OperatorOffboardingReviewReport:
    return OperatorOffboardingReviewReport._owned(_derive(model))


def verify_supplied_operator_offboarding(
    report: Any, *, model: Any
) -> OperatorOffboardingReviewReport:
    if type(report) is not OperatorOffboardingReviewReport:
        raise OperatorOffboardingReviewError("Exact operator offboarding wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OperatorOffboardingReviewError("Report differs from separate original model")
    return OperatorOffboardingReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-operator-offboarding",
        "synthetic_fixture": True,
        "person_ref": "synthetic-person-001",
        "account_ref": "synthetic-account-001",
        "termination_time": "2026-01-01T00:00:00Z",
        "account_disable_time": "2026-01-01T01:00:00Z",
        "privileged_event_time": "2026-01-01T00:30:00Z",
        "event_source": "synthetic-privileged-audit",
    }
