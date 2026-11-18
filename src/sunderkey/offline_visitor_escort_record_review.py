"""Compare supplied synthetic visitor records with declared escort requirements."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_visitor_escort_record_review"
PROFILE_ID = "AOE-GA-D02-S09"
CAPABILITY_ID = "army.ga.d02.s09"
VECTOR_ID = "AV-GA-D02-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S09"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ca0f50b3f6af9f047750d3180151523ec7d395afd877b6ffffac859af6475daa"
DOMAIN = "sunderkey.offline-visitor-escort-record-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VISITOR = re.compile(r"visitor-[0-9]{2}\Z")
ESCORT = re.compile(r"escort-[0-9]{2}\Z")
ENTRY = re.compile(r"door-[a-z]\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class VisitorEscortRecordReviewError(ValueError):
    """A synthetic visitor record declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise VisitorEscortRecordReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise VisitorEscortRecordReviewError("Model exceeds byte bound")
    return result


def _time(value: Any) -> datetime:
    if type(value) is not str or UTC_SECOND.fullmatch(value) is None:
        raise VisitorEscortRecordReviewError("UTC second timestamp required")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VisitorEscortRecordReviewError("Invalid visitor timestamp") from exc


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "controlled_entries",
         "visits"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VisitorEscortRecordReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise VisitorEscortRecordReviewError("Only synthetic fixtures are accepted")
    entries = model["controlled_entries"]
    if (type(entries) is not list or not 1 <= len(entries) <= 8
            or any(type(item) is not str or ENTRY.fullmatch(item) is None
                   for item in entries)
            or len(set(entries)) != len(entries)):
        raise VisitorEscortRecordReviewError("Distinct controlled entry IDs required")
    visits = model["visits"]
    if type(visits) is not list or not 1 <= len(visits) <= 8:
        raise VisitorEscortRecordReviewError("One to eight visitor records required")
    seen = set()
    rows = []
    for item in visits:
        row = core.exact(
            item,
            {"visitor_id", "entry_id", "entry_time_utc", "exit_time_utc",
             "escort_required", "escort_id"},
            "visit",
        )
        visitor = row["visitor_id"]
        if (type(visitor) is not str or VISITOR.fullmatch(visitor) is None
                or visitor in seen or row["entry_id"] not in entries
                or type(row["escort_required"]) is not bool):
            raise VisitorEscortRecordReviewError("Distinct synthetic visitor record required")
        seen.add(visitor)
        entry_time = _time(row["entry_time_utc"])
        exit_value = row["exit_time_utc"]
        if exit_value is not None and _time(exit_value) <= entry_time:
            raise VisitorEscortRecordReviewError("Exit must follow entry")
        escort = row["escort_id"]
        if escort is not None and (
            type(escort) is not str or ESCORT.fullmatch(escort) is None
        ):
            raise VisitorEscortRecordReviewError("Synthetic escort ID required")
        rows.append({
            "visitor_id_sha256": _hash(visitor),
            "entry_id": row["entry_id"],
            "escort_required": row["escort_required"],
            "escort_recorded": escort is not None,
            "exit_recorded": exit_value is not None,
            "declared_escort_gap": row["escort_required"] and escort is None,
        })
    gaps = sum(row["declared_escort_gap"] for row in rows)
    open_visits = sum(not row["exit_recorded"] for row in rows)
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "controlled_entry_count": len(entries),
        "visitor_record_count": len(rows),
        "declared_escort_gap_count": gaps,
        "missing_exit_record_count": open_visits,
        "record_projections": rows,
        "tailgating_observed": False,
        "escort_presence_verified": False,
        "physical_entry_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "visitor_records_and_entry_policy_unverified",
            "escort_presence_and_physical_entry_unobserved",
            "tailgating_unobservable_from_supplied_records",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only bounded synthetic PE-3 and PE-8 visitor-record fields are compared.",
            "An omitted escort or exit field is a declared record gap, not an access breach.",
            "No person, escort, camera, sensor, badge, or physical entry is observed.",
            "No facility visit, tailgating test, or contact occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VER-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class VisitorEscortRecordReviewReport:
    """Unsigned visitor-record projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VisitorEscortRecordReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VisitorEscortRecordReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_visitor_escort_records(model: Any) -> VisitorEscortRecordReviewReport:
    return VisitorEscortRecordReviewReport._owned(_derive(model))


def verify_supplied_visitor_escort_records(
    report: Any, *, model: Any
) -> VisitorEscortRecordReviewReport:
    if type(report) is not VisitorEscortRecordReviewReport:
        raise VisitorEscortRecordReviewError("Exact visitor wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VisitorEscortRecordReviewError("Report differs from separate original model")
    return VisitorEscortRecordReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-visitor-escort-records",
        "synthetic_fixture": True,
        "controlled_entries": ["door-a", "door-b"],
        "visits": [
            {
                "visitor_id": "visitor-01",
                "entry_id": "door-a",
                "entry_time_utc": "2026-01-01T10:00:00Z",
                "exit_time_utc": "2026-01-01T10:30:00Z",
                "escort_required": True,
                "escort_id": "escort-01",
            },
            {
                "visitor_id": "visitor-02",
                "entry_id": "door-b",
                "entry_time_utc": "2026-01-01T11:00:00Z",
                "exit_time_utc": None,
                "escort_required": True,
                "escort_id": None,
            },
        ],
    }
