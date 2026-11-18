"""Project bounded synthetic AIS Class A position-report structure."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "transport_supplied_ais_position_report_projection"
PROFILE_ID = "AOE-GD-D25-S07"
CAPABILITY_ID = "army.gd.d25.s07"
VECTOR_ID = "AV-GD-D25-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:38541247fec61145af4fcc5abd463b0314e731268c7cee841209820daf67ac87"
DOMAIN = "sunderkey.offline-ais-position-report.v1"
MAX_MODEL_BYTES = 2_048
MAX_REPORT_BYTES = 32_768
REPORT_BITS = 168
LON_UNAVAILABLE = 108_600_000
LAT_UNAVAILABLE = 54_600_000
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class AisPositionReportError(ValueError):
    """A supplied AIS model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AisPositionReportError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise AisPositionReportError("Model exceeds byte bound")
    return result


def _signed(value: int, width: int) -> int:
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _take(bits: str, cursor: int, width: int) -> tuple[int, int]:
    return int(bits[cursor:cursor + width], 2), cursor + width


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "report_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AisPositionReportError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise AisPositionReportError("Only synthetic fixtures are accepted")
    encoded = model["report_base64"]
    if type(encoded) is not str or len(encoded) != 28:
        raise AisPositionReportError("A 168-bit base64 report is required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AisPositionReportError("Report base64 is invalid") from exc
    if len(raw) != REPORT_BITS // 8:
        raise AisPositionReportError("Exactly 168 report bits are required")
    bits = "".join(f"{octet:08b}" for octet in raw)
    cursor = 0
    message_id, cursor = _take(bits, cursor, 6)
    repeat_indicator, cursor = _take(bits, cursor, 2)
    source_id, cursor = _take(bits, cursor, 30)
    navigation_status, cursor = _take(bits, cursor, 4)
    rate_of_turn, cursor = _take(bits, cursor, 8)
    speed_over_ground, cursor = _take(bits, cursor, 10)
    position_accuracy, cursor = _take(bits, cursor, 1)
    longitude_bits, cursor = _take(bits, cursor, 28)
    latitude_bits, cursor = _take(bits, cursor, 27)
    course_over_ground, cursor = _take(bits, cursor, 12)
    true_heading, cursor = _take(bits, cursor, 9)
    time_stamp, cursor = _take(bits, cursor, 6)
    special_manoeuvre, cursor = _take(bits, cursor, 2)
    spare, cursor = _take(bits, cursor, 2)
    transmit_power, cursor = _take(bits, cursor, 1)
    raim_flag, cursor = _take(bits, cursor, 1)
    communication_state, cursor = _take(bits, cursor, 19)
    if cursor != REPORT_BITS or message_id not in (1, 2, 3):
        raise AisPositionReportError("Only Class A position reports 1 through 3 are supported")
    longitude = _signed(longitude_bits, 28)
    latitude = _signed(latitude_bits, 27)
    if longitude != LON_UNAVAILABLE and not -108_000_000 <= longitude <= 108_000_000:
        raise AisPositionReportError("Longitude is outside defined range")
    if latitude != LAT_UNAVAILABLE and not -54_000_000 <= latitude <= 54_000_000:
        raise AisPositionReportError("Latitude is outside defined range")
    if course_over_ground > 3_600 or 360 <= true_heading <= 510 or spare:
        raise AisPositionReportError("Reserved course, heading or spare bits")
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
        "source_report_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "synthetic_fixture_asserted": True,
        "message_id": message_id,
        "repeat_indicator": repeat_indicator,
        "source_id_sha256": "sha256:" + hashlib.sha256(
            source_id.to_bytes(4, "big")
        ).hexdigest(),
        "navigation_status_code": navigation_status,
        "rate_of_turn_available": rate_of_turn != 128,
        "speed_over_ground_available": speed_over_ground != 1023,
        "longitude_available": longitude != LON_UNAVAILABLE,
        "latitude_available": latitude != LAT_UNAVAILABLE,
        "course_over_ground_available": course_over_ground != 3600,
        "true_heading_available": true_heading != 511,
        "reported_position_accuracy_bit": position_accuracy,
        "time_stamp_code": time_stamp,
        "special_manoeuvre_code": special_manoeuvre,
        "transmit_power_code": transmit_power,
        "reported_raim_flag": raim_flag,
        "communication_state_sha256": "sha256:" + hashlib.sha256(
            communication_state.to_bytes(3, "big")
        ).hexdigest(),
        "report_geometry_valid": True,
        "vessel_identity_verified": False,
        "position_accuracy_verified": False,
        "navigation_state_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "radio_capture_and_sender_identity_unverified",
            "position_and_raim_claims_not_independently_validated",
            "vessel_state_and_navigation_safety_unassessed",
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
            "Only a synthetic supplied 168-bit AIS position report is inspected.",
            "Source ID and coordinate values are not retained in the report.",
            "Reported accuracy and RAIM bits are unverified claims, not safety evidence.",
            "No radio data is acquired or transmitted, and no vessel is identified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="APR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class AisPositionReport:
    """Unsigned AIS projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AisPositionReportError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AisPositionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ais_position_report(model: Any) -> AisPositionReport:
    return AisPositionReport._owned(_derive(model))


def verify_supplied_ais_position_report(
    report: Any, *, model: Any
) -> AisPositionReport:
    if type(report) is not AisPositionReport:
        raise AisPositionReportError("Exact AIS wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AisPositionReportError("Report differs from separate original model")
    return AisPositionReport._owned(expected)


def component_fixture() -> dict:
    fields = (
        (1, 6), (0, 2), (123456789, 30), (15, 4), (128, 8), (1023, 10),
        (0, 1), (LON_UNAVAILABLE, 28), (LAT_UNAVAILABLE, 27), (3600, 12),
        (511, 9), (60, 6), (0, 2), (0, 2), (0, 1), (0, 1), (0, 19),
    )
    bits = "".join(f"{value:0{width}b}" for value, width in fields)
    assert len(bits) == REPORT_BITS
    raw = int(bits, 2).to_bytes(REPORT_BITS // 8, "big")
    return {
        "schema_version": 1,
        "source_id": "synthetic-ais-position-report",
        "synthetic_fixture": True,
        "report_base64": base64.b64encode(raw).decode("ascii"),
    }
