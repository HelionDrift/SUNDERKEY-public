"""Inspect one supplied synthetic OSDP poll frame without device I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_osdp_poll_frame_review"
PROFILE_ID = "AOE-GA-D02-S10"
CAPABILITY_ID = "army.ga.d02.s10"
VECTOR_ID = "AV-GA-D02-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S10"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c0404ad7eec7a3f3dd6b6ba57df62179ba73fbfbd8f2aca27da23619e35fa803"
DOMAIN = "sunderkey.offline-osdp-poll-frame-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
HEX = re.compile(r"[0-9a-f]{14}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OsdpPollFrameReviewError(ValueError):
    """A synthetic OSDP frame declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise OsdpPollFrameReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise OsdpPollFrameReviewError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "frame_hex",
         "expected_pd_address"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OsdpPollFrameReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise OsdpPollFrameReviewError("Only synthetic fixtures are accepted")
    expected_address = model["expected_pd_address"]
    if type(expected_address) is not int or not 1 <= expected_address <= 126:
        raise OsdpPollFrameReviewError("Bounded peripheral address required")
    frame_hex = model["frame_hex"]
    if type(frame_hex) is not str or HEX.fullmatch(frame_hex) is None:
        raise OsdpPollFrameReviewError("Seven lowercase frame bytes required")
    frame = bytes.fromhex(frame_hex)
    address = frame[1]
    length = frame[2] | (frame[3] << 8)
    control = frame[4]
    if (frame[0] != 0x53 or not 1 <= address <= 126 or length != len(frame)
            or control & 0xFC or frame[5] != 0x60):
        raise OsdpPollFrameReviewError("Plain OSDP CMD_POLL frame required")
    if sum(frame) & 0xFF:
        raise OsdpPollFrameReviewError("OSDP checksum does not balance")
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
        "frame_sha256": "sha256:" + hashlib.sha256(frame).hexdigest(),
        "frame_length": len(frame),
        "peripheral_address": address,
        "address_matches_supplied_expectation": address == expected_address,
        "sequence_number": control & 0x03,
        "checksum_consistent": True,
        "command_code": "CMD_POLL",
        "secure_channel_observed": False,
        "badge_read_observed": False,
        "access_granted_observed": False,
        "frame_transmitted": False,
        "candidate_count": 0,
        "uncertainty": [
            "frame_origin_unverified",
            "reader_and_badge_state_unobserved",
            "access_decision_unobserved",
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
            "Only one synthetic plain OSDP CMD_POLL envelope is checked.",
            "Checksum agreement does not authenticate origin or prove secure channel.",
            "No badge data, access decision, reader state, or physical entry is observed.",
            "No OSDP frame is transmitted and no device is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OPR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OsdpPollFrameReviewReport:
    """Unsigned OSDP envelope projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OsdpPollFrameReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OsdpPollFrameReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_osdp_poll_frame(model: Any) -> OsdpPollFrameReviewReport:
    return OsdpPollFrameReviewReport._owned(_derive(model))


def verify_supplied_osdp_poll_frame(
    report: Any, *, model: Any
) -> OsdpPollFrameReviewReport:
    if type(report) is not OsdpPollFrameReviewReport:
        raise OsdpPollFrameReviewError("Exact OSDP wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OsdpPollFrameReviewError("Report differs from separate original model")
    return OsdpPollFrameReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-osdp-poll-frame",
        "synthetic_fixture": True,
        "frame_hex": "53010700006045",
        "expected_pd_address": 1,
    }
