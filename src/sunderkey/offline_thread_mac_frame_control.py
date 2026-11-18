"""Project supplied synthetic IEEE 802.15.4 frame-control declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_thread_mac_frame_control_projection"
PROFILE_ID = "AOE-GD-D18-S14"
CAPABILITY_ID = "army.gd.d18.s14"
VECTOR_ID = "AV-GD-D18-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S14"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c3448e7349ff8a4d624b9528a874cadabfaef2c90bdf039ba3bac51b83dc7222"
DOMAIN = "sunderkey.offline-thread-mac-frame-control.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_WORDS = 64
HEX_WORD = re.compile(r"[0-9a-fA-F]{4}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class ThreadMacFrameControlError(ValueError):
    """A supplied frame-control model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture", "word_inventory_complete",
            "require_data_security_bit", "words",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ThreadMacFrameControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise ThreadMacFrameControlError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["word_inventory_complete"], "word inventory")
    require_security = core.boolean(
        model["require_data_security_bit"], "data security policy"
    )
    rows = []
    seen = set()
    for item in core.bounded_list(model["words"], MAX_WORDS, "words"):
        row = core.exact(item, {"word_id", "frame_control_le_hex"}, "word")
        word_id = core.identifier(row["word_id"], "word ID")
        if word_id in seen:
            raise ThreadMacFrameControlError("Duplicate word ID")
        seen.add(word_id)
        raw = row["frame_control_le_hex"]
        if type(raw) is not str or HEX_WORD.fullmatch(raw) is None:
            raise ThreadMacFrameControlError("Frame control must be exactly two hex bytes")
        field = int.from_bytes(bytes.fromhex(raw), "little")
        frame_type = field & 0x7
        security_bit = bool(field & (1 << 3))
        ack_bit = bool(field & (1 << 5))
        destination_mode = (field >> 10) & 0x3
        version = (field >> 12) & 0x3
        source_mode = (field >> 14) & 0x3
        unsupported = []
        if frame_type not in {0, 1, 2, 3, 5}:
            unsupported.append("unsupported_frame_type")
        if version not in {0, 1, 2}:
            unsupported.append("unsupported_frame_version")
        if destination_mode == 1 or source_mode == 1:
            unsupported.append("reserved_address_mode")
        outside_policy = frame_type == 1 and require_security and not security_bit
        rows.append({
            "word_id": word_id,
            "frame_type": frame_type,
            "security_enabled_bit_declared": security_bit,
            "ack_requested_bit_declared": ack_bit,
            "destination_address_mode": destination_mode,
            "source_address_mode": source_mode,
            "frame_version": version,
            "outside_supplied_data_security_policy": outside_policy,
            "unsupported_fields": unsupported,
        })
    if not rows:
        raise ThreadMacFrameControlError("At least one frame-control word is required")
    rows.sort(key=lambda row: row["word_id"])
    uncertainty = []
    if not complete:
        uncertainty.append("supplied_word_inventory_incomplete")
    if any(row["unsupported_fields"] for row in rows):
        uncertainty.append("one_or_more_unsupported_field_values")
    flagged = [
        row["word_id"] for row in rows
        if row["outside_supplied_data_security_policy"]
    ]
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
        "word_inventory_complete_asserted": complete,
        "require_data_security_bit_asserted": require_security,
        "word_projections": rows,
        "outside_supplied_policy_word_ids": flagged,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_mac_header_policy_projection",
        "source_authenticated": False,
        "complete_mac_frame_parsed": False,
        "mic_verified": False,
        "thread_membership_verified": False,
        "matter_behavior_verified": False,
        "radio_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Words and policy are synthetic caller-supplied assertions.",
            "Only the two-byte frame-control word is projected, not a full MAC frame.",
            "A security-enabled bit does not prove encryption, MIC validity or key use.",
            "No Thread membership, Matter behavior or radio interaction is established.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TFC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ThreadMacFrameControlReport:
    """Unsigned header projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ThreadMacFrameControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ThreadMacFrameControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_thread_frame_control(model: Any) -> ThreadMacFrameControlReport:
    return ThreadMacFrameControlReport._owned(_derive(model))


def verify_supplied_thread_frame_control(
    report: Any, *, model: Any
) -> ThreadMacFrameControlReport:
    if type(report) is not ThreadMacFrameControlReport:
        raise ThreadMacFrameControlError("Exact frame-control wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ThreadMacFrameControlError("Report differs from separate original model")
    return ThreadMacFrameControlReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-thread-frame-control",
        "synthetic_fixture": True,
        "word_inventory_complete": True,
        "require_data_security_bit": True,
        "words": [
            {"word_id": "secured-data", "frame_control_le_hex": "29a8"},
            {"word_id": "unsecured-data", "frame_control_le_hex": "21a8"},
        ],
    }
