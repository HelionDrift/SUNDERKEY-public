"""Compare bounded supplied frames with an explicitly supplied framing hypothesis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_custom_protocol_framing"
PROFILE_ID = "AOE-GE-D22-S12"
CAPABILITY_ID = "army.ge.d22.s12"
VECTOR_ID = "AV-GE-D22-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S12"
WAVE_ID = "IW2-025"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:66ef13d8a670d68bb0141e7ba9c5c9ea58cca1f6d7b25f7bd133c60ba8a4557a"
DOMAIN = "sunderkey.offline-custom-protocol-framing.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_FRAMES = 64
MAX_WIRE_BYTES = 256
HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class CustomProtocolFramingError(ValueError):
    """The supplied framing model or original-model replay is invalid."""


def _index(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 255:
        raise CustomProtocolFramingError(f"{label} must be a bounded native integer")
    return value


def _model(value: Any) -> tuple[dict, dict, list[tuple[str, str, bytes]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "capture_inventory_complete", "framing", "frames"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CustomProtocolFramingError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["capture_inventory_complete"], "capture completeness")
    framing = core.exact(
        model["framing"],
        {
            "kind_offset", "kind_width", "length_offset", "length_width",
            "length_endian", "payload_offset",
        },
        "framing",
    )
    kind_offset = _index(framing["kind_offset"], "kind offset")
    length_offset = _index(framing["length_offset"], "length offset")
    payload_offset = _index(framing["payload_offset"], "payload offset")
    kind_width = _index(framing["kind_width"], "kind width")
    length_width = _index(framing["length_width"], "length width")
    if kind_width not in (1, 2) or length_width not in (1, 2):
        raise CustomProtocolFramingError("Field widths must be one or two bytes")
    core.choice(framing["length_endian"], {"big", "little"}, "length endian")
    kind_range = set(range(kind_offset, kind_offset + kind_width))
    length_range = set(range(length_offset, length_offset + length_width))
    if (
        kind_range & length_range
        or payload_offset < max(kind_offset + kind_width, length_offset + length_width)
    ):
        raise CustomProtocolFramingError("Framing fields overlap or extend into payload")
    frames: list[tuple[str, str, bytes]] = []
    seen = set()
    for item in core.bounded_list(model["frames"], MAX_FRAMES, "frames"):
        row = core.exact(item, {"frame_id", "direction", "wire_hex"}, "frame")
        frame_id = core.identifier(row["frame_id"], "frame ID")
        if frame_id in seen:
            raise CustomProtocolFramingError("Duplicate frame ID")
        seen.add(frame_id)
        direction = core.choice(
            row["direction"], {"client_to_server", "server_to_client"}, "direction"
        )
        wire_hex = row["wire_hex"]
        if (
            type(wire_hex) is not str
            or len(wire_hex) > 2 * MAX_WIRE_BYTES
            or HEX.fullmatch(wire_hex) is None
        ):
            raise CustomProtocolFramingError("Wire bytes must be bounded lowercase hex")
        wire = bytes.fromhex(wire_hex)
        if len(wire) < payload_offset:
            raise CustomProtocolFramingError("Frame is shorter than supplied header")
        frames.append((frame_id, direction, wire))
    if not frames:
        raise CustomProtocolFramingError("At least one frame is required")
    return model, framing, frames, core.canonical(model)


def _derive(value: Any) -> dict:
    model, framing, frames, source_text = _model(value)
    rows = []
    for frame_id, direction, wire in frames:
        kind_start = framing["kind_offset"]
        kind_end = kind_start + framing["kind_width"]
        length_start = framing["length_offset"]
        length_end = length_start + framing["length_width"]
        kind = wire[kind_start:kind_end].hex()
        declared = int.from_bytes(
            wire[length_start:length_end], framing["length_endian"]
        )
        observed = len(wire) - framing["payload_offset"]
        rows.append({
            "frame_id": frame_id,
            "direction": direction,
            "kind_hex": kind,
            "declared_payload_bytes": declared,
            "observed_payload_bytes": observed,
            "length_matches": declared == observed,
        })
    rows.sort(key=lambda row: row["frame_id"])
    mismatches = [row["frame_id"] for row in rows if not row["length_matches"]]
    kinds = sorted({(row["direction"], row["kind_hex"]) for row in rows})
    unknown = [] if model["capture_inventory_complete"] else [
        "supplied_capture_inventory_incomplete"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "capture_inventory_complete_asserted": model["capture_inventory_complete"],
        "supplied_frame_count": len(frames),
        "direction_kind_pairs": [
            {"direction": direction, "kind_hex": kind} for direction, kind in kinds
        ],
        "frame_projections": rows,
        "length_mismatch_frame_ids": mismatches,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_framing_hypothesis_projection",
        "source_authenticated": False,
        "framing_hypothesis_verified": False,
        "protocol_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Framing fields and capture completeness are caller-supplied assertions.",
            "A length mismatch does not establish a parser defect or exploitable condition.",
            "Frames are synthetic and are not sent to any endpoint or target.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CPF-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CustomProtocolFramingReport:
    """Unsigned framing projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CustomProtocolFramingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CustomProtocolFramingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_custom_protocol_framing(model: Any) -> CustomProtocolFramingReport:
    return CustomProtocolFramingReport._owned(_derive(model))


def verify_supplied_custom_protocol_framing(
    report: Any, *, model: Any
) -> CustomProtocolFramingReport:
    if type(report) is not CustomProtocolFramingReport:
        raise CustomProtocolFramingError("Exact framing wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CustomProtocolFramingError("Report differs from separate original model")
    return CustomProtocolFramingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-custom-protocol-frames",
        "capture_inventory_complete": True,
        "framing": {
            "kind_offset": 0,
            "kind_width": 1,
            "length_offset": 1,
            "length_width": 2,
            "length_endian": "big",
            "payload_offset": 3,
        },
        "frames": [
            {"frame_id": "f1", "direction": "client_to_server", "wire_hex": "010002aabb"},
            {"frame_id": "f2", "direction": "server_to_client", "wire_hex": "020001cc"},
        ],
    }
