"""Project bounded synthetic SocketCAN classical data-frame structure."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "industrial_supplied_socketcan_classical_frame_projection"
PROFILE_ID = "AOE-GD-D19-S12"
CAPABILITY_ID = "army.gd.d19.s12"
VECTOR_ID = "AV-GD-D19-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S12"
WAVE_ID = "IW2-022"
COMMANDER_ID = "AOE-GD-D19-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:48edf3a396cac4a0164dc00c736771d142cae5bd9580ea2bc9f235d45658edd0"
DOMAIN = "sunderkey.offline-socketcan-classical-frames.v1"
MAX_FRAME_COUNT = 128
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 131_072
FRAME_BYTES = 16
CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000
CAN_SFF_MASK = 0x7FF
CAN_EFF_MASK = 0x1FFFFFFF
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SocketCanClassicalFrameError(ValueError):
    """A supplied frame model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SocketCanClassicalFrameError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise SocketCanClassicalFrameError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "frames_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SocketCanClassicalFrameError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise SocketCanClassicalFrameError("Only synthetic fixtures are accepted")
    encoded = model["frames_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((FRAME_BYTES * MAX_FRAME_COUNT + 2) // 3):
        raise SocketCanClassicalFrameError("Bounded frame base64 is required")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SocketCanClassicalFrameError("Frame base64 is invalid") from exc
    if not FRAME_BYTES <= len(data) <= FRAME_BYTES * MAX_FRAME_COUNT:
        raise SocketCanClassicalFrameError("Frame byte count is outside bound")
    if len(data) % FRAME_BYTES:
        raise SocketCanClassicalFrameError("Whole 16-byte frame records are required")
    observations = []
    for index in range(len(data) // FRAME_BYTES):
        raw = data[index * FRAME_BYTES:(index + 1) * FRAME_BYTES]
        can_id, length, pad, reserved, len8_dlc, payload = struct.unpack("<IBBBB8s", raw)
        if length > 8 or pad or reserved or len8_dlc:
            raise SocketCanClassicalFrameError("Unsupported length or reserved frame bytes")
        if can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG):
            raise SocketCanClassicalFrameError("Only classical data frames are supported")
        extended = bool(can_id & CAN_EFF_FLAG)
        identifier = can_id & CAN_EFF_MASK
        if not extended and identifier > CAN_SFF_MASK:
            raise SocketCanClassicalFrameError("Standard identifier exceeds 11 bits")
        if any(payload[length:]):
            raise SocketCanClassicalFrameError("Unused payload bytes must be zero")
        observations.append({
            "index": index,
            "identifier_width": "extended_29" if extended else "standard_11",
            "identifier_hex": f"0x{identifier:x}",
            "payload_length": length,
            "payload_sha256": "sha256:" + hashlib.sha256(payload[:length]).hexdigest(),
            "reserved_bytes_zero": True,
        })
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
        "source_frames_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "synthetic_fixture_asserted": True,
        "frame_count": len(observations),
        "standard_frame_count": sum(
            row["identifier_width"] == "standard_11" for row in observations
        ),
        "extended_frame_count": sum(
            row["identifier_width"] == "extended_29" for row in observations
        ),
        "frame_observations": observations,
        "candidate_count": 0,
        "uncertainty": [
            "host_byte_order_and_capture_origin_unverified",
            "vehicle_bus_and_payload_semantics_unassessed",
        ],
        "unknown_count": 2,
        "disposition": "unknown",
        "source_authenticated": False,
        "vehicle_identity_verified": False,
        "bus_capture_verified": False,
        "uds_message_interpreted": False,
        "vehicle_behavior_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Frames are synthetic caller-supplied little-endian SocketCAN records.",
            "Only classical data-frame geometry is parsed; RTR, error and CAN FD are excluded.",
            "Payload bytes are not interpreted or retained, only hashed.",
            "CAN IDs do not establish a vehicle, bus, ECU or UDS meaning.",
            "No frame is acquired from or sent to any interface or target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SCF-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SocketCanClassicalFrameReport:
    """Unsigned frame projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SocketCanClassicalFrameError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SocketCanClassicalFrameReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_socketcan_classical_frames(
    model: Any,
) -> SocketCanClassicalFrameReport:
    return SocketCanClassicalFrameReport._owned(_derive(model))


def verify_supplied_socketcan_classical_frames(
    report: Any, *, model: Any
) -> SocketCanClassicalFrameReport:
    if type(report) is not SocketCanClassicalFrameReport:
        raise SocketCanClassicalFrameError("Exact SocketCAN wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SocketCanClassicalFrameError("Report differs from separate original model")
    return SocketCanClassicalFrameReport._owned(expected)


def component_fixture() -> dict:
    standard = struct.pack("<IBBBB8s", 0x123, 3, 0, 0, 0, b"\x01\x02\x03" + bytes(5))
    extended = struct.pack(
        "<IBBBB8s", CAN_EFF_FLAG | 0x18FF50E5, 2, 0, 0, 0,
        b"\xaa\x55" + bytes(6),
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-socketcan-classical-frames",
        "synthetic_fixture": True,
        "frames_base64": base64.b64encode(standard + extended).decode("ascii"),
    }
