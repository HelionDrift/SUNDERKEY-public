"""Project bounded synthetic MAVLink 2 packet-envelope geometry."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "transport_supplied_mavlink2_packet_envelope"
PROFILE_ID = "AOE-GD-D25-S10"
CAPABILITY_ID = "army.gd.d25.s10"
VECTOR_ID = "AV-GD-D25-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:5bc430ff5930e1ab5609627fc1aa551d187f1ef24161900d1e9f08aaeaadd640"
DOMAIN = "sunderkey.offline-mavlink2-packet-envelope.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
MAX_PACKET_BYTES = 280
SIGNED_FLAG = 0x01
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class Mavlink2PacketEnvelopeError(ValueError):
    """A supplied packet model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Mavlink2PacketEnvelopeError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise Mavlink2PacketEnvelopeError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "packet_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise Mavlink2PacketEnvelopeError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise Mavlink2PacketEnvelopeError("Only synthetic fixtures are accepted")
    encoded = model["packet_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_PACKET_BYTES + 2) // 3):
        raise Mavlink2PacketEnvelopeError("Bounded packet base64 is required")
    try:
        packet = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Mavlink2PacketEnvelopeError("Packet base64 is invalid") from exc
    if not 12 <= len(packet) <= MAX_PACKET_BYTES:
        raise Mavlink2PacketEnvelopeError("Packet byte count is outside bound")
    if packet[0] != 0xFD:
        raise Mavlink2PacketEnvelopeError("MAVLink 2 magic byte is required")
    payload_length = packet[1]
    incompatible_flags = packet[2]
    if incompatible_flags & ~SIGNED_FLAG:
        raise Mavlink2PacketEnvelopeError("Unknown incompatibility flag")
    signature_present = bool(incompatible_flags & SIGNED_FLAG)
    expected_length = 12 + payload_length + (13 if signature_present else 0)
    if len(packet) != expected_length:
        raise Mavlink2PacketEnvelopeError("Packet length does not match envelope")
    if packet[5] == 0 or packet[6] == 0:
        raise Mavlink2PacketEnvelopeError("Sender IDs must not be zero")
    payload = packet[10:10 + payload_length]
    checksum = packet[10 + payload_length:12 + payload_length]
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
        "source_packet_sha256": "sha256:" + hashlib.sha256(packet).hexdigest(),
        "synthetic_fixture_asserted": True,
        "packet_length": len(packet),
        "payload_length": payload_length,
        "sequence": packet[4],
        "sender_system_id": packet[5],
        "sender_component_id": packet[6],
        "message_id": int.from_bytes(packet[7:10], "little"),
        "compatibility_flags_hex": f"0x{packet[3]:02x}",
        "signature_present": signature_present,
        "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "checksum_field_hex": checksum.hex(),
        "envelope_geometry_valid": True,
        "checksum_verified": False,
        "signature_verified": False,
        "message_definition_verified": False,
        "sender_identity_verified": False,
        "aircraft_identity_verified": False,
        "flight_behavior_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "crc_extra_and_message_definition_unavailable",
            "signature_key_and_sender_identity_unavailable",
            "capture_origin_and_aircraft_state_unverified",
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
            "Only a synthetic supplied MAVLink 2 packet envelope is inspected.",
            "Payload meaning and CRC_EXTRA-dependent checksum are not verified.",
            "A signature field is only detected, never authenticated.",
            "Sender IDs do not establish an aircraft or trusted device identity.",
            "No packet is acquired from or sent to an interface or target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPE-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class Mavlink2PacketEnvelopeReport:
    """Unsigned packet projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise Mavlink2PacketEnvelopeError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> Mavlink2PacketEnvelopeReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mavlink2_packet_envelope(model: Any) -> Mavlink2PacketEnvelopeReport:
    return Mavlink2PacketEnvelopeReport._owned(_derive(model))


def verify_supplied_mavlink2_packet_envelope(
    report: Any, *, model: Any
) -> Mavlink2PacketEnvelopeReport:
    if type(report) is not Mavlink2PacketEnvelopeReport:
        raise Mavlink2PacketEnvelopeError("Exact MAVLink wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise Mavlink2PacketEnvelopeError("Report differs from separate original model")
    return Mavlink2PacketEnvelopeReport._owned(expected)


def component_fixture() -> dict:
    packet = bytes((0xFD, 2, 0, 0, 7, 1, 2, 0, 0, 0, 0x42, 0x21, 0, 0))
    return {
        "schema_version": 1,
        "source_id": "synthetic-mavlink2-envelope",
        "synthetic_fixture": True,
        "packet_base64": base64.b64encode(packet).decode("ascii"),
    }
