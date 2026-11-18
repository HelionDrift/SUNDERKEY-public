"""Project bounded synthetic CCSDS Space Packet primary-header geometry."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "transport_supplied_ccsds_space_packet_projection"
PROFILE_ID = "AOE-GD-D25-S08"
CAPABILITY_ID = "army.gd.d25.s08"
VECTOR_ID = "AV-GD-D25-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:16017394bae8ea9b05cc1610ad483a742650e9f41b2cd4c2abc301713e899208"
DOMAIN = "sunderkey.offline-ccsds-space-packet.v1"
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 32_768
MAX_PACKET_BYTES = 4_102
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class CcsdsSpacePacketError(ValueError):
    """A supplied packet model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CcsdsSpacePacketError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise CcsdsSpacePacketError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "packet_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CcsdsSpacePacketError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise CcsdsSpacePacketError("Only synthetic fixtures are accepted")
    encoded = model["packet_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_PACKET_BYTES + 2) // 3):
        raise CcsdsSpacePacketError("Bounded packet base64 is required")
    try:
        packet = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CcsdsSpacePacketError("Packet base64 is invalid") from exc
    if not 7 <= len(packet) <= MAX_PACKET_BYTES:
        raise CcsdsSpacePacketError("Packet byte count is outside bound")
    identification = int.from_bytes(packet[0:2], "big")
    sequence_control = int.from_bytes(packet[2:4], "big")
    version = identification >> 13
    if version != 0:
        raise CcsdsSpacePacketError("Unsupported packet version")
    packet_type = (identification >> 12) & 1
    secondary_header_present = bool((identification >> 11) & 1)
    apid = identification & 0x7FF
    if apid == 0x7FF and secondary_header_present:
        raise CcsdsSpacePacketError("Idle APID cannot declare a secondary header")
    data_length_count = int.from_bytes(packet[4:6], "big")
    data_length = data_length_count + 1
    if len(packet) != 6 + data_length:
        raise CcsdsSpacePacketError("Packet data length does not match envelope")
    data = packet[6:]
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
        "packet_version_number": version,
        "packet_type": "telecommand" if packet_type else "telemetry",
        "secondary_header_flag": secondary_header_present,
        "application_process_id": apid,
        "idle_apid": apid == 0x7FF,
        "sequence_flags": (sequence_control >> 14) & 3,
        "sequence_count_or_name": sequence_control & 0x3FFF,
        "packet_data_length": data_length,
        "packet_data_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "primary_header_geometry_valid": True,
        "secondary_header_interpreted": False,
        "mission_apid_mapping_verified": False,
        "telecommand_meaning_verified": False,
        "mission_identity_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "mission_specific_apid_mapping_unavailable",
            "secondary_header_and_user_data_not_interpreted",
            "source_and_spacecraft_identity_unverified",
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
            "Only a synthetic supplied CCSDS Space Packet primary header is inspected.",
            "APID mappings and packet data meaning are mission specific and unverified.",
            "A telecommand type bit does not prove a valid or executed command.",
            "No link-layer integrity, sender identity or spacecraft state is verified.",
            "No packet is acquired from or sent to an interface or target.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CcsdsSpacePacketReport:
    """Unsigned primary-header projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CcsdsSpacePacketError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CcsdsSpacePacketReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ccsds_space_packet(model: Any) -> CcsdsSpacePacketReport:
    return CcsdsSpacePacketReport._owned(_derive(model))


def verify_supplied_ccsds_space_packet(
    report: Any, *, model: Any
) -> CcsdsSpacePacketReport:
    if type(report) is not CcsdsSpacePacketReport:
        raise CcsdsSpacePacketError("Exact CCSDS wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CcsdsSpacePacketError("Report differs from separate original model")
    return CcsdsSpacePacketReport._owned(expected)


def component_fixture() -> dict:
    identification = 0x002A
    sequence_control = 0xC001
    packet = (
        identification.to_bytes(2, "big")
        + sequence_control.to_bytes(2, "big")
        + (2).to_bytes(2, "big")
        + b"\x01\x02\x03"
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-ccsds-space-packet",
        "synthetic_fixture": True,
        "packet_base64": base64.b64encode(packet).decode("ascii"),
    }
