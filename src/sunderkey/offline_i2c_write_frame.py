"""Project one bounded synthetic I2C controller-write event frame."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_i2c_write_frame_projection"
PROFILE_ID = "AOE-GD-D18-S06"
CAPABILITY_ID = "army.gd.d18.s06"
VECTOR_ID = "AV-GD-D18-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S06"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:b474cb1ac602d4642cb70fb4b266d7974d1a7a746bd4edbfd796a3357f4d13f3"
DOMAIN = "sunderkey.offline-i2c-write-frame.v1"
KINDS = {"START", "ADDRESS", "DATA", "ACK", "NACK", "STOP"}
OCTET = re.compile(r"[0-9a-f]{2}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class I2cWriteFrameError(ValueError):
    """The synthetic frame or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "single_controller_write_asserted", "events",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise I2cWriteFrameError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise I2cWriteFrameError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    if not core.boolean(model["single_controller_write_asserted"], "write assertion"):
        raise I2cWriteFrameError("Only the declared single controller write is modeled")
    supplied = core.bounded_list(model["events"], 64, "events")
    if not supplied:
        raise I2cWriteFrameError("At least one event is required")
    events = []
    seen = set()
    for item in supplied:
        row = core.exact(item, {"event_id", "kind", "byte_hex"}, "event")
        event_id = core.identifier(row["event_id"], "event ID")
        if event_id in seen:
            raise I2cWriteFrameError("Duplicate event ID")
        seen.add(event_id)
        kind = core.choice(row["kind"], KINDS, "event kind")
        octet = row["byte_hex"]
        if kind in {"ADDRESS", "DATA"}:
            if type(octet) is not str or OCTET.fullmatch(octet) is None:
                raise I2cWriteFrameError("Address and data events require lowercase octets")
            if kind == "ADDRESS" and int(octet, 16) & 1:
                raise I2cWriteFrameError("Address octet declares read direction")
        elif octet is not None:
            raise I2cWriteFrameError("Control events must not carry an octet")
        events.append((event_id, kind))
    state = "start"
    data_octets = 0
    rows = []
    for event_id, kind in events:
        flags = []
        if state == "start" and kind == "START":
            state = "expect_address"
        elif state == "expect_address" and kind == "ADDRESS":
            state = "expect_address_ack"
        elif state == "expect_address_ack" and kind == "ACK":
            state = "ready_data_or_stop"
        elif state == "expect_address_ack" and kind == "NACK":
            state = "expect_stop"
        elif state == "ready_data_or_stop" and kind == "DATA":
            data_octets += 1
            state = "expect_data_ack"
        elif state == "expect_data_ack" and kind == "ACK":
            state = "ready_data_or_stop"
        elif state == "expect_data_ack" and kind == "NACK":
            state = "expect_stop"
        elif state in {"ready_data_or_stop", "expect_stop"} and kind == "STOP":
            state = "done"
        else:
            flags.append("event_outside_declared_write_frame")
        rows.append({
            "event_id": event_id,
            "kind": kind,
            "state_after_event": state,
            "declared_framing_flags": flags,
        })
    deviations = sorted(row["event_id"] for row in rows if row["declared_framing_flags"])
    unknown = [] if complete else ["supplied_i2c_trace_incomplete"]
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
        "inventory_complete_asserted": complete,
        "single_controller_write_asserted": True,
        "supplied_event_count": len(events),
        "supplied_data_octet_count": data_octets,
        "event_projections": rows,
        "declared_framing_deviation_event_ids": deviations,
        "final_declared_state": state,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_i2c_write_projection",
        "source_authenticated": False,
        "hardware_connected": False,
        "electrical_signals_verified": False,
        "bus_capture_verified": False,
        "protocol_conformance_verified": False,
        "spi_modeled": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Events, octets, ordering, write shape, and completeness are supplied assertions.",
            "Reads, repeated starts, arbitration, clock stretching, timing, and SPI are"
            " outside scope.",
            "A model deviation is not proof of a bus error or security vulnerability.",
            "No hardware, bus, device, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IWF-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class I2cWriteFrameReport:
    """Unsigned frame projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise I2cWriteFrameError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> I2cWriteFrameReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_i2c_write(model: Any) -> I2cWriteFrameReport:
    return I2cWriteFrameReport._owned(_derive(model))


def verify_supplied_i2c_write(
    report: Any, *, model: Any
) -> I2cWriteFrameReport:
    if type(report) is not I2cWriteFrameReport:
        raise I2cWriteFrameError("Exact I2C wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise I2cWriteFrameError("Report differs from separate original model")
    return I2cWriteFrameReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-i2c-write",
        "synthetic_fixture": True, "inventory_complete": True,
        "single_controller_write_asserted": True,
        "events": [
            {"event_id": "e1", "kind": "START", "byte_hex": None},
            {"event_id": "e2", "kind": "ADDRESS", "byte_hex": "a0"},
            {"event_id": "e3", "kind": "ACK", "byte_hex": None},
            {"event_id": "e4", "kind": "DATA", "byte_hex": "42"},
            {"event_id": "e5", "kind": "ACK", "byte_hex": None},
            {"event_id": "e6", "kind": "STOP", "byte_hex": None},
        ],
    }
