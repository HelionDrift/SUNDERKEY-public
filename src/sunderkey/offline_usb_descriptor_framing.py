"""Frame bounded caller-supplied USB descriptors without device contact."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "usb_supplied_descriptor_framing"
PROFILE_ID = "AOE-GD-D24-S03"
CAPABILITY_ID = "army.gd.d24.s03"
VECTOR_ID = "AV-GD-D24-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:9920127946b691a24450085623770fdb1d22760f12f16ca2c1541f106cb26495"
DOMAIN = "sunderkey.offline-usb-descriptor-framing.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_DESCRIPTOR_BYTES = 4_096
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class UsbDescriptorFramingError(ValueError):
    """A supplied USB byte model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "capture_complete", "descriptor_bytes"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise UsbDescriptorFramingError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["capture_complete"], "capture completeness")
    stream = core.bounded_list(model["descriptor_bytes"], MAX_DESCRIPTOR_BYTES, "descriptor bytes")
    if not stream:
        raise UsbDescriptorFramingError("Descriptor bytes must not be empty")
    if any(type(item) is not int or not 0 <= item <= 255 for item in stream):
        raise UsbDescriptorFramingError("Descriptor bytes must be native unsigned8 values")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    stream = model["descriptor_bytes"]
    descriptors = []
    issues = []
    offset = 0
    while offset < len(stream):
        if len(stream) - offset < 2:
            issues.append({"offset": offset, "issue": "short_descriptor_header"})
            break
        length, descriptor_type = stream[offset : offset + 2]
        if length < 2:
            issues.append({"offset": offset, "issue": "invalid_descriptor_length"})
            break
        if offset + length > len(stream):
            issues.append({"offset": offset, "issue": "truncated_descriptor"})
            break
        descriptors.append({
            "offset": offset,
            "length": length,
            "descriptor_type": descriptor_type,
        })
        offset += length
    disposition = (
        "unknown"
        if not model["capture_complete"]
        else "candidate_supplied_usb_descriptor_framing_gap"
        if issues
        else "no_supplied_usb_descriptor_framing_gap"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "supplied_byte_count": len(stream),
        "parsed_descriptors": descriptors,
        "issues": issues,
        "disposition": disposition,
        "candidate_count": len(issues) if model["capture_complete"] else 0,
        "unknown_count": int(not model["capture_complete"]),
        "source_authenticated": False,
        "usb_device_contacted": False,
        "descriptor_semantics_verified": False,
        "exploit_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Descriptor bytes and completeness are caller-supplied and unauthenticated.",
            "Only bLength and bDescriptorType framing are inspected; class payloads are opaque.",
            "Unknown descriptor types are retained, not rejected or interpreted.",
            "No USB device, HID endpoint, removable media or host controller is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="UDF-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class UsbDescriptorFramingReport:
    """Unsigned descriptor projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise UsbDescriptorFramingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> UsbDescriptorFramingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_usb_descriptors(model: Any) -> UsbDescriptorFramingReport:
    return UsbDescriptorFramingReport._owned(_derive(model))


def verify_supplied_usb_descriptors(
    report: Any, *, model: Any
) -> UsbDescriptorFramingReport:
    if type(report) is not UsbDescriptorFramingReport:
        raise UsbDescriptorFramingError("Exact USB descriptor wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise UsbDescriptorFramingError("Report differs from separate original model")
    return UsbDescriptorFramingReport._owned(expected)


def verify_supplied_usb_descriptors_bytes(
    report_bytes: bytes, *, model: Any
) -> UsbDescriptorFramingReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise UsbDescriptorFramingError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise UsbDescriptorFramingError("Exported report differs from original replay")
    return UsbDescriptorFramingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-usb-descriptors",
        "capture_complete": True,
        "descriptor_bytes": [2, 1, 1, 4],
    }
