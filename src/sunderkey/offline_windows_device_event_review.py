"""Parse one supplied synthetic Windows 6416 event without device access."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_windows_device_event_review"
PROFILE_ID = "AOE-GA-D02-S11"
CAPABILITY_ID = "army.ga.d02.s11"
VECTOR_ID = "AV-GA-D02-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S11"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9f48118d6d41ac279721a5e3d7d43eb55cc46d039bb55d63fd6533b2102ecd29"
DOMAIN = "sunderkey.offline-windows-device-event-review.v1"
NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
ROOT_TAG = f"{{{NAMESPACE}}}Event"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
DEVICE_ID = re.compile(r"USBSTOR\\SYNTHETIC\\[0-9]{4}\Z")
CLASS_GUID = "{4D36E967-E325-11CE-BFC1-08002BE10318}"
DATA_NAMES = {
    "SubjectUserSid", "DeviceId", "DeviceDescription", "ClassId", "ClassName",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsDeviceEventReviewError(ValueError):
    """A synthetic 6416 event declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise WindowsDeviceEventReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise WindowsDeviceEventReviewError("Model exceeds byte bound")
    return result


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "event_xml",
         "expected_device_id"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsDeviceEventReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise WindowsDeviceEventReviewError("Only synthetic fixtures are accepted")
    expected_device = model["expected_device_id"]
    if type(expected_device) is not str or DEVICE_ID.fullmatch(expected_device) is None:
        raise WindowsDeviceEventReviewError("Synthetic device ID required")
    xml = model["event_xml"]
    if (type(xml) is not str or not 1 <= len(xml) <= 4_096
            or not xml.isascii() or "<!" in xml or "<?" in xml):
        raise WindowsDeviceEventReviewError("Bounded ASCII event XML required")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise WindowsDeviceEventReviewError("Malformed event XML") from exc
    if root.tag != ROOT_TAG or root.attrib or len(root) != 2:
        raise WindowsDeviceEventReviewError("Event root requires System and EventData")
    system, event_data = root
    if (system.tag != f"{{{NAMESPACE}}}System"
            or event_data.tag != f"{{{NAMESPACE}}}EventData"
            or system.attrib or event_data.attrib or len(system) != 4
            or len(event_data) != len(DATA_NAMES)):
        raise WindowsDeviceEventReviewError("Closed 6416 event structure required")
    provider, event_id, version, channel = system
    if (provider.tag != f"{{{NAMESPACE}}}Provider"
            or provider.attrib != {"Name": "Microsoft-Windows-Security-Auditing"}
            or event_id.tag != f"{{{NAMESPACE}}}EventID" or event_id.text != "6416"
            or version.tag != f"{{{NAMESPACE}}}Version" or version.text != "1"
            or channel.tag != f"{{{NAMESPACE}}}Channel" or channel.text != "Security"
            or any(len(item) or (item.tail or "").strip() for item in system)):
        raise WindowsDeviceEventReviewError("Windows Security 6416 v1 fields required")
    data = {}
    for item in event_data:
        if (item.tag != f"{{{NAMESPACE}}}Data" or len(item)
                or item.attrib.keys() != {"Name"}
                or item.attrib["Name"] not in DATA_NAMES
                or item.attrib["Name"] in data
                or item.text is None or len(item.text) > 256
                or (item.tail or "").strip()):
            raise WindowsDeviceEventReviewError("Closed unique 6416 Data fields required")
        data[item.attrib["Name"]] = item.text
    if (set(data) != DATA_NAMES or data["SubjectUserSid"] != "S-1-5-18"
            or DEVICE_ID.fullmatch(data["DeviceId"]) is None
            or data["ClassId"] != CLASS_GUID or data["ClassName"] != "DiskDrive"
            or data["DeviceDescription"] != "Synthetic Test Device"):
        raise WindowsDeviceEventReviewError("Synthetic 6416 field subset required")
    device_id = data["DeviceId"]
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
        "event_xml_sha256": _hash(xml),
        "device_id_sha256": _hash(device_id),
        "device_matches_supplied_expectation": device_id == expected_device,
        "event_id": 6416,
        "event_version": 1,
        "external_device_recognition_declared": True,
        "removable_storage_confirmed": False,
        "media_read_or_written": False,
        "device_placed_by_actor": False,
        "candidate_count": 0,
        "uncertainty": [
            "event_origin_and_completeness_unverified",
            "removable_media_and_data_access_unobserved",
            "device_placement_and_operator_action_unobserved",
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
            "Only one synthetic Windows Security 6416 v1 event subset is parsed.",
            "Event 6416 is recognition, not proof of removable storage or content access.",
            "The event source and any associated person or device are not authenticated.",
            "No device is attached, read, written, placed, or activated.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WDR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsDeviceEventReviewReport:
    """Unsigned device-event projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsDeviceEventReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsDeviceEventReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_windows_device_event(model: Any) -> WindowsDeviceEventReviewReport:
    return WindowsDeviceEventReviewReport._owned(_derive(model))


def verify_supplied_windows_device_event(
    report: Any, *, model: Any
) -> WindowsDeviceEventReviewReport:
    if type(report) is not WindowsDeviceEventReviewReport:
        raise WindowsDeviceEventReviewError("Exact device-event wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsDeviceEventReviewError("Report differs from separate original model")
    return WindowsDeviceEventReviewReport._owned(expected)


def component_fixture() -> dict:
    device_id = "USBSTOR\\SYNTHETIC\\0001"
    return {
        "schema_version": 1,
        "source_id": "synthetic-windows-6416",
        "synthetic_fixture": True,
        "event_xml": (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
            '<EventID>6416</EventID><Version>1</Version><Channel>Security</Channel>'
            '</System><EventData>'
            '<Data Name="SubjectUserSid">S-1-5-18</Data>'
            f'<Data Name="DeviceId">{device_id}</Data>'
            '<Data Name="DeviceDescription">Synthetic Test Device</Data>'
            f'<Data Name="ClassId">{CLASS_GUID}</Data>'
            '<Data Name="ClassName">DiskDrive</Data>'
            '</EventData></Event>'
        ),
        "expected_device_id": device_id,
    }
