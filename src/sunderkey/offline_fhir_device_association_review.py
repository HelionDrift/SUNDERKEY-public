"""Review a privacy-minimal synthetic FHIR R5 DeviceAssociation subset."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "clinical_supplied_fhir_device_association_review"
PROFILE_ID = "AOE-GD-D25-S11"
CAPABILITY_ID = "army.gd.d25.s11"
VECTOR_ID = "AV-GD-D25-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GD-D25-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:0b9cc2e1edba61ea0ca14c4b9fdb6376f59b4abe84aacb2259b264ef61efb202"
DOMAIN = "sunderkey.offline-fhir-device-association-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
FHIR_ID = re.compile(r"[A-Za-z0-9.-]{1,64}\Z")
SUBJECT = re.compile(r"Patient/[A-Za-z0-9.-]{1,64}\Z")
DEVICE_STATUSES = {"active", "inactive", "entered-in-error", "unknown"}
ASSOCIATION_STATUSES = {"implanted", "explanted", "attached", "entered-in-error", "unknown"}
STATUS_SYSTEM = "http://hl7.org/fhir/deviceassociation-status"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class FhirDeviceAssociationReviewError(ValueError):
    """A synthetic FHIR relation or original-model replay is invalid."""


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fhir_id(value: Any, label: str) -> str:
    if type(value) is not str or FHIR_ID.fullmatch(value) is None:
        raise FhirDeviceAssociationReviewError(f"Bounded {label} FHIR ID required")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "device", "association"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FhirDeviceAssociationReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise FhirDeviceAssociationReviewError("Only synthetic fixtures are accepted")
    device = core.exact(model["device"], {"resourceType", "id", "status"}, "device")
    if device["resourceType"] != "Device":
        raise FhirDeviceAssociationReviewError("FHIR Device resource required")
    device_id = _fhir_id(device["id"], "device")
    if type(device["status"]) is not str or device["status"] not in DEVICE_STATUSES:
        raise FhirDeviceAssociationReviewError("Known Device status required")
    association = core.exact(
        model["association"],
        {"resourceType", "id", "device", "status", "subject"},
        "association",
    )
    if association["resourceType"] != "DeviceAssociation":
        raise FhirDeviceAssociationReviewError("FHIR DeviceAssociation required")
    association_id = _fhir_id(association["id"], "association")
    device_ref = core.exact(association["device"], {"reference"}, "device reference")[
        "reference"
    ]
    if type(device_ref) is not str or not device_ref.startswith("Device/"):
        raise FhirDeviceAssociationReviewError("Relative Device reference required")
    _fhir_id(device_ref[7:], "device reference")
    subject_ref = core.exact(association["subject"], {"reference"}, "subject")[
        "reference"
    ]
    if type(subject_ref) is not str or SUBJECT.fullmatch(subject_ref) is None:
        raise FhirDeviceAssociationReviewError("Synthetic Patient reference required")
    status = core.exact(association["status"], {"coding"}, "association status")
    codings = status["coding"]
    if type(codings) is not list or len(codings) != 1:
        raise FhirDeviceAssociationReviewError("One status coding required")
    coding = core.exact(codings[0], {"system", "code"}, "status coding")
    if (coding["system"] != STATUS_SYSTEM or type(coding["code"]) is not str
            or coding["code"] not in ASSOCIATION_STATUSES):
        raise FhirDeviceAssociationReviewError("Known R5 association status required")
    relation_matches = device_ref == f"Device/{device_id}"
    status_review_cue = device["status"] == "inactive" and coding["code"] == "implanted"
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "fhir_release": "R5-5.0.0",
        "device_id_sha256": _digest(device_id),
        "association_id_sha256": _digest(association_id),
        "subject_ref_sha256": _digest(subject_ref),
        "device_reference_matches_supplied_device": relation_matches,
        "declared_device_status": device["status"],
        "declared_association_status": coding["code"],
        "inactive_device_with_implanted_association_review_cue": status_review_cue,
        "candidate_count": 0,
        "uncertainty": [
            "fhir_resource_origin_and_patient_link_unverified",
            "device_inventory_and_clinical_state_unobserved",
            "status_combination_may_be_valid_in_local_workflow",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "patient_association_verified": False,
        "device_security_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only a privacy-minimal synthetic FHIR R5 Device and DeviceAssociation subset is read.",
            "A status pairing is a review cue, not a device fault or patient-safety conclusion.",
            "No real patient, device, clinical record, or FHIR server is contacted.",
            "No device operation, security control, or clinical status is verified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="FDR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class FhirDeviceAssociationReviewReport:
    """Unsigned clinical relation projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FhirDeviceAssociationReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FhirDeviceAssociationReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_fhir_device_association(model: Any) -> FhirDeviceAssociationReviewReport:
    return FhirDeviceAssociationReviewReport._owned(_derive(model))


def verify_supplied_fhir_device_association(
    report: Any, *, model: Any
) -> FhirDeviceAssociationReviewReport:
    if type(report) is not FhirDeviceAssociationReviewReport:
        raise FhirDeviceAssociationReviewError("Exact FHIR device wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise FhirDeviceAssociationReviewError("Report differs from separate original model")
    return FhirDeviceAssociationReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-fhir-device-association",
        "synthetic_fixture": True,
        "device": {"resourceType": "Device", "id": "device-001", "status": "active"},
        "association": {
            "resourceType": "DeviceAssociation",
            "id": "association-001",
            "device": {"reference": "Device/device-001"},
            "status": {"coding": [{"system": STATUS_SYSTEM, "code": "implanted"}]},
            "subject": {"reference": "Patient/synthetic-001"},
        },
    }
