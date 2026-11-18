"""Project declared biometric-assurance conflicts without biometric material."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_biometric_assurance_projection"
PROFILE_ID = "AOE-GA-D03-S17"
CAPABILITY_ID = "army.ga.d03.s17"
VECTOR_ID = "AV-GA-D03-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S17"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8ba380a2aa96a81464e8e3324736f2b4afc431afac35f675fc8a9d55a59ad585"
DOMAIN = "sunderkey.offline-biometric-assurance-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_RECORDS = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class BiometricAssuranceProjectionError(ValueError):
    """A supplied assurance model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise BiometricAssuranceProjectionError(f"{label} must be synthetic")
    return identifier


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "records_complete",
            "order_complete",
            "require_liveness", "require_bound_device", "require_unique_nonce",
            "records",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BiometricAssuranceProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in (
        "policy_complete", "records_complete", "order_complete", "require_liveness",
        "require_bound_device", "require_unique_nonce",
    ):
        core.boolean(model[field], field)
    records = core.bounded_list(model["records"], MAX_RECORDS, "records")
    if not records:
        raise BiometricAssuranceProjectionError("At least one record is required")
    seen: set[str] = set()
    for item in records:
        row = core.exact(
            item,
            {
                "record_id", "nonce_id", "reported_outcome", "declared_liveness",
                "declared_device_binding",
            },
            "record",
        )
        record_id = _synthetic(row["record_id"], "record ID")
        if record_id in seen:
            raise BiometricAssuranceProjectionError("Duplicate record ID")
        seen.add(record_id)
        _synthetic(row["nonce_id"], "nonce ID")
        core.choice(row["reported_outcome"], {"accepted", "rejected", "unknown"}, "outcome")
        for field in ("declared_liveness", "declared_device_binding"):
            core.choice(row[field], {"yes", "no", "unknown"}, field)
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[field] for field in ("policy_complete", "records_complete", "order_complete")
    )
    seen_nonces: set[str] = set()
    projections: list[dict] = []
    for record in model["records"]:
        nonce_reused = record["nonce_id"] in seen_nonces
        seen_nonces.add(record["nonce_id"])
        required_unknown = (
            record["reported_outcome"] == "unknown"
            or model["require_liveness"] and record["declared_liveness"] == "unknown"
            or model["require_bound_device"]
            and record["declared_device_binding"] == "unknown"
        )
        flags: list[str] = []
        if complete and not required_unknown and record["reported_outcome"] == "accepted":
            if model["require_liveness"] and record["declared_liveness"] == "no":
                flags.append("candidate_acceptance_without_declared_liveness")
            if model["require_bound_device"] and record["declared_device_binding"] == "no":
                flags.append("candidate_acceptance_without_declared_device_binding")
            if model["require_unique_nonce"] and nonce_reused:
                flags.append("candidate_acceptance_with_reused_nonce_label")
        disposition = (
            "unknown" if not complete or required_unknown
            else "candidate" if flags else "no_declared_conflict"
        )
        projections.append({
            "record_id": record["record_id"],
            "nonce_id": record["nonce_id"],
            "reported_outcome": record["reported_outcome"],
            "nonce_label_reused": nonce_reused,
            "disposition": disposition,
            "candidate_flags": flags,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "record_count": len(projections),
            "candidate_count": sum(row["disposition"] == "candidate" for row in projections),
            "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "biometric_material_processed": False,
        "liveness_verified": False,
        "device_attestation_verified": False,
        "nonce_freshness_verified": False,
        "authentication_attempt_performed": False,
        "presentation_attack_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Policy, outcomes, liveness labels, device labels and order are caller declarations.",
            "Nonce reuse is arithmetic over synthetic labels, not cryptographic freshness proof.",
            "No biometric sample, template, image, sensor or target response is processed.",
            "A declared acceptance conflict is not a verified presentation attack or finding.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BAP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class BiometricAssuranceProjectionReport:
    """Unsigned assurance projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BiometricAssuranceProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BiometricAssuranceProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_biometric_assurance(model: Any) -> BiometricAssuranceProjectionReport:
    try:
        return BiometricAssuranceProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise BiometricAssuranceProjectionError(str(exc)) from exc


def verify_supplied_biometric_assurance(
    report: Any, *, model: Any,
) -> BiometricAssuranceProjectionReport:
    if type(report) is not BiometricAssuranceProjectionReport:
        raise BiometricAssuranceProjectionError("Exact report wrapper required")
    expected = analyze_supplied_biometric_assurance(model)
    if report.to_json() != expected.to_json():
        raise BiometricAssuranceProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_biometric_assurance_bytes(
    report_bytes: bytes, *, model: Any,
) -> BiometricAssuranceProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise BiometricAssuranceProjectionError(str(exc)) from exc
    expected = analyze_supplied_biometric_assurance(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise BiometricAssuranceProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:biometric-assurance",
        "policy_complete": True,
        "records_complete": True,
        "order_complete": True,
        "require_liveness": True,
        "require_bound_device": True,
        "require_unique_nonce": True,
        "records": [
            {"record_id": "synthetic:first", "nonce_id": "synthetic:nonce-one",
             "reported_outcome": "accepted", "declared_liveness": "yes",
             "declared_device_binding": "yes"},
            {"record_id": "synthetic:second", "nonce_id": "synthetic:nonce-one",
             "reported_outcome": "accepted", "declared_liveness": "no",
             "declared_device_binding": "no"},
        ],
    }


__all__ = [
    "BiometricAssuranceProjectionError", "BiometricAssuranceProjectionReport",
    "analyze_supplied_biometric_assurance", "verify_supplied_biometric_assurance",
    "verify_supplied_biometric_assurance_bytes", "component_fixture",
]
