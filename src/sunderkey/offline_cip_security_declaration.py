"""Compare supplied CIP Security connection labels with explicit local requirements."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cip_supplied_security_property_gap"
PROFILE_ID = "AOE-GD-D19-S20"
CAPABILITY_ID = "army.gd.d19.s20"
VECTOR_ID = "AV-GD-D19-S20-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S20"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:12b3840e3a3cd552b2958db8d281471be93c4bc84eda54f2c32bf65b840cd081"
DOMAIN = "sunderkey.offline-cip-security-declaration.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
PROPERTIES = (
    (
        "endpoint_authentication_required",
        "endpoint_authentication_declared",
        "endpoint_authentication",
    ),
    ("integrity_required", "integrity_declared", "message_integrity"),
    ("confidentiality_required", "encryption_declared", "message_confidentiality"),
)
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class CipSecurityDeclarationError(ValueError):
    """A supplied industrial connection declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "connections"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CipSecurityDeclarationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    connections = core.bounded_list(model["connections"], 64, "connections")
    if not connections:
        raise CipSecurityDeclarationError("At least one connection is required")
    seen: set[str] = set()
    boolean_fields = {name for required, declared, _ in PROPERTIES for name in (required, declared)}
    for item in connections:
        row = core.exact(
            item,
            {"connection_id", "originator_id", "target_id", "context_complete"}
            | boolean_fields,
            "connection",
        )
        connection_id = core.identifier(row["connection_id"], "connection ID")
        if connection_id in seen:
            raise CipSecurityDeclarationError("Duplicate connection ID")
        seen.add(connection_id)
        core.identifier(row["originator_id"], "originator ID")
        core.identifier(row["target_id"], "target ID")
        core.boolean(row["context_complete"], "context completeness")
        for key in boolean_fields:
            core.boolean(row[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["connections"]:
        missing = [
            label
            for required, declared, label in PROPERTIES
            if row[required] and not row[declared]
        ]
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_cip_security_property_gap"
            if missing
            else "no_declared_cip_security_property_gap"
        )
        projections.append(
            {
                "connection_id": row["connection_id"],
                "originator_id": row["originator_id"],
                "target_id": row["target_id"],
                "unmet_property_labels": missing,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "connection_count": len(model["connections"]),
        "connection_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "industrial_network_contacted": False,
        "cip_security_profile_verified": False,
        "protected_transport_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Required and declared security properties are caller-supplied labels.",
            "No EtherNet/IP or CIP frame, device profile, certificate or key is inspected.",
            "A declared property gap does not prove an exploitable control connection.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CSD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class CipSecurityDeclarationReport:
    """Unsigned industrial connection projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CipSecurityDeclarationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CipSecurityDeclarationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cip_security(model: Any) -> CipSecurityDeclarationReport:
    return CipSecurityDeclarationReport._owned(_derive(model))


def verify_supplied_cip_security(
    report: Any, *, model: Any
) -> CipSecurityDeclarationReport:
    if type(report) is not CipSecurityDeclarationReport:
        raise CipSecurityDeclarationError("Exact CIP security wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CipSecurityDeclarationError("Report differs from separate original model")
    return CipSecurityDeclarationReport._owned(expected)


def verify_supplied_cip_security_bytes(
    report_bytes: bytes, *, model: Any
) -> CipSecurityDeclarationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise CipSecurityDeclarationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise CipSecurityDeclarationError("Exported report differs from original replay")
    return CipSecurityDeclarationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-cip-security-policy",
        "connections": [
            {
                "connection_id": "cell-link-one",
                "originator_id": "controller-a",
                "target_id": "drive-b",
                "context_complete": True,
                "endpoint_authentication_required": True,
                "endpoint_authentication_declared": True,
                "integrity_required": True,
                "integrity_declared": True,
                "confidentiality_required": True,
                "encryption_declared": False,
            }
        ],
    }
