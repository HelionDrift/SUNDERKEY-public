"""Compare synthetic endpoint package assignments with supplied ring policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_endpoint_assignment_policy_projection"
PROFILE_ID = "AOE-GC-D11-S18"
CAPABILITY_ID = "army.gc.d11.s18"
VECTOR_ID = "AV-GC-D11-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S18"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:375d5f01ddf7ed70585fffafa0fa5e57e169bd70b07d5b243157ab255eefa23a"
DOMAIN = "sunderkey.offline-endpoint-assignment-policy.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class EndpointAssignmentPolicyError(ValueError):
    """A supplied endpoint assignment model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "ring_ids", "package_policies", "assignments",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EndpointAssignmentPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise EndpointAssignmentPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    rings = [
        core.identifier(item, "ring ID")
        for item in core.bounded_list(model["ring_ids"], 32, "rings")
    ]
    if not rings or len(rings) != len(set(rings)):
        raise EndpointAssignmentPolicyError("Rings must be nonempty and unique")
    known = set(rings)
    packages = {}
    for item in core.bounded_list(model["package_policies"], 32, "package policies"):
        row = core.exact(item, {"package_id", "allowed_ring_ids"}, "package policy")
        package_id = core.identifier(row["package_id"], "package ID")
        if package_id in packages:
            raise EndpointAssignmentPolicyError("Duplicate package policy")
        allowed = [
            core.identifier(ring, "allowed ring ID")
            for ring in core.bounded_list(row["allowed_ring_ids"], 32, "allowed rings")
        ]
        if len(allowed) != len(set(allowed)) or not set(allowed).issubset(known):
            raise EndpointAssignmentPolicyError("Allowed rings are duplicate or unknown")
        packages[package_id] = set(allowed)
    if not packages:
        raise EndpointAssignmentPolicyError("At least one package policy is required")
    assignments = core.bounded_list(model["assignments"], 64, "assignments")
    if not assignments:
        raise EndpointAssignmentPolicyError("At least one assignment is required")
    rows = []
    seen = set()
    for item in assignments:
        row = core.exact(item, {
            "assignment_id", "package_id", "ring_id", "enabled_declared",
        }, "assignment")
        assignment_id = core.identifier(row["assignment_id"], "assignment ID")
        package_id = core.identifier(row["package_id"], "package ID")
        ring_id = core.identifier(row["ring_id"], "ring ID")
        if assignment_id in seen or package_id not in packages or ring_id not in known:
            raise EndpointAssignmentPolicyError("Duplicate or unknown assignment reference")
        seen.add(assignment_id)
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = []
        if enabled and ring_id not in packages[package_id]:
            flags.append("ring_outside_supplied_package_policy")
        rows.append({
            "assignment_id": assignment_id,
            "package_id": package_id,
            "ring_id": ring_id,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["assignment_id"])
    deviations = [row["assignment_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_endpoint_assignment_inventory_incomplete"]
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
        "assignment_projections": rows,
        "declared_policy_deviation_assignment_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_endpoint_assignment_projection",
        "source_authenticated": False,
        "management_service_connected": False,
        "device_connected": False,
        "package_content_read": False,
        "package_delivered": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Packages, deployment rings, assignments, and completeness are assertions.",
            "The model does not parse or verify SCCM or Intune tenant configuration.",
            "A policy mismatch does not prove installation, delivery, or device impact.",
            "No management service, package, device, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EAP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class EndpointAssignmentPolicyReport:
    """Unsigned assignment projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EndpointAssignmentPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EndpointAssignmentPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_endpoint_assignments(model: Any) -> EndpointAssignmentPolicyReport:
    return EndpointAssignmentPolicyReport._owned(_derive(model))


def verify_supplied_endpoint_assignments(
    report: Any, *, model: Any
) -> EndpointAssignmentPolicyReport:
    if type(report) is not EndpointAssignmentPolicyReport:
        raise EndpointAssignmentPolicyError("Exact endpoint assignment wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EndpointAssignmentPolicyError("Report differs from separate original model")
    return EndpointAssignmentPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-endpoint-assignment",
        "synthetic_fixture": True, "inventory_complete": True,
        "ring_ids": ["pilot", "production"],
        "package_policies": [{
            "package_id": "package-a", "allowed_ring_ids": ["pilot"],
        }],
        "assignments": [{
            "assignment_id": "assignment-a", "package_id": "package-a",
            "ring_id": "production", "enabled_declared": True,
        }],
    }
