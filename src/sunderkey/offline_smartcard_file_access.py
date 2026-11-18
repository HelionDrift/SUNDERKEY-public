"""Compare synthetic smartcard file access claims with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_smartcard_file_access_projection"
PROFILE_ID = "AOE-GD-D18-S13"
CAPABILITY_ID = "army.gd.d18.s13"
VECTOR_ID = "AV-GD-D18-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S13"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:0bae4f808515d25104a446cb9b3e134f1050a397127b10c906dae18bbe68ef98"
DOMAIN = "sunderkey.offline-smartcard-file-access.v1"
OPERATIONS = {"read", "write"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SmartcardFileAccessError(ValueError):
    """A supplied access declaration or original-model replay is invalid."""


def _roles(value: Any, known: set[str], label: str) -> list[str]:
    roles = [core.identifier(item, label) for item in core.bounded_list(value, 16, label)]
    if len(roles) != len(set(roles)) or not set(roles).issubset(known):
        raise SmartcardFileAccessError(f"{label} has duplicate or unknown role")
    return sorted(roles)


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "roles", "policies", "files",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SmartcardFileAccessError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise SmartcardFileAccessError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    roles = [
        core.identifier(item, "role ID") for item in core.bounded_list(model["roles"], 16, "roles")
    ]
    if not roles or len(roles) != len(set(roles)):
        raise SmartcardFileAccessError("Roles must be nonempty and unique")
    known = set(roles)
    policies = {}
    for item in core.bounded_list(model["policies"], 16, "policies"):
        row = core.exact(item, {
            "policy_id", "allowed_read_role_ids", "allowed_write_role_ids",
        }, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in policies:
            raise SmartcardFileAccessError("Duplicate policy ID")
        policies[policy_id] = {
            "read": _roles(row["allowed_read_role_ids"], known, "allowed read roles"),
            "write": _roles(row["allowed_write_role_ids"], known, "allowed write roles"),
        }
    if not policies:
        raise SmartcardFileAccessError("At least one policy is required")
    files = []
    seen = set()
    for item in core.bounded_list(model["files"], 64, "files"):
        row = core.exact(item, {
            "file_id", "policy_id", "declared_read_role_ids", "declared_write_role_ids",
        }, "file")
        file_id = core.identifier(row["file_id"], "file ID")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if file_id in seen or policy_id not in policies:
            raise SmartcardFileAccessError("Duplicate file or unknown policy")
        seen.add(file_id)
        mismatches = {}
        declared = {
            "read": _roles(row["declared_read_role_ids"], known, "declared read roles"),
            "write": _roles(row["declared_write_role_ids"], known, "declared write roles"),
        }
        for operation in sorted(OPERATIONS):
            mismatches[operation] = sorted(
                set(declared[operation]) - set(policies[policy_id][operation])
            )
        files.append({
            "file_id": file_id,
            "policy_id": policy_id,
            "declared_extra_read_role_ids": mismatches["read"],
            "declared_extra_write_role_ids": mismatches["write"],
        })
    if not files:
        raise SmartcardFileAccessError("At least one file is required")
    files.sort(key=lambda row: row["file_id"])
    deviations = sorted(
        row["file_id"] for row in files
        if row["declared_extra_read_role_ids"] or row["declared_extra_write_role_ids"]
    )
    unknown = [] if complete else ["supplied_smartcard_file_inventory_incomplete"]
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
        "supplied_role_count": len(roles),
        "file_projections": files,
        "declared_policy_deviation_file_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_smartcard_file_projection",
        "source_authenticated": False,
        "card_connected": False,
        "reader_connected": False,
        "apdu_sent": False,
        "file_content_read": False,
        "access_controls_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Roles, policies, file inventory, and access declarations are supplied assertions.",
            "A policy mismatch does not establish actual card access or a vulnerability.",
            "No card, reader, radio, credential, APDU, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SFA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SmartcardFileAccessReport:
    """Unsigned policy projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SmartcardFileAccessError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SmartcardFileAccessReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_smartcard_files(model: Any) -> SmartcardFileAccessReport:
    return SmartcardFileAccessReport._owned(_derive(model))


def verify_supplied_smartcard_files(
    report: Any, *, model: Any
) -> SmartcardFileAccessReport:
    if type(report) is not SmartcardFileAccessReport:
        raise SmartcardFileAccessError("Exact smartcard wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SmartcardFileAccessError("Report differs from separate original model")
    return SmartcardFileAccessReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-card-files",
        "synthetic_fixture": True, "inventory_complete": True,
        "roles": ["anonymous", "cardholder"],
        "policies": [{
            "policy_id": "private-file", "allowed_read_role_ids": ["cardholder"],
            "allowed_write_role_ids": ["cardholder"],
        }],
        "files": [{
            "file_id": "file-a", "policy_id": "private-file",
            "declared_read_role_ids": ["anonymous", "cardholder"],
            "declared_write_role_ids": ["cardholder"],
        }],
    }
