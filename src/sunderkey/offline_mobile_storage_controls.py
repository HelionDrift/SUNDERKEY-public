"""Compare supplied synthetic mobile storage controls with declared policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mobile_supplied_storage_control_projection"
PROFILE_ID = "AOE-GB-D08-S10"
CAPABILITY_ID = "army.gb.d08.s10"
VECTOR_ID = "AV-GB-D08-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S10"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:de6e0742d45ac18f9a2f48b9db31205304a7d3228686fc45c1984e28ed7cc1c9"
DOMAIN = "sunderkey.offline-mobile-storage-controls.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}
CONTROL_KEYS = ("encrypted_at_rest", "excluded_from_backup", "user_presence_required")


class MobileStorageControlError(ValueError):
    """The declaration or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "policies", "artifacts",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MobileStorageControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MobileStorageControlError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    policies = {}
    for item in core.bounded_list(model["policies"], 32, "policies"):
        row = core.exact(item, {"policy_id", "data_class", *CONTROL_KEYS}, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        data_class = core.choice(row["data_class"], {
            "public", "internal", "sensitive", "credential_material",
        }, "data class")
        if policy_id in policies:
            raise MobileStorageControlError("Duplicate policy ID")
        policies[policy_id] = {
            "data_class": data_class,
            **{key: core.boolean(row[key], key) for key in CONTROL_KEYS},
        }
    if not policies:
        raise MobileStorageControlError("At least one policy is required")
    rows = []
    seen = set()
    for item in core.bounded_list(model["artifacts"], 64, "artifacts"):
        row = core.exact(
            item, {"artifact_id", "policy_id", "storage_kind", *CONTROL_KEYS}, "artifact"
        )
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        if artifact_id in seen:
            raise MobileStorageControlError("Duplicate artifact ID")
        seen.add(artifact_id)
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id not in policies:
            raise MobileStorageControlError("Unknown artifact policy")
        kind = core.choice(row["storage_kind"], {
            "preferences", "database", "file", "key_store",
        }, "storage kind")
        actual = {key: core.boolean(row[key], key) for key in CONTROL_KEYS}
        missing = sorted(
            key for key in CONTROL_KEYS if policies[policy_id][key] and not actual[key]
        )
        rows.append({
            "artifact_id": artifact_id,
            "policy_id": policy_id,
            "data_class": policies[policy_id]["data_class"],
            "storage_kind": kind,
            "missing_declared_control_keys": missing,
        })
    if not rows:
        raise MobileStorageControlError("At least one artifact is required")
    rows.sort(key=lambda row: row["artifact_id"])
    unknown = [] if complete else ["supplied_artifact_inventory_incomplete"]
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
        "supplied_policy_count": len(policies),
        "supplied_artifact_count": len(rows),
        "artifact_projections": rows,
        "declared_control_gap_artifact_ids": sorted(
            row["artifact_id"] for row in rows if row["missing_declared_control_keys"]
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_storage_control_projection",
        "source_authenticated": False,
        "application_inspected": False,
        "cryptography_verified": False,
        "biometric_enforcement_verified": False,
        "backup_behavior_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Policies, inventory, and control states are supplied assertions.",
            "A declared gap is only a mismatch with a supplied policy, not a vulnerability.",
            "No app, device, storage, key material, or biometric system is inspected.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MSC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MobileStorageControlReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MobileStorageControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MobileStorageControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mobile_storage(model: Any) -> MobileStorageControlReport:
    return MobileStorageControlReport._owned(_derive(model))


def verify_supplied_mobile_storage(
    report: Any, *, model: Any
) -> MobileStorageControlReport:
    if type(report) is not MobileStorageControlReport:
        raise MobileStorageControlError("Exact storage wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MobileStorageControlError("Report differs from separate original model")
    return MobileStorageControlReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-mobile-storage",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "policies": [{
            "policy_id": "sensitive-local", "data_class": "sensitive",
            "encrypted_at_rest": True, "excluded_from_backup": True,
            "user_presence_required": False,
        }],
        "artifacts": [{
            "artifact_id": "cached-profile", "policy_id": "sensitive-local",
            "storage_kind": "database", "encrypted_at_rest": True,
            "excluded_from_backup": False, "user_presence_required": False,
        }],
    }
