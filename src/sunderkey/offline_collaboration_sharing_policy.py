"""Compare synthetic collaboration-sharing claims with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_collaboration_sharing_policy_projection"
PROFILE_ID = "AOE-GC-D11-S16"
CAPABILITY_ID = "army.gc.d11.s16"
VECTOR_ID = "AV-GC-D11-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S16"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4b7933b0480069b607fc012b85594c3460e40b9d6ada30ab8344ab3547520616"
DOMAIN = "sunderkey.offline-collaboration-sharing-policy.v1"
KINDS = {"document", "site", "team"}
MODES = {"private", "organization", "guest", "anonymous"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class CollaborationSharingPolicyError(ValueError):
    """A supplied collaboration declaration or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "policies", "resources",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CollaborationSharingPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise CollaborationSharingPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    policies = {}
    for item in core.bounded_list(model["policies"], 32, "policies"):
        row = core.exact(item, {"policy_id", "allowed_share_modes"}, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in policies:
            raise CollaborationSharingPolicyError("Duplicate policy ID")
        modes = [
            core.choice(mode, MODES, "share mode")
            for mode in core.bounded_list(row["allowed_share_modes"], 4, "share modes")
        ]
        if len(modes) != len(set(modes)):
            raise CollaborationSharingPolicyError("Duplicate allowed share mode")
        policies[policy_id] = set(modes)
    if not policies:
        raise CollaborationSharingPolicyError("At least one policy is required")
    resources = core.bounded_list(model["resources"], 64, "resources")
    if not resources:
        raise CollaborationSharingPolicyError("At least one resource is required")
    rows = []
    seen = set()
    for item in resources:
        row = core.exact(item, {
            "resource_id", "kind", "policy_id", "share_mode_declared",
        }, "resource")
        resource_id = core.identifier(row["resource_id"], "resource ID")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if resource_id in seen or policy_id not in policies:
            raise CollaborationSharingPolicyError("Duplicate resource or unknown policy")
        seen.add(resource_id)
        kind = core.choice(row["kind"], KINDS, "resource kind")
        mode = core.choice(row["share_mode_declared"], MODES, "declared share mode")
        flags = [] if mode in policies[policy_id] else ["mode_outside_supplied_policy"]
        rows.append({
            "resource_id": resource_id,
            "kind": kind,
            "policy_id": policy_id,
            "share_mode_declared": mode,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["resource_id"])
    deviations = [row["resource_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_collaboration_inventory_incomplete"]
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
        "resource_projections": rows,
        "declared_policy_deviation_resource_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_collaboration_projection",
        "source_authenticated": False,
        "tenant_connected": False,
        "resource_content_read": False,
        "sharing_setting_verified": False,
        "sharing_change_performed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Resources, share modes, policy, and completeness are supplied assertions.",
            "Abstract labels do not parse or verify Microsoft 365 sharing controls.",
            "A declared mismatch does not prove public access or data exposure.",
            "No tenant, document, site, team, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CollaborationSharingPolicyReport:
    """Unsigned sharing projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CollaborationSharingPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CollaborationSharingPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_collaboration_sharing(model: Any) -> CollaborationSharingPolicyReport:
    return CollaborationSharingPolicyReport._owned(_derive(model))


def verify_supplied_collaboration_sharing(
    report: Any, *, model: Any
) -> CollaborationSharingPolicyReport:
    if type(report) is not CollaborationSharingPolicyReport:
        raise CollaborationSharingPolicyError("Exact collaboration wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CollaborationSharingPolicyError("Report differs from separate original model")
    return CollaborationSharingPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-collaboration-sharing",
        "synthetic_fixture": True, "inventory_complete": True,
        "policies": [{"policy_id": "internal-only", "allowed_share_modes": ["private"]}],
        "resources": [{
            "resource_id": "document-a", "kind": "document", "policy_id": "internal-only",
            "share_mode_declared": "anonymous",
        }],
    }
