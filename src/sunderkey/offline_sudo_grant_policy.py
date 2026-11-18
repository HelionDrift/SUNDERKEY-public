"""Compare synthetic normalized sudo grant claims with supplied root policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_sudo_grant_policy_projection"
PROFILE_ID = "AOE-GC-D12-S03"
CAPABILITY_ID = "army.gc.d12.s03"
VECTOR_ID = "AV-GC-D12-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f888a0dacee6aa197bc2744f952d3ebd9bed747948d85c23192dbe9259590fa8"
DOMAIN = "sunderkey.offline-sudo-grant-policy.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SudoGrantPolicyError(ValueError):
    """A supplied normalized sudo model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "principal_ids", "command_policies", "grants",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SudoGrantPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise SudoGrantPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    principals = [
        core.identifier(item, "principal ID")
        for item in core.bounded_list(model["principal_ids"], 32, "principals")
    ]
    if not principals or len(principals) != len(set(principals)):
        raise SudoGrantPolicyError("Principals must be nonempty and unique")
    known = set(principals)
    policies = {}
    for item in core.bounded_list(model["command_policies"], 32, "command policies"):
        row = core.exact(item, {
            "command_id", "allowed_root_principal_ids", "root_password_required",
        }, "command policy")
        command_id = core.identifier(row["command_id"], "command ID")
        if command_id in policies:
            raise SudoGrantPolicyError("Duplicate command policy")
        allowed = [
            core.identifier(principal, "allowed principal")
            for principal in core.bounded_list(
                row["allowed_root_principal_ids"], 32, "allowed root principals"
            )
        ]
        if len(allowed) != len(set(allowed)) or not set(allowed).issubset(known):
            raise SudoGrantPolicyError("Allowed root principals are duplicate or unknown")
        policies[command_id] = {
            "allowed": set(allowed),
            "password_required": core.boolean(
                row["root_password_required"], "root password policy"
            ),
        }
    if not policies:
        raise SudoGrantPolicyError("At least one command policy is required")
    grants = core.bounded_list(model["grants"], 64, "grants")
    if not grants:
        raise SudoGrantPolicyError("At least one grant is required")
    rows = []
    seen = set()
    for item in grants:
        row = core.exact(item, {
            "grant_id", "principal_id", "command_id", "root_run_declared",
            "password_required_declared",
        }, "grant")
        grant_id = core.identifier(row["grant_id"], "grant ID")
        principal_id = core.identifier(row["principal_id"], "principal ID")
        command_id = core.identifier(row["command_id"], "command ID")
        if grant_id in seen or principal_id not in known or command_id not in policies:
            raise SudoGrantPolicyError("Duplicate grant or unknown principal or command")
        seen.add(grant_id)
        root = core.boolean(row["root_run_declared"], "root-run declaration")
        password = core.boolean(
            row["password_required_declared"], "password declaration"
        )
        flags = []
        if root:
            if principal_id not in policies[command_id]["allowed"]:
                flags.append("principal_outside_supplied_root_policy")
            if policies[command_id]["password_required"] and not password:
                flags.append("declared_password_requirement_absent")
        rows.append({
            "grant_id": grant_id,
            "principal_id": principal_id,
            "command_id": command_id,
            "root_run_declared": root,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["grant_id"])
    deviations = [row["grant_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_sudo_grant_inventory_incomplete"]
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
        "grant_projections": rows,
        "declared_policy_deviation_grant_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_sudo_grant_projection",
        "source_authenticated": False,
        "host_configuration_read": False,
        "sudoers_parsed": False,
        "command_executed": False,
        "privilege_change_attempted": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Principals, commands, grants, policy, and completeness are supplied assertions.",
            "Normalized labels are not parsed PAM, sudoers, or polkit configuration.",
            "A declared mismatch does not prove executable privilege elevation.",
            "No host, command, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SGP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SudoGrantPolicyReport:
    """Unsigned grant projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SudoGrantPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SudoGrantPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_sudo_grants(model: Any) -> SudoGrantPolicyReport:
    return SudoGrantPolicyReport._owned(_derive(model))


def verify_supplied_sudo_grants(
    report: Any, *, model: Any
) -> SudoGrantPolicyReport:
    if type(report) is not SudoGrantPolicyReport:
        raise SudoGrantPolicyError("Exact sudo-grant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SudoGrantPolicyError("Report differs from separate original model")
    return SudoGrantPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-sudo-grants",
        "synthetic_fixture": True, "inventory_complete": True,
        "principal_ids": ["operator", "reviewer"],
        "command_policies": [{
            "command_id": "maintenance", "allowed_root_principal_ids": ["operator"],
            "root_password_required": True,
        }],
        "grants": [{
            "grant_id": "grant-a", "principal_id": "reviewer",
            "command_id": "maintenance", "root_run_declared": True,
            "password_required_declared": False,
        }],
    }
