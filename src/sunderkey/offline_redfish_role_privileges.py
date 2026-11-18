"""Compare caller-supplied Redfish role grants with declared account ceilings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "redfish_supplied_role_privilege_ceiling"
PROFILE_ID = "AOE-GD-D24-S02"
CAPABILITY_ID = "army.gd.d24.s02"
VECTOR_ID = "AV-GD-D24-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c5be8741724ba5662af62fa653e54d9c67e74095b9d4fcde3818b5e8e68ae169"
DOMAIN = "sunderkey.offline-redfish-role-privileges.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class RedfishRolePrivilegesError(ValueError):
    """A supplied Redfish declaration or original-model replay is invalid."""


def _privileges(value: Any, label: str) -> list[str]:
    rows = core.bounded_list(value, 32, label)
    privileges = [core.identifier(row, label) for row in rows]
    if len(privileges) != len(set(privileges)):
        raise RedfishRolePrivilegesError(f"Duplicate {label}")
    return privileges


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "roles", "accounts"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RedfishRolePrivilegesError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    roles = core.bounded_list(model["roles"], 64, "roles")
    accounts = core.bounded_list(model["accounts"], 64, "accounts")
    if not accounts:
        raise RedfishRolePrivilegesError("At least one account is required")
    role_ids: set[str] = set()
    for row in roles:
        role = core.exact(row, {"role_id", "assigned_privileges"}, "role")
        role_id = core.identifier(role["role_id"], "role ID")
        if role_id in role_ids:
            raise RedfishRolePrivilegesError("Duplicate role ID")
        role_ids.add(role_id)
        _privileges(role["assigned_privileges"], "assigned privileges")
    account_ids: set[str] = set()
    for row in accounts:
        account = core.exact(
            row, {"account_id", "role_id", "allowed_privileges"}, "account"
        )
        account_id = core.identifier(account["account_id"], "account ID")
        core.identifier(account["role_id"], "role ID")
        if account_id in account_ids:
            raise RedfishRolePrivilegesError("Duplicate account ID")
        account_ids.add(account_id)
        _privileges(account["allowed_privileges"], "allowed privileges")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    roles = {row["role_id"]: set(row["assigned_privileges"]) for row in model["roles"]}
    gaps = []
    for account in sorted(model["accounts"], key=lambda row: row["account_id"]):
        granted = roles.get(account["role_id"])
        if granted is None:
            gaps.append({
                "account_id": account["account_id"],
                "role_id": account["role_id"],
                "issue": "unresolved_role_reference",
                "excess_privileges": [],
            })
            continue
        excess = sorted(granted - set(account["allowed_privileges"]))
        if excess:
            gaps.append({
                "account_id": account["account_id"],
                "role_id": account["role_id"],
                "issue": "declared_privilege_ceiling_exceeded",
                "excess_privileges": excess,
            })
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_redfish_role_gap"
        if gaps
        else "no_supplied_redfish_role_gap"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "role_count": len(model["roles"]),
        "account_count": len(model["accounts"]),
        "gaps": gaps,
        "disposition": disposition,
        "candidate_count": len(gaps) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "bmc_contacted": False,
        "effective_privileges_verified": False,
        "exploit_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Accounts, roles, privilege names and intended ceilings are caller-supplied.",
            "No Redfish service, BMC, IPMI endpoint or account is contacted.",
            "Role inheritance, OEM privilege semantics and effective access are not resolved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RRP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RedfishRolePrivilegesReport:
    """Unsigned role projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RedfishRolePrivilegesError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RedfishRolePrivilegesReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_redfish_role_privileges(model: Any) -> RedfishRolePrivilegesReport:
    return RedfishRolePrivilegesReport._owned(_derive(model))


def verify_supplied_redfish_role_privileges(
    report: Any, *, model: Any
) -> RedfishRolePrivilegesReport:
    if type(report) is not RedfishRolePrivilegesReport:
        raise RedfishRolePrivilegesError("Exact Redfish role wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RedfishRolePrivilegesError("Report differs from separate original model")
    return RedfishRolePrivilegesReport._owned(expected)


def verify_supplied_redfish_role_privileges_bytes(
    report_bytes: bytes, *, model: Any
) -> RedfishRolePrivilegesReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise RedfishRolePrivilegesError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise RedfishRolePrivilegesError("Exported report differs from original replay")
    return RedfishRolePrivilegesReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-redfish-roles",
        "inventory_complete": True,
        "roles": [
            {"role_id": "Operator", "assigned_privileges": ["Login", "ConfigureComponents"]}
        ],
        "accounts": [
            {"account_id": "operator-a", "role_id": "Operator", "allowed_privileges": ["Login"]}
        ],
    }
