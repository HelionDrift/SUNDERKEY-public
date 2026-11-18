"""Compare supplied Java and .NET enterprise-server management labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "enterprise_server_supplied_management_projection"
PROFILE_ID = "AOE-GC-D16-S10"
CAPABILITY_ID = "army.gc.d16.s10"
VECTOR_ID = "AV-GC-D16-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S10"
WAVE_ID = "IW2-022"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e628f90705e89979b0b0111b444e638dbb63933152807ed92c8e1af099bac94c"
DOMAIN = "sunderkey.offline-enterprise-server-management.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_SERVERS = 32
STACKS = {"java", "dotnet"}
SCOPES = {"internal", "partner", "public", "unknown"}
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


class EnterpriseServerManagementError(ValueError):
    """The reduced server declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "servers"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EnterpriseServerManagementError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["servers"], MAX_SERVERS, "servers"):
        server = core.exact(
            row,
            {
                "server_id",
                "stack",
                "management_scope",
                "admin_mfa_enforced",
                "debug_endpoint_enabled",
                "policy_assertions_complete",
            },
            "server",
        )
        server_id = core.identifier(server["server_id"], "server ID")
        if server_id in seen:
            raise EnterpriseServerManagementError("Duplicate server ID")
        seen.add(server_id)
        core.choice(server["stack"], STACKS, "stack")
        core.choice(server["management_scope"], SCOPES, "management scope")
        for field in ("admin_mfa_enforced", "debug_endpoint_enabled"):
            if server[field] is not None:
                core.boolean(server[field], field)
        core.boolean(server["policy_assertions_complete"], "policy completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    servers = sorted(model["servers"], key=lambda row: row["server_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for server in servers:
        server_id = server["server_id"]
        if not server["policy_assertions_complete"]:
            uncertainty.append(
                {"issue": "incomplete_declared_server_policy", "server_id": server_id}
            )
            continue
        scope = server["management_scope"]
        if scope == "public":
            signals.append({"issue": "declared_public_management_scope", "server_id": server_id})
        elif scope == "unknown":
            uncertainty.append({"issue": "management_scope_unknown", "server_id": server_id})
        if server["admin_mfa_enforced"] is None:
            uncertainty.append({"issue": "admin_mfa_not_asserted", "server_id": server_id})
        elif scope == "public" and not server["admin_mfa_enforced"]:
            signals.append({"issue": "declared_public_admin_without_mfa", "server_id": server_id})
        if server["debug_endpoint_enabled"] is None:
            uncertainty.append({"issue": "debug_endpoint_state_unknown", "server_id": server_id})
        elif server["debug_endpoint_enabled"]:
            signals.append({"issue": "declared_debug_endpoint_enabled", "server_id": server_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "server_id": "none"})
    signals.sort(key=lambda row: (row["server_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["server_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_enterprise_server_review"
    elif uncertainty or not servers:
        disposition = "unknown"
    else:
        disposition = "no_declared_enterprise_server_review_signal"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "inventory_complete_asserted": model["inventory_complete"],
        "server_count": len(servers),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not servers),
        "disposition": disposition,
        "source_authenticated": False,
        "management_reachability_verified": False,
        "admin_authorization_verified": False,
        "server_contacted": False,
        "process_started": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Stack, management, MFA and debug labels are supplied assertions.",
            "No Java or .NET server configuration, policy, route or binary is parsed.",
            "A declared management difference is a review hypothesis, not access proof.",
            "No server, process, credential or target is contacted or started.",
            "An absent signal does not establish enterprise-server safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ESM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class EnterpriseServerManagementReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EnterpriseServerManagementError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EnterpriseServerManagementReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_enterprise_server_management(model: Any) -> EnterpriseServerManagementReport:
    return EnterpriseServerManagementReport._owned(_derive(model))


def verify_supplied_enterprise_server_management(
    report: Any, *, model: Any
) -> EnterpriseServerManagementReport:
    if type(report) is not EnterpriseServerManagementReport:
        raise EnterpriseServerManagementError("Exact enterprise server wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EnterpriseServerManagementError("Report differs from separate original model")
    return EnterpriseServerManagementReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-enterprise-server",
        "inventory_complete": True,
        "servers": [
            {
                "server_id": "server_a",
                "stack": "java",
                "management_scope": "public",
                "admin_mfa_enforced": False,
                "debug_endpoint_enabled": True,
                "policy_assertions_complete": True,
            }
        ],
    }
