"""Project caller-supplied enterprise SaaS privileged delegation boundaries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "saas_supplied_tenant_admin_delegation"
PROFILE_ID = "AOE-GC-D14-S17"
CAPABILITY_ID = "army.gc.d14.s17"
VECTOR_ID = "AV-GC-D14-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S17"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9ceefbc2fbc15b358468e97bdd168a5da41536426759ccd518b0fbfdcd1a2990"
DOMAIN = "sunderkey.offline-enterprise-saas-admin-delegation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
PRODUCT_FAMILIES = {"salesforce", "servicenow", "workday", "atlassian", "other"}
PRINCIPAL_SCOPES = {"internal", "external", "unknown"}
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


class EnterpriseSaasAdminError(ValueError):
    """A delegation model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "product_family",
            "tenant_id",
            "external_privileged_delegation_allowed",
            "delegations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EnterpriseSaasAdminError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["tenant_id"], "tenant ID")
    core.choice(model["product_family"], PRODUCT_FAMILIES, "product family")
    core.boolean(model["external_privileged_delegation_allowed"], "external delegation policy")
    delegations = core.bounded_list(model["delegations"], 32, "delegations")
    if not delegations:
        raise EnterpriseSaasAdminError("At least one delegation is required")
    seen: set[str] = set()
    for item in delegations:
        delegation = core.exact(
            item,
            {
                "delegation_id",
                "principal_scope",
                "privileged",
                "active",
                "context_complete",
            },
            "delegation",
        )
        delegation_id = core.identifier(delegation["delegation_id"], "delegation ID")
        if delegation_id in seen:
            raise EnterpriseSaasAdminError("Duplicate delegation ID")
        seen.add(delegation_id)
        core.choice(delegation["principal_scope"], PRINCIPAL_SCOPES, "principal scope")
        for key in ("privileged", "active", "context_complete"):
            core.boolean(delegation[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    for delegation in model["delegations"]:
        disposition = (
            "unknown"
            if not delegation["context_complete"] or delegation["principal_scope"] == "unknown"
            else "candidate_declared_admin_delegation_gap"
            if delegation["active"]
            and delegation["privileged"]
            and delegation["principal_scope"] == "external"
            and not model["external_privileged_delegation_allowed"]
            else "no_declared_admin_delegation_gap"
        )
        rows.append({"delegation_id": delegation["delegation_id"], "disposition": disposition})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "product_family": model["product_family"],
        "tenant_id": model["tenant_id"],
        "delegation_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "saas_queried": False,
        "inherited_roles_resolved": False,
        "effective_access_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Product, tenant policy, principal scope and delegation are caller-supplied labels.",
            "No SaaS platform is queried; platform-specific roles are not evaluated.",
            "A declared mismatch does not prove privileged access or data disclosure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SAD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class EnterpriseSaasAdminReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EnterpriseSaasAdminError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EnterpriseSaasAdminReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_enterprise_saas_admin(model: Any) -> EnterpriseSaasAdminReport:
    return EnterpriseSaasAdminReport._owned(_derive(model))


def verify_supplied_enterprise_saas_admin(report: Any, *, model: Any) -> EnterpriseSaasAdminReport:
    if type(report) is not EnterpriseSaasAdminReport:
        raise EnterpriseSaasAdminError("Exact enterprise SaaS report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EnterpriseSaasAdminError("Report differs from separate original model")
    return EnterpriseSaasAdminReport._owned(expected)


def verify_supplied_enterprise_saas_admin_bytes(
    report_bytes: bytes, *, model: Any
) -> EnterpriseSaasAdminReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise EnterpriseSaasAdminError("Exported report differs from original replay")
    return EnterpriseSaasAdminReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-saas-admin",
        "product_family": "salesforce",
        "tenant_id": "tenant-one",
        "external_privileged_delegation_allowed": False,
        "delegations": [
            {
                "delegation_id": "external-admin",
                "principal_scope": "external",
                "privileged": True,
                "active": True,
                "context_complete": True,
            },
            {
                "delegation_id": "internal-reader",
                "principal_scope": "internal",
                "privileged": False,
                "active": True,
                "context_complete": True,
            },
        ],
    }
