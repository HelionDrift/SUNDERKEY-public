"""Compare supplied managed-service grants with intended resource scope."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "managed_paas_supplied_grant_scope"
PROFILE_ID = "AOE-GC-D14-S16"
CAPABILITY_ID = "army.gc.d14.s16"
VECTOR_ID = "AV-GC-D14-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S16"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b80c366055646740b1149f7fb27c19064b6d8d3b7e2bc92c15ea33805def97fa"
DOMAIN = "sunderkey.offline-managed-paas-grant-scope.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
SERVICE_KINDS = {"managed_database", "managed_application", "managed_queue"}
SCOPES = {"resource": 0, "project": 1, "tenant": 2}
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


class ManagedPaasGrantScopeError(ValueError):
    """A supplied managed-service grant model or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "services"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ManagedPaasGrantScopeError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    services = core.bounded_list(model["services"], 32, "services")
    if not services:
        raise ManagedPaasGrantScopeError("At least one service is required")
    seen_services: set[str] = set()
    for item in services:
        service = core.exact(
            item,
            {"service_id", "service_kind", "context_complete", "grants"},
            "service",
        )
        service_id = core.identifier(service["service_id"], "service ID")
        if service_id in seen_services:
            raise ManagedPaasGrantScopeError("Duplicate service ID")
        seen_services.add(service_id)
        core.choice(service["service_kind"], SERVICE_KINDS, "service kind")
        core.boolean(service["context_complete"], "context completeness")
        grants = core.bounded_list(service["grants"], 32, "grants")
        seen_grants: set[str] = set()
        for item_grant in grants:
            grant = core.exact(
                item_grant,
                {"grant_id", "principal_id", "intended_scope", "granted_scope", "active"},
                "grant",
            )
            grant_id = core.identifier(grant["grant_id"], "grant ID")
            if grant_id in seen_grants:
                raise ManagedPaasGrantScopeError("Duplicate grant ID")
            seen_grants.add(grant_id)
            core.identifier(grant["principal_id"], "principal ID")
            core.choice(grant["intended_scope"], set(SCOPES), "intended scope")
            core.choice(grant["granted_scope"], set(SCOPES), "granted scope")
            core.boolean(grant["active"], "grant activity")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for service in model["services"]:
        broader = sorted(
            grant["grant_id"]
            for grant in service["grants"]
            if grant["active"]
            and SCOPES[grant["granted_scope"]] > SCOPES[grant["intended_scope"]]
        )
        disposition = (
            "unknown"
            if not service["context_complete"]
            else "candidate_declared_managed_service_broad_grant"
            if broader
            else "no_declared_managed_service_broad_grant"
        )
        projections.append(
            {
                "service_id": service["service_id"],
                "service_kind": service["service_kind"],
                "broader_grant_ids": broader,
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
        "service_count": len(model["services"]),
        "service_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "provider_queried": False,
        "effective_grant_verified": False,
        "privilege_use_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Service, principal, intended scope and granted scope are caller-supplied labels.",
            "Provider role inheritance, conditions and effective permissions are not evaluated.",
            "A broader declared grant does not prove privilege use or unauthorized access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPG-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ManagedPaasGrantScopeReport:
    """Unsigned managed-service projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ManagedPaasGrantScopeError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ManagedPaasGrantScopeReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_managed_paas_grants(model: Any) -> ManagedPaasGrantScopeReport:
    return ManagedPaasGrantScopeReport._owned(_derive(model))


def verify_supplied_managed_paas_grants(
    report: Any, *, model: Any
) -> ManagedPaasGrantScopeReport:
    if type(report) is not ManagedPaasGrantScopeReport:
        raise ManagedPaasGrantScopeError("Exact managed-service grant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ManagedPaasGrantScopeError("Report differs from separate original model")
    return ManagedPaasGrantScopeReport._owned(expected)


def verify_supplied_managed_paas_grants_bytes(
    report_bytes: bytes, *, model: Any
) -> ManagedPaasGrantScopeReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ManagedPaasGrantScopeError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ManagedPaasGrantScopeError("Exported report differs from original replay")
    return ManagedPaasGrantScopeReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-managed-paas-grants",
        "services": [
            {
                "service_id": "database-one",
                "service_kind": "managed_database",
                "context_complete": True,
                "grants": [
                    {
                        "grant_id": "grant-broad",
                        "principal_id": "service-principal-one",
                        "intended_scope": "resource",
                        "granted_scope": "tenant",
                        "active": True,
                    },
                    {
                        "grant_id": "grant-narrow",
                        "principal_id": "service-principal-two",
                        "intended_scope": "resource",
                        "granted_scope": "resource",
                        "active": True,
                    },
                ],
            }
        ],
    }
