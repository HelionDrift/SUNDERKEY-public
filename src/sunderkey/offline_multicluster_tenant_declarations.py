"""Compare bounded, caller-supplied cluster and tenant membership declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "multicluster_supplied_tenant_declarations"
PROFILE_ID = "AOE-GC-D15-S14"
CAPABILITY_ID = "army.gc.d15.s14"
VECTOR_ID = "AV-GC-D15-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S14"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:900b5d773157c6c81b48fb72401cd911300982d551f3b621642768c369cc53d1"
DOMAIN = "sunderkey.offline-multicluster-tenant-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_RECORDS = 64
MAX_MEMBERSHIPS = 256
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class MulticlusterTenantDeclarationError(ValueError):
    """A supplied declaration or original-model replay is invalid."""


def _identifiers(value: Any, label: str) -> list[str]:
    rows = core.bounded_list(value, MAX_RECORDS, label)
    result = [core.identifier(item, label) for item in rows]
    if len(set(result)) != len(result):
        raise MulticlusterTenantDeclarationError(f"Duplicate {label}")
    return result


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "clusters", "tenants"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MulticlusterTenantDeclarationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    clusters = core.bounded_list(model["clusters"], MAX_RECORDS, "clusters")
    tenants = core.bounded_list(model["tenants"], MAX_RECORDS, "tenants")
    cluster_ids: set[str] = set()
    tenant_ids: set[str] = set()
    membership_count = 0
    for index, value in enumerate(clusters):
        item = core.exact(
            value, {"cluster_id", "managed_declared", "tenant_ids"}, f"cluster {index}"
        )
        cluster_id = core.identifier(item["cluster_id"], "cluster ID")
        if cluster_id in cluster_ids:
            raise MulticlusterTenantDeclarationError("Duplicate cluster ID")
        cluster_ids.add(cluster_id)
        core.boolean(item["managed_declared"], "managed declaration")
        membership_count += len(_identifiers(item["tenant_ids"], "tenant IDs"))
        if membership_count > MAX_MEMBERSHIPS:
            raise MulticlusterTenantDeclarationError("Too many cluster-tenant memberships")
    for index, value in enumerate(tenants):
        item = core.exact(value, {"tenant_id", "cluster_ids"}, f"tenant {index}")
        tenant_id = core.identifier(item["tenant_id"], "tenant ID")
        if tenant_id in tenant_ids:
            raise MulticlusterTenantDeclarationError("Duplicate tenant ID")
        tenant_ids.add(tenant_id)
        membership_count += len(_identifiers(item["cluster_ids"], "cluster IDs"))
        if membership_count > MAX_MEMBERSHIPS:
            raise MulticlusterTenantDeclarationError("Too many tenant-cluster memberships")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    complete = model["inventory_complete"]
    cluster_by_id = {item["cluster_id"]: item for item in model["clusters"]}
    tenant_by_id = {item["tenant_id"]: item for item in model["tenants"]}
    mismatches: list[dict[str, str]] = []
    cluster_rows = []
    for index, cluster in enumerate(model["clusters"]):
        checks = []
        for tenant_id in cluster["tenant_ids"]:
            tenant = tenant_by_id.get(tenant_id)
            match = tenant is not None and cluster["cluster_id"] in tenant["cluster_ids"]
            if complete and not match:
                mismatches.append({
                    "issue": "cluster_tenant_membership_mismatch",
                    "path": f"clusters/{index}/tenant_ids/{tenant_id}",
                })
            checks.append({"tenant_id": tenant_id, "reciprocal_match": match if complete else None})
        cluster_rows.append({
            "cluster_id": cluster["cluster_id"],
            "managed_declared": cluster["managed_declared"],
            "tenant_checks": checks,
        })
    tenant_rows = []
    for index, tenant in enumerate(model["tenants"]):
        checks = []
        for cluster_id in tenant["cluster_ids"]:
            cluster = cluster_by_id.get(cluster_id)
            match = cluster is not None and tenant["tenant_id"] in cluster["tenant_ids"]
            if complete and not match:
                mismatches.append({
                    "issue": "tenant_cluster_membership_mismatch",
                    "path": f"tenants/{index}/cluster_ids/{cluster_id}",
                })
            checks.append({
                "cluster_id": cluster_id,
                "reciprocal_match": match if complete else None,
            })
        tenant_rows.append({"tenant_id": tenant["tenant_id"], "cluster_checks": checks})
    if not complete:
        disposition = "unknown"
    elif mismatches:
        disposition = "candidate_supplied_membership_mismatch"
    elif (
        not cluster_rows or not tenant_rows
        or not any(row["tenant_checks"] for row in cluster_rows)
    ):
        disposition = "unknown"
    else:
        disposition = "supplied_membership_consistent"
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
        "cluster_record_count": len(cluster_rows),
        "tenant_record_count": len(tenant_rows),
        "cluster_rows": cluster_rows,
        "tenant_rows": tenant_rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "provider_contacted": False,
        "cluster_contacted": False,
        "managed_status_verified": False,
        "tenant_identity_verified": False,
        "tenant_isolation_verified": False,
        "authorization_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Cluster and tenant records, including completeness and managed status, "
            "are caller-supplied.",
            "Only reciprocal identifier memberships in a finite declaration subset are compared.",
            "No provider or cluster call, tenant authentication, or authorization check occurs.",
            "A matching declaration does not establish tenant identity, isolation, or safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OMT-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class MulticlusterTenantDeclarationReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MulticlusterTenantDeclarationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MulticlusterTenantDeclarationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_multicluster_tenant_declarations(
    model: Any,
) -> MulticlusterTenantDeclarationReport:
    return MulticlusterTenantDeclarationReport._owned(_derive(model))


def verify_supplied_multicluster_tenant_declarations(
    report: Any, *, model: Any,
) -> MulticlusterTenantDeclarationReport:
    if type(report) is not MulticlusterTenantDeclarationReport:
        raise MulticlusterTenantDeclarationError("Exact tenant declaration wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MulticlusterTenantDeclarationError("Report differs from separate original model")
    return MulticlusterTenantDeclarationReport._owned(expected)


def verify_supplied_multicluster_tenant_declarations_bytes(
    report_bytes: bytes, *, model: Any,
) -> MulticlusterTenantDeclarationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise MulticlusterTenantDeclarationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise MulticlusterTenantDeclarationError("Exported report differs from original replay")
    return MulticlusterTenantDeclarationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-cluster-tenants",
        "inventory_complete": True,
        "clusters": [{
            "cluster_id": "cluster-a", "managed_declared": True, "tenant_ids": ["tenant-a"]
        }],
        "tenants": [{"tenant_id": "tenant-a", "cluster_ids": ["cluster-a"]}],
    }
