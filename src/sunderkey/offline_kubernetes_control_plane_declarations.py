"""Compare supplied Kubernetes API and etcd declarations without cluster access."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "kubernetes_supplied_control_plane_declarations"
PROFILE_ID = "AOE-GC-D15-S06"
CAPABILITY_ID = "army.gc.d15.s06"
VECTOR_ID = "AV-GC-D15-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S06"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a7526c678c1ca0791e72924ff1e4514d4ff56e5eef691d3161632f21e30b4c33"
DOMAIN = "sunderkey.offline-kubernetes-control-plane-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class KubernetesControlPlaneDeclarationsError(ValueError):
    """A supplied control-plane declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str, dict[str, dict], dict[str, dict]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "api_inventory_complete",
            "store_inventory_complete",
            "api_servers",
            "stores",
            "checks",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesControlPlaneDeclarationsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["api_inventory_complete"], "API inventory completeness")
    core.boolean(model["store_inventory_complete"], "store inventory completeness")
    api_servers: dict[str, dict] = {}
    for row in core.bounded_list(model["api_servers"], 64, "API servers"):
        api = core.exact(row, {"api_id", "store_id", "client_tls_required"}, "API server")
        api_id = core.identifier(api["api_id"], "API server ID")
        if api_id in api_servers:
            raise KubernetesControlPlaneDeclarationsError("Duplicate API server ID")
        core.identifier(api["store_id"], "referenced store ID")
        core.boolean(api["client_tls_required"], "API client TLS requirement")
        api_servers[api_id] = api
    stores: dict[str, dict] = {}
    for row in core.bounded_list(model["stores"], 64, "stores"):
        store = core.exact(
            row,
            {"store_id", "client_tls_required", "at_rest_encryption_declared"},
            "store",
        )
        store_id = core.identifier(store["store_id"], "store ID")
        if store_id in stores:
            raise KubernetesControlPlaneDeclarationsError("Duplicate store ID")
        core.boolean(store["client_tls_required"], "store client TLS requirement")
        core.boolean(store["at_rest_encryption_declared"], "at-rest encryption declaration")
        stores[store_id] = store
    check_ids: set[str] = set()
    for row in core.bounded_list(model["checks"], 128, "checks"):
        check = core.exact(
            row,
            {
                "check_id",
                "api_id",
                "require_api_client_tls",
                "require_store_client_tls",
                "require_storage_encryption_at_rest",
                "claimed_compliant",
                "context_complete",
            },
            "check",
        )
        check_id = core.identifier(check["check_id"], "check ID")
        if check_id in check_ids:
            raise KubernetesControlPlaneDeclarationsError("Duplicate check ID")
        check_ids.add(check_id)
        core.identifier(check["api_id"], "referenced API server ID")
        for field in (
            "require_api_client_tls",
            "require_store_client_tls",
            "require_storage_encryption_at_rest",
            "claimed_compliant",
            "context_complete",
        ):
            core.boolean(check[field], field)
    return model, core.canonical(model), api_servers, stores


def _derive(value: Any) -> dict:
    model, source_text, api_servers, stores = _model(value)
    rows = []
    for check in sorted(model["checks"], key=lambda row: row["check_id"]):
        api = api_servers.get(check["api_id"])
        reasons = []
        unknown = not check["context_complete"]
        store_id = None
        if api is None:
            if model["api_inventory_complete"]:
                reasons.append("api_server_absent_from_complete_inventory")
            else:
                unknown = True
        else:
            store_id = api["store_id"]
            if check["require_api_client_tls"] and not api["client_tls_required"]:
                reasons.append("api_client_tls_requirement_not_declared")
            store = stores.get(store_id)
            if store is None:
                if model["store_inventory_complete"]:
                    reasons.append("store_absent_from_complete_inventory")
                else:
                    unknown = True
            else:
                if check["require_store_client_tls"] and not store["client_tls_required"]:
                    reasons.append("store_client_tls_requirement_not_declared")
                if (
                    check["require_storage_encryption_at_rest"]
                    and not store["at_rest_encryption_declared"]
                ):
                    reasons.append("storage_encryption_requirement_not_declared")
        projected = None if unknown else not reasons
        disposition = (
            "unknown_supplied_context"
            if projected is None
            else "candidate_claim_conflict"
            if projected != check["claimed_compliant"]
            else "supplied_claim_consistent"
        )
        rows.append(
            {
                "check_id": check["check_id"],
                "api_id": check["api_id"],
                "store_id": store_id,
                "reasons": reasons,
                "projected_compliant": projected,
                "claimed_compliant": check["claimed_compliant"],
                "disposition": disposition,
            }
        )
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
        "api_server_count": len(api_servers),
        "store_count": len(stores),
        "check_count": len(rows),
        "rows": rows,
        "candidate_count": sum(row["disposition"] == "candidate_claim_conflict" for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown_supplied_context" for row in rows),
        "source_authenticated": False,
        "cluster_contacted": False,
        "api_contacted": False,
        "etcd_contacted": False,
        "network_contacted": False,
        "configuration_changed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All API, store, local requirement, claim and completeness fields are supplied.",
            "TLS and encryption fields are declarations, not cryptographic validation.",
            "Store at-rest declarations do not model API-server resource encryption coverage.",
            "No Kubernetes API, etcd endpoint, cluster or encryption provider is contacted.",
            "A claim conflict is an unsigned review candidate, not proof of exposure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KCP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KubernetesControlPlaneDeclarationsReport:
    """Unsigned control-plane projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KubernetesControlPlaneDeclarationsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KubernetesControlPlaneDeclarationsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kubernetes_control_plane_declarations(
    model: Any,
) -> KubernetesControlPlaneDeclarationsReport:
    return KubernetesControlPlaneDeclarationsReport._owned(_derive(model))


def verify_supplied_kubernetes_control_plane_declarations(
    report: Any, *, model: Any
) -> KubernetesControlPlaneDeclarationsReport:
    if type(report) is not KubernetesControlPlaneDeclarationsReport:
        raise KubernetesControlPlaneDeclarationsError("Exact control-plane report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KubernetesControlPlaneDeclarationsError("Report differs from separate original model")
    return KubernetesControlPlaneDeclarationsReport._owned(expected)


def verify_supplied_kubernetes_control_plane_declarations_bytes(
    report_bytes: bytes, *, model: Any
) -> KubernetesControlPlaneDeclarationsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise KubernetesControlPlaneDeclarationsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise KubernetesControlPlaneDeclarationsError(
            "Exported report differs from original replay"
        )
    return KubernetesControlPlaneDeclarationsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-kubernetes-control-plane-declarations",
        "api_inventory_complete": True,
        "store_inventory_complete": True,
        "api_servers": [
            {
                "api_id": "api-a",
                "store_id": "store-a",
                "client_tls_required": True,
            }
        ],
        "stores": [
            {
                "store_id": "store-a",
                "client_tls_required": True,
                "at_rest_encryption_declared": False,
            }
        ],
        "checks": [
            {
                "check_id": "check-a",
                "api_id": "api-a",
                "require_api_client_tls": True,
                "require_store_client_tls": True,
                "require_storage_encryption_at_rest": True,
                "claimed_compliant": True,
                "context_complete": True,
            }
        ],
    }
