"""Compare supplied compute ingress labels with private-only intent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "compute_supplied_private_ingress_scope"
PROFILE_ID = "AOE-GC-D14-S02"
CAPABILITY_ID = "army.gc.d14.s02"
VECTOR_ID = "AV-GC-D14-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S02"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:72c7f0cc84b87cd3abadb52e4d5c4964b62191f1b64f1b53ed77f324ce10c809"
DOMAIN = "sunderkey.offline-compute-ingress-scope.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
WORKLOAD_KINDS = {"compute", "container", "serverless"}
INGRESS_SCOPES = {"private", "public", "unknown"}
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


class ComputeIngressScopeError(ValueError):
    """A supplied compute ingress model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "workloads"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ComputeIngressScopeError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    workloads = core.bounded_list(model["workloads"], 32, "workloads")
    if not workloads:
        raise ComputeIngressScopeError("At least one workload is required")
    seen: set[str] = set()
    for item in workloads:
        row = core.exact(
            item,
            {
                "workload_id",
                "workload_kind",
                "private_only_required",
                "ingress_scope",
                "authentication_required",
                "context_complete",
            },
            "workload",
        )
        workload_id = core.identifier(row["workload_id"], "workload ID")
        if workload_id in seen:
            raise ComputeIngressScopeError("Duplicate workload ID")
        seen.add(workload_id)
        core.choice(row["workload_kind"], WORKLOAD_KINDS, "workload kind")
        core.choice(row["ingress_scope"], INGRESS_SCOPES, "ingress scope")
        for key in ("private_only_required", "authentication_required", "context_complete"):
            core.boolean(row[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["workloads"]:
        disposition = (
            "unknown"
            if not row["context_complete"] or row["ingress_scope"] == "unknown"
            else "candidate_declared_private_compute_public_ingress"
            if row["private_only_required"] and row["ingress_scope"] == "public"
            else "no_declared_private_compute_public_ingress"
        )
        projections.append(
            {
                "workload_id": row["workload_id"],
                "workload_kind": row["workload_kind"],
                "ingress_scope": row["ingress_scope"],
                "authentication_required": row["authentication_required"],
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
        "workload_count": len(model["workloads"]),
        "workload_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "provider_queried": False,
        "effective_ingress_verified": False,
        "reachability_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Workload type, private-only intent and ingress scope are caller-supplied.",
            "No cloud provider configuration, network route or workload endpoint is inspected.",
            "A public ingress label does not prove reachability or unauthorized access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CIS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ComputeIngressScopeReport:
    """Unsigned compute ingress projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ComputeIngressScopeError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ComputeIngressScopeReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_compute_ingress(model: Any) -> ComputeIngressScopeReport:
    return ComputeIngressScopeReport._owned(_derive(model))


def verify_supplied_compute_ingress(
    report: Any, *, model: Any
) -> ComputeIngressScopeReport:
    if type(report) is not ComputeIngressScopeReport:
        raise ComputeIngressScopeError("Exact compute ingress wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ComputeIngressScopeError("Report differs from separate original model")
    return ComputeIngressScopeReport._owned(expected)


def verify_supplied_compute_ingress_bytes(
    report_bytes: bytes, *, model: Any
) -> ComputeIngressScopeReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ComputeIngressScopeError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ComputeIngressScopeError("Exported report differs from original replay")
    return ComputeIngressScopeReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-compute-ingress",
        "workloads": [
            {
                "workload_id": "function-one",
                "workload_kind": "serverless",
                "private_only_required": True,
                "ingress_scope": "public",
                "authentication_required": True,
                "context_complete": True,
            },
            {
                "workload_id": "container-one",
                "workload_kind": "container",
                "private_only_required": True,
                "ingress_scope": "private",
                "authentication_required": True,
                "context_complete": True,
            },
        ],
    }
