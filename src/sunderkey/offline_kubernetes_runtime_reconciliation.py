"""Reconcile bounded, caller-supplied Kubernetes workload declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "kubernetes_supplied_runtime_reconciliation"
PROFILE_ID = "AOE-GC-D15-S12"
CAPABILITY_ID = "army.gc.d15.s12"
VECTOR_ID = "AV-GC-D15-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S12"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5bd4891d97762de8894be24ea392501e960d6c978ca61c76e0dc2a98c9fe18a1"
DOMAIN = "sunderkey.offline-kubernetes-runtime-reconciliation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_WORKLOADS = 64
DELIVERY_KINDS = {"helm", "operator", "gitops"}
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class KubernetesRuntimeReconciliationError(ValueError):
    """A supplied runtime declaration or original replay is invalid."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise KubernetesRuntimeReconciliationError(f"{label} must be lowercase SHA-256")
    return value


def _workloads(value: Any, label: str, *, desired: bool) -> list[dict]:
    rows = core.bounded_list(value, MAX_WORKLOADS, label)
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        fields = {"namespace", "workload_id", "image_digest", "revision"}
        if desired:
            fields.add("delivery_kind")
        item = core.exact(row, fields, f"{label} row {index}")
        namespace = core.identifier(item["namespace"], "namespace")
        workload_id = core.identifier(item["workload_id"], "workload ID")
        key = namespace, workload_id
        if key in seen:
            raise KubernetesRuntimeReconciliationError(f"Duplicate {label} workload key")
        seen.add(key)
        _digest(item["image_digest"], "image digest")
        if desired:
            core.choice(item["delivery_kind"], DELIVERY_KINDS, "delivery kind")
            core.identifier(item["revision"], "desired revision")
        elif item["revision"] is not None:
            core.identifier(item["revision"], "runtime revision")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "desired", "runtime"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesRuntimeReconciliationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    _workloads(model["desired"], "desired", desired=True)
    _workloads(model["runtime"], "runtime", desired=False)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    complete = model["inventory_complete"]
    runtime = {
        (row["namespace"], row["workload_id"]): row for row in model["runtime"]
    }
    desired_keys = {(row["namespace"], row["workload_id"]) for row in model["desired"]}
    rows = []
    mismatches: list[dict[str, str]] = []
    for index, desired in enumerate(model["desired"]):
        observed = runtime.get((desired["namespace"], desired["workload_id"]))
        image_match = (
            desired["image_digest"] == observed["image_digest"]
            if complete and observed is not None else None
        )
        revision_match = (
            desired["revision"] == observed["revision"]
            if complete and observed is not None and observed["revision"] is not None else None
        )
        if complete and observed is None:
            mismatches.append({"issue": "runtime_workload_absent", "path": f"desired/{index}"})
        elif complete:
            if image_match is False:
                mismatches.append({"issue": "image_digest_mismatch", "path": f"desired/{index}"})
            if revision_match is False:
                mismatches.append({"issue": "revision_mismatch", "path": f"desired/{index}"})
        if not complete:
            status = "unknown"
        elif observed is None or image_match is False or revision_match is False:
            status = "candidate_supplied_runtime_mismatch"
        elif revision_match is None:
            status = "unknown"
        else:
            status = "supplied_runtime_consistent"
        rows.append({
            "namespace": desired["namespace"],
            "workload_id": desired["workload_id"],
            "delivery_kind": desired["delivery_kind"],
            "desired_image_digest": desired["image_digest"],
            "runtime_image_digest": observed["image_digest"] if observed is not None else None,
            "desired_revision": desired["revision"],
            "runtime_revision": observed["revision"] if observed is not None else None,
            "image_match": image_match,
            "revision_match": revision_match,
            "status": status,
        })
    for index, observed in enumerate(model["runtime"]):
        if complete and (observed["namespace"], observed["workload_id"]) not in desired_keys:
            mismatches.append({
                "issue": "undeclared_runtime_workload", "path": f"runtime/{index}"
            })
    if mismatches:
        disposition = "candidate_supplied_runtime_mismatch"
    elif not complete or not rows or any(row["status"] == "unknown" for row in rows):
        disposition = "unknown"
    else:
        disposition = "supplied_runtime_consistent"
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
        "desired_workload_count": len(model["desired"]),
        "runtime_workload_count": len(model["runtime"]),
        "workload_rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "cluster_queried": False,
        "helm_rendered": False,
        "operator_reconciled": False,
        "gitops_reconciled": False,
        "runtime_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Desired and runtime workload rows, including completeness, are caller-supplied.",
            "Only exact namespace, workload ID, image digest and revision values are compared.",
            "A null runtime revision leaves that comparison unknown.",
            "No Helm rendering, controller execution, cluster query or policy check occurs.",
            "Matching declarations do not establish deployment state or runtime safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KRR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KubernetesRuntimeReconciliationReport:
    """Unsigned reconciliation projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KubernetesRuntimeReconciliationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KubernetesRuntimeReconciliationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kubernetes_runtime_reconciliation(
    model: Any,
) -> KubernetesRuntimeReconciliationReport:
    return KubernetesRuntimeReconciliationReport._owned(_derive(model))


def verify_supplied_kubernetes_runtime_reconciliation(
    report: Any, *, model: Any,
) -> KubernetesRuntimeReconciliationReport:
    if type(report) is not KubernetesRuntimeReconciliationReport:
        raise KubernetesRuntimeReconciliationError("Exact runtime reconciliation wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KubernetesRuntimeReconciliationError("Report differs from separate original model")
    return KubernetesRuntimeReconciliationReport._owned(expected)


def verify_supplied_kubernetes_runtime_reconciliation_bytes(
    report_bytes: bytes, *, model: Any,
) -> KubernetesRuntimeReconciliationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise KubernetesRuntimeReconciliationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise KubernetesRuntimeReconciliationError("Exported report differs from original replay")
    return KubernetesRuntimeReconciliationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-kubernetes-runtime",
        "inventory_complete": True,
        "desired": [{
            "namespace": "demo",
            "workload_id": "web",
            "delivery_kind": "gitops",
            "revision": "revision-1",
            "image_digest": "sha256:" + "a" * 64,
        }],
        "runtime": [{
            "namespace": "demo",
            "workload_id": "web",
            "revision": "revision-1",
            "image_digest": "sha256:" + "a" * 64,
        }],
    }
