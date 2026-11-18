"""Compare supplied data-cloud grants with declared dataset sharing policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "data_cloud_supplied_grant_scope_policy"
PROFILE_ID = "AOE-GC-D14-S21"
CAPABILITY_ID = "army.gc.d14.s21"
VECTOR_ID = "AV-GC-D14-S21-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S21"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:13a17ecc358222f453fae7fa3dd17897ecc7984b12c93aa366abd4585af39d4c"
DOMAIN = "sunderkey.offline-data-cloud-grant-scope.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
CLASSIFICATIONS = {"public", "internal", "restricted"}
RECIPIENT_SCOPES = {"internal", "external", "public"}
PERMISSIONS = {"read", "write", "admin"}
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


class DataCloudGrantScopeError(ValueError):
    """A supplied data-cloud grant model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "warehouse_id", "datasets"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DataCloudGrantScopeError("Unsupported model version")
    for key in ("source_id", "warehouse_id"):
        core.identifier(model[key], key)
    datasets = core.bounded_list(model["datasets"], 32, "datasets")
    if not datasets:
        raise DataCloudGrantScopeError("At least one dataset is required")
    seen_datasets: set[str] = set()
    for item in datasets:
        dataset = core.exact(
            item,
            {
                "dataset_id",
                "classification",
                "external_sharing_allowed",
                "context_complete",
                "grants",
            },
            "dataset",
        )
        dataset_id = core.identifier(dataset["dataset_id"], "dataset ID")
        if dataset_id in seen_datasets:
            raise DataCloudGrantScopeError("Duplicate dataset ID")
        seen_datasets.add(dataset_id)
        core.choice(dataset["classification"], CLASSIFICATIONS, "classification")
        core.boolean(dataset["external_sharing_allowed"], "external-sharing policy")
        core.boolean(dataset["context_complete"], "context completeness")
        grants = core.bounded_list(dataset["grants"], 32, "grants")
        seen_grants: set[str] = set()
        for item_grant in grants:
            grant = core.exact(
                item_grant,
                {"grant_id", "recipient_scope", "permission", "active"},
                "grant",
            )
            grant_id = core.identifier(grant["grant_id"], "grant ID")
            if grant_id in seen_grants:
                raise DataCloudGrantScopeError("Duplicate grant ID")
            seen_grants.add(grant_id)
            core.choice(grant["recipient_scope"], RECIPIENT_SCOPES, "recipient scope")
            core.choice(grant["permission"], PERMISSIONS, "permission")
            core.boolean(grant["active"], "grant activity")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for dataset in model["datasets"]:
        mismatched = sorted(
            grant["grant_id"]
            for grant in dataset["grants"]
            if grant["active"]
            and (
                (
                    grant["recipient_scope"] == "public"
                    and dataset["classification"] == "restricted"
                )
                or (
                    grant["recipient_scope"] in {"external", "public"}
                    and not dataset["external_sharing_allowed"]
                )
            )
        )
        disposition = (
            "unknown"
            if not dataset["context_complete"]
            else "candidate_declared_data_grant_scope_mismatch"
            if mismatched
            else "no_declared_data_grant_scope_mismatch"
        )
        projections.append(
            {
                "dataset_id": dataset["dataset_id"],
                "mismatched_grant_ids": mismatched,
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
        "dataset_count": len(model["datasets"]),
        "dataset_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "data_cloud_queried": False,
        "effective_grant_verified": False,
        "data_access_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Dataset classification, sharing policy and grant scope are caller-supplied.",
            "Inherited roles, provider policies and effective data access are not evaluated.",
            "A declared scope mismatch does not prove data exposure or disclosure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DCG-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class DataCloudGrantScopeReport:
    """Unsigned data-cloud projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DataCloudGrantScopeError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DataCloudGrantScopeReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_data_cloud_grants(model: Any) -> DataCloudGrantScopeReport:
    return DataCloudGrantScopeReport._owned(_derive(model))


def verify_supplied_data_cloud_grants(
    report: Any, *, model: Any
) -> DataCloudGrantScopeReport:
    if type(report) is not DataCloudGrantScopeReport:
        raise DataCloudGrantScopeError("Exact data-cloud grant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DataCloudGrantScopeError("Report differs from separate original model")
    return DataCloudGrantScopeReport._owned(expected)


def verify_supplied_data_cloud_grants_bytes(
    report_bytes: bytes, *, model: Any
) -> DataCloudGrantScopeReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise DataCloudGrantScopeError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise DataCloudGrantScopeError("Exported report differs from original replay")
    return DataCloudGrantScopeReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-data-cloud-grants",
        "warehouse_id": "warehouse-one",
        "datasets": [
            {
                "dataset_id": "restricted-dataset",
                "classification": "restricted",
                "external_sharing_allowed": False,
                "context_complete": True,
                "grants": [
                    {
                        "grant_id": "external-reader",
                        "recipient_scope": "external",
                        "permission": "read",
                        "active": True,
                    },
                    {
                        "grant_id": "internal-admin",
                        "recipient_scope": "internal",
                        "permission": "admin",
                        "active": True,
                    },
                ],
            }
        ],
    }
