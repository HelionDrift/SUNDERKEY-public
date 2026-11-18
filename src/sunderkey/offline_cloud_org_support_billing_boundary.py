"""Project supplied organization support and billing approval declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cloud_org_supplied_support_billing_boundary"
PROFILE_ID = "AOE-GC-D14-S15"
CAPABILITY_ID = "army.gc.d14.s15"
VECTOR_ID = "AV-GC-D14-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S15"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:52c276120317b68813728211a7461f18ac328d50dd013f0da54aee46dd787792"
DOMAIN = "sunderkey.offline-cloud-org-support-billing-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
CHANNELS = {"organization", "billing", "support"}
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


class CloudOrgSupportBillingError(ValueError):
    """A declaration or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "organization_id", "access_paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CloudOrgSupportBillingError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["organization_id"], "organization ID")
    paths = core.bounded_list(model["access_paths"], 32, "access paths")
    if not paths:
        raise CloudOrgSupportBillingError("At least one access path is required")
    seen: set[str] = set()
    for item in paths:
        path = core.exact(
            item,
            {
                "path_id",
                "channel",
                "active",
                "privileged",
                "approval_required",
                "approval_recorded",
                "context_complete",
            },
            "access path",
        )
        path_id = core.identifier(path["path_id"], "path ID")
        if path_id in seen:
            raise CloudOrgSupportBillingError("Duplicate access path ID")
        seen.add(path_id)
        core.choice(path["channel"], CHANNELS, "channel")
        for key in (
            "active",
            "privileged",
            "approval_required",
            "approval_recorded",
            "context_complete",
        ):
            core.boolean(path[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    for path in model["access_paths"]:
        disposition = (
            "unknown"
            if not path["context_complete"]
            else "candidate_declared_approval_gap"
            if path["active"]
            and path["privileged"]
            and path["approval_required"]
            and not path["approval_recorded"]
            else "no_declared_approval_gap"
        )
        rows.append(
            {"path_id": path["path_id"], "channel": path["channel"], "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "organization_id": model["organization_id"],
        "access_path_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "provider_queried": False,
        "approval_authenticity_verified": False,
        "effective_access_verified": False,
        "billing_action_performed": False,
        "support_action_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Organization, path privilege and approval labels are caller-supplied.",
            "No support case, billing record, provider policy or effective access is queried.",
            "A missing declared approval does not prove unauthorized access or abuse.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OSB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class CloudOrgSupportBillingReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CloudOrgSupportBillingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CloudOrgSupportBillingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cloud_org_support_billing(model: Any) -> CloudOrgSupportBillingReport:
    return CloudOrgSupportBillingReport._owned(_derive(model))


def verify_supplied_cloud_org_support_billing(
    report: Any, *, model: Any
) -> CloudOrgSupportBillingReport:
    if type(report) is not CloudOrgSupportBillingReport:
        raise CloudOrgSupportBillingError("Exact cloud organization report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CloudOrgSupportBillingError("Report differs from separate original model")
    return CloudOrgSupportBillingReport._owned(expected)


def verify_supplied_cloud_org_support_billing_bytes(
    report_bytes: bytes, *, model: Any
) -> CloudOrgSupportBillingReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise CloudOrgSupportBillingError("Exported report differs from original replay")
    return CloudOrgSupportBillingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-org-paths",
        "organization_id": "org-one",
        "access_paths": [
            {
                "path_id": "support-admin",
                "channel": "support",
                "active": True,
                "privileged": True,
                "approval_required": True,
                "approval_recorded": False,
                "context_complete": True,
            },
            {
                "path_id": "billing-reader",
                "channel": "billing",
                "active": True,
                "privileged": False,
                "approval_required": True,
                "approval_recorded": False,
                "context_complete": True,
            },
        ],
    }
