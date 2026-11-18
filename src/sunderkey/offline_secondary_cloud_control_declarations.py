"""Project caller-supplied secondary-cloud control declarations without provider access."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "secondary_cloud_supplied_control_declarations"
PROFILE_ID = "AOE-GC-D14-S08"
CAPABILITY_ID = "army.gc.d14.s08"
VECTOR_ID = "AV-GC-D14-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S08"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:336477a5593a549a54a17ba3a5c5a8a4d083f2719664e8987c8cfacb622fa446"
DOMAIN = "sunderkey.offline-secondary-cloud-control-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
PROVIDERS = {"oci", "alibaba_cloud", "digitalocean", "other"}
STATES = {"enforced", "not_enforced", "unknown"}
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


class SecondaryCloudControlError(ValueError):
    """A declaration or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "provider_family", "tenant_id", "controls"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SecondaryCloudControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["tenant_id"], "tenant ID")
    core.choice(model["provider_family"], PROVIDERS, "provider family")
    controls = core.bounded_list(model["controls"], 32, "controls")
    if not controls:
        raise SecondaryCloudControlError("At least one control is required")
    seen: set[str] = set()
    for item in controls:
        control = core.exact(
            item, {"control_id", "required", "observed_state", "context_complete"}, "control"
        )
        control_id = core.identifier(control["control_id"], "control ID")
        if control_id in seen:
            raise SecondaryCloudControlError("Duplicate control ID")
        seen.add(control_id)
        core.boolean(control["required"], "required")
        core.choice(control["observed_state"], STATES, "observed state")
        core.boolean(control["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    for control in model["controls"]:
        disposition = (
            "unknown"
            if not control["context_complete"] or control["observed_state"] == "unknown"
            else "candidate_declared_control_gap"
            if control["required"] and control["observed_state"] == "not_enforced"
            else "no_declared_control_gap"
        )
        rows.append({"control_id": control["control_id"], "disposition": disposition})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "provider_family": model["provider_family"],
        "tenant_id": model["tenant_id"],
        "control_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "provider_queried": False,
        "control_effectiveness_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Provider family, tenant, requirements and observed states are caller-supplied labels.",
            "No provider-specific control semantics or effective enforcement are evaluated.",
            "A declared control gap does not establish cloud exposure or access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SCC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SecondaryCloudControlReport:
    """Unsigned projection that must be replayed against the original model."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SecondaryCloudControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SecondaryCloudControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_secondary_cloud_controls(model: Any) -> SecondaryCloudControlReport:
    return SecondaryCloudControlReport._owned(_derive(model))


def verify_supplied_secondary_cloud_controls(
    report: Any, *, model: Any
) -> SecondaryCloudControlReport:
    if type(report) is not SecondaryCloudControlReport:
        raise SecondaryCloudControlError("Exact secondary-cloud report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SecondaryCloudControlError("Report differs from separate original model")
    return SecondaryCloudControlReport._owned(expected)


def verify_supplied_secondary_cloud_controls_bytes(
    report_bytes: bytes, *, model: Any
) -> SecondaryCloudControlReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise SecondaryCloudControlError("Exported report differs from original replay")
    return SecondaryCloudControlReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-secondary-cloud",
        "provider_family": "oci",
        "tenant_id": "tenant-one",
        "controls": [
            {
                "control_id": "admin-mfa",
                "required": True,
                "observed_state": "not_enforced",
                "context_complete": True,
            },
            {
                "control_id": "audit-export",
                "required": True,
                "observed_state": "enforced",
                "context_complete": True,
            },
        ],
    }
