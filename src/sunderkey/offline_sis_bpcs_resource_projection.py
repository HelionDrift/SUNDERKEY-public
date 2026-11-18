"""Compare declared synthetic SIS and BPCS resource identifiers only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "industrial_supplied_sis_bpcs_resource_projection"
PROFILE_ID = "AOE-GD-D19-S05"
CAPABILITY_ID = "army.gd.d19.s05"
VECTOR_ID = "AV-GD-D19-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S05"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GD-D19-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:1499dd04ebef0cdb7c1292c211c642011c907dfbd739b5c27370c77ebf09147d"
DOMAIN = "sunderkey.offline-sis-bpcs-resource-projection.v1"
MAX_MODEL_BYTES = 4_096
MAX_REPORT_BYTES = 32_768
RESOURCE_KINDS = ("sensors", "logic_solvers", "final_elements")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SisBpcsResourceProjectionError(ValueError):
    """A supplied declaration or its original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SisBpcsResourceProjectionError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise SisBpcsResourceProjectionError("Model exceeds byte bound")
    return result


def _resources(value: Any, label: str) -> dict[str, list[str]]:
    value = core.exact(value, set(RESOURCE_KINDS), label)
    result = {}
    all_ids = set()
    for kind in RESOURCE_KINDS:
        items = value[kind]
        if type(items) is not list or not 1 <= len(items) <= 8:
            raise SisBpcsResourceProjectionError(
                "Each path needs 1 to 8 declared resources per role"
            )
        validated = []
        for item in items:
            core.identifier(item, "resource ID")
            if item in all_ids:
                raise SisBpcsResourceProjectionError("A resource repeats within one path")
            all_ids.add(item)
            validated.append(item)
        result[kind] = validated
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "sis", "bpcs"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SisBpcsResourceProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise SisBpcsResourceProjectionError("Only synthetic fixtures are accepted")
    sis = _resources(model["sis"], "SIS")
    bpcs = _resources(model["bpcs"], "BPCS")
    sis_ids = set().union(*(sis[kind] for kind in RESOURCE_KINDS))
    bpcs_ids = set().union(*(bpcs[kind] for kind in RESOURCE_KINDS))
    shared_ids = sorted(sis_ids & bpcs_ids)
    shared_roles = []
    for resource_id in shared_ids:
        sis_role = next(kind for kind in RESOURCE_KINDS if resource_id in sis[kind])
        bpcs_role = next(kind for kind in RESOURCE_KINDS if resource_id in bpcs[kind])
        shared_roles.append({
            "resource_sha256": "sha256:" + hashlib.sha256(resource_id.encode()).hexdigest(),
            "sis_role": sis_role,
            "bpcs_role": bpcs_role,
        })
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "sis_resource_counts": {kind: len(sis[kind]) for kind in RESOURCE_KINDS},
        "bpcs_resource_counts": {kind: len(bpcs[kind]) for kind in RESOURCE_KINDS},
        "declared_shared_resource_count": len(shared_ids),
        "declared_shared_resources": shared_roles,
        "declared_paths_complete": True,
        "design_independence_verified": False,
        "functional_safety_verified": False,
        "field_configuration_verified": False,
        "failure_effect_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "declaration_source_and_field_configuration_unverified",
            "shared_resource_failure_effect_unverified",
            "functional_safety_and_design_independence_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only identifiers in a synthetic supplied SIS and BPCS declaration are compared.",
            "Shared identifiers need engineering review and do not alone establish a defect.",
            "No-overlap does not prove independent failure behavior or functional safety.",
            "No process equipment, controller, or target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SBR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SisBpcsResourceProjectionReport:
    """Unsigned resource comparison requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SisBpcsResourceProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SisBpcsResourceProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_sis_bpcs_resource_projection(model: Any) -> SisBpcsResourceProjectionReport:
    return SisBpcsResourceProjectionReport._owned(_derive(model))


def verify_supplied_sis_bpcs_resource_projection(
    report: Any, *, model: Any
) -> SisBpcsResourceProjectionReport:
    if type(report) is not SisBpcsResourceProjectionReport:
        raise SisBpcsResourceProjectionError("Exact SIS/BPCS wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SisBpcsResourceProjectionError("Report differs from separate original model")
    return SisBpcsResourceProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-sis-bpcs-resources",
        "synthetic_fixture": True,
        "sis": {
            "sensors": ["sis-sensor-1", "shared-sensor-1"],
            "logic_solvers": ["sis-logic-1"],
            "final_elements": ["sis-final-1"],
        },
        "bpcs": {
            "sensors": ["bpcs-sensor-1", "shared-sensor-1"],
            "logic_solvers": ["bpcs-logic-1"],
            "final_elements": ["bpcs-final-1"],
        },
    }
