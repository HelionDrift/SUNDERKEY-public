"""Vector-bound qualification planning for every Army v2 specialist."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attack_vectors import AttackVectorCatalog
from .errors import QualificationError
from .qualification import QualificationStandard, _canonical_json, _canonical_sha256
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

CATALOG_DOMAIN = "sunderkey.qualification-plans-v2.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PLAN_FIELDS = {
    "profile_id",
    "vector_id",
    "scenario_family_id",
    "technical_focus",
    "evaluation_objective",
    "primary_capability_ids",
    "supporting_capability_ids",
    "independent_validator_id",
    "allowed_action_tiers",
    "required_scenario_variants",
    "required_observations",
    "required_evidence",
    "cleanup_and_restoration",
    "required_gate_ids",
    "critical_failures",
}


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise QualificationError(f"{label} must be a nonempty list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or not item.isascii():
            raise QualificationError(f"{label} must contain nonempty ASCII text")
        result.append(item)
    if len(result) != len(set(result)):
        raise QualificationError(f"{label} contains duplicates")
    return tuple(result)


@dataclass(frozen=True)
class QualificationPlanCatalogV2:
    catalog_sha256: str
    profile_plans: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, int]
    document_json: str

    @property
    def plans_by_profile_id(self) -> dict[str, dict[str, Any]]:
        return {item["profile_id"]: dict(item) for item in self.profile_plans}

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        capabilities: CapabilityCatalog,
        vectors: AttackVectorCatalog,
        standard: QualificationStandard,
    ) -> QualificationPlanCatalogV2:
        if not isinstance(raw, dict):
            raise QualificationError("Qualification plan catalog v2 must be an object")
        fields = {
            "schema_version",
            "plan_catalog_id",
            "plan_catalog_version",
            "catalog_sha256",
            "qualification_standard_id",
            "qualification_standard_version",
            "qualification_standard_sha256",
            "expert_catalog_id",
            "expert_catalog_version",
            "capability_catalog_id",
            "capability_catalog_version",
            "capability_catalog_sha256",
            "vector_catalog_id",
            "vector_catalog_version",
            "vector_catalog_sha256",
            "plan_status",
            "qualification_effect",
            "profile_plans",
            "coverage_summary",
            "limitations",
        }
        if set(raw) != fields:
            raise QualificationError("Qualification plan catalog v2 fields are invalid")
        if (
            raw.get("schema_version") != 2
            or raw.get("plan_catalog_id") != "sunderkey-army-qualification-plans-v2"
            or raw.get("plan_catalog_version") != "2.0.0"
            or raw.get("qualification_standard_id") != standard.standard_id
            or raw.get("qualification_standard_version") != standard.standard_version
            or raw.get("qualification_standard_sha256") != _canonical_sha256(standard.to_dict())
            or raw.get("expert_catalog_id") != registry.catalog_id
            or raw.get("expert_catalog_version") != registry.catalog_version
            or raw.get("capability_catalog_id") != capabilities.catalog_id
            or raw.get("capability_catalog_version") != capabilities.catalog_version
            or raw.get("capability_catalog_sha256") != capabilities.canonical_sha256
            or raw.get("vector_catalog_id") != "sunderkey-attack-vectors-v2"
            or raw.get("vector_catalog_version") != "2.0.0"
            or raw.get("vector_catalog_sha256") != vectors.catalog_sha256
            or raw.get("plan_status") != "defined_unexecuted"
            or raw.get("qualification_effect") != "none"
        ):
            raise QualificationError("Qualification plan catalog v2 binding is invalid")

        plans_raw = raw.get("profile_plans")
        if not isinstance(plans_raw, list):
            raise QualificationError("Qualification profile plans must be a list")
        plans: list[dict[str, Any]] = []
        seen: set[str] = set()
        vectors_by_profile = {item.primary_specialist_id: item for item in vectors.vectors}
        expected_profile_order = tuple(item.primary_specialist_id for item in vectors.vectors)
        assignments = capabilities.assignments_by_profile_id
        for raw_plan in plans_raw:
            if not isinstance(raw_plan, dict) or set(raw_plan) != PLAN_FIELDS:
                raise QualificationError("Qualification profile plan fields are invalid")
            profile_id = raw_plan.get("profile_id")
            if not isinstance(profile_id, str) or profile_id in seen:
                raise QualificationError("Qualification profile plan ID is invalid or duplicated")
            seen.add(profile_id)
            vector = vectors_by_profile.get(profile_id)
            assignment = assignments.get(profile_id)
            if vector is None or assignment is None:
                raise QualificationError(
                    f"Qualification plan references unknown profile {profile_id}"
                )
            if (
                raw_plan.get("vector_id") != vector.vector_id
                or raw_plan.get("scenario_family_id") != vector.qualification_scenario_id
                or raw_plan.get("technical_focus") != vector.name
                or tuple(raw_plan.get("primary_capability_ids", ()))
                != assignment.primary_capability_ids
                or tuple(raw_plan.get("supporting_capability_ids", ()))
                != assignment.supporting_capability_ids
                or raw_plan.get("independent_validator_id") != vector.independent_validator_id
                or tuple(raw_plan.get("allowed_action_tiers", ())) != vector.allowed_action_tiers
                or tuple(raw_plan.get("required_observations", ()))
                != vector.prerequisites_and_observations
                or tuple(raw_plan.get("required_evidence", ())) != vector.expected_evidence
                or tuple(raw_plan.get("cleanup_and_restoration", ()))
                != vector.cleanup_and_restoration
                or tuple(raw_plan.get("required_gate_ids", ())) != standard.gate_ids
            ):
                raise QualificationError(f"Qualification plan {profile_id} is not vector-bound")
            scenarios = _strings(
                raw_plan.get("required_scenario_variants"), f"{profile_id} scenarios"
            )
            if len(scenarios) < 6:
                raise QualificationError(f"Qualification plan {profile_id} lacks scenario variants")
            critical = _strings(raw_plan.get("critical_failures"), f"{profile_id} failures")
            if len(critical) < 5:
                raise QualificationError(f"Qualification plan {profile_id} lacks critical failures")
            objective = raw_plan.get("evaluation_objective")
            if (
                not isinstance(objective, str)
                or not objective.strip()
                or not objective.isascii()
                or vector.vector_id not in objective
            ):
                raise QualificationError(
                    f"Qualification plan {profile_id} objective is not specific"
                )
            plans.append(dict(raw_plan))

        if (
            seen != set(vectors_by_profile)
            or tuple(item["profile_id"] for item in plans) != expected_profile_order
            or len(plans) != 391
        ):
            raise QualificationError("Qualification plans do not cover every v2 specialist")
        coverage = raw.get("coverage_summary")
        expected_coverage = {
            "profile_plan_count": 391,
            "vector_bound_plan_count": 391,
            "plans_with_supporting_capabilities": 391,
            "plans_with_independent_validator": 391,
            "plans_with_cleanup_requirements": 391,
            "plans_with_critical_failures": 391,
        }
        if coverage != expected_coverage:
            raise QualificationError("Qualification plan coverage summary is invalid")
        _strings(raw.get("limitations"), "qualification plan limitations")
        catalog_sha256 = raw.get("catalog_sha256")
        if not isinstance(catalog_sha256, str) or SHA256_PATTERN.fullmatch(catalog_sha256) is None:
            raise QualificationError("Qualification plan catalog hash is invalid")
        canonical = dict(raw)
        canonical.pop("catalog_sha256")
        digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": canonical})
        if digest != catalog_sha256:
            raise QualificationError("Qualification plan catalog hash does not match content")
        return cls(
            catalog_sha256=catalog_sha256,
            profile_plans=tuple(plans),
            coverage_summary=dict(coverage),
            document_json=_canonical_json(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def load_qualification_plan_catalog_v2(
    source: str | Path,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    vectors: AttackVectorCatalog,
    standard: QualificationStandard,
) -> QualificationPlanCatalogV2:
    path = Path(source)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load qualification plans v2: {path}") from exc
    return QualificationPlanCatalogV2.from_dict(raw, registry, capabilities, vectors, standard)


__all__ = ["QualificationPlanCatalogV2", "load_qualification_plan_catalog_v2"]
