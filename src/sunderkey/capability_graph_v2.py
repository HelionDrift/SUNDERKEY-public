"""Migration validation for the Army v2 collaborative capability graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .attack_vectors import AttackVectorCatalog
from .errors import RoutingError
from .qualification import _canonical_sha256
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

REPORT_DOMAIN = "sunderkey.capability-graph-v2-report.v1"
TARGET_CATALOG_ID = "sunderkey-army-capabilities-v2"
TARGET_CATALOG_VERSION = "2.0.0"


@dataclass(frozen=True)
class CapabilityGraphV2Report:
    report_id: str
    report_sha256: str
    preserved_capability_count: int
    capability_count: int
    assignment_count: int
    assignments_with_supporting_edges: int
    supporting_edge_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "preserved_capability_count": self.preserved_capability_count,
            "capability_count": self.capability_count,
            "assignment_count": self.assignment_count,
            "assignments_with_supporting_edges": self.assignments_with_supporting_edges,
            "supporting_edge_count": self.supporting_edge_count,
            "graph_status": "complete_vector_derived_collaboration_graph",
            "routing_policy_status": "not_created",
            "qualification_effect": "none",
            "routing_effect": "none",
            "execution_effect": "none",
        }


def validate_capability_graph_v2(
    baseline_registry: ExpertRegistry,
    baseline: CapabilityCatalog,
    target: CapabilityCatalog,
    registry: ExpertRegistry,
    vectors: AttackVectorCatalog,
) -> CapabilityGraphV2Report:
    """Verify primary-ID preservation and exact vector-derived support edges."""

    baseline.validate(baseline_registry)
    target.validate(registry)
    if target.catalog_id != TARGET_CATALOG_ID or target.catalog_version != TARGET_CATALOG_VERSION:
        raise RoutingError("Army v2 capability graph identity is invalid")

    baseline_capabilities = {item.id: item.to_dict() for item in baseline.capabilities}
    target_capabilities = {item.id: item.to_dict() for item in target.capabilities}
    for capability_id, definition in baseline_capabilities.items():
        if target_capabilities.get(capability_id) != definition:
            raise RoutingError(f"Army v2 changed v1 capability {capability_id}")

    baseline_assignments = baseline.assignments_by_profile_id
    target_assignments = target.assignments_by_profile_id
    primary_by_profile: dict[str, str] = {}
    for profile_id, assignment in target_assignments.items():
        if len(assignment.primary_capability_ids) != 1:
            raise RoutingError(f"{profile_id} must have one primary capability")
        primary_by_profile[profile_id] = assignment.primary_capability_ids[0]
        old = baseline_assignments.get(profile_id)
        if old is not None and assignment.primary_capability_ids != old.primary_capability_ids:
            raise RoutingError(f"Army v2 changed v1 primary assignment {profile_id}")

    vectors_by_primary = {item.primary_specialist_id: item for item in vectors.vectors}
    if set(vectors_by_primary) != set(target_assignments):
        raise RoutingError("Capability graph and vector primary profile sets differ")
    edge_count = 0
    with_support = 0
    for profile_id, assignment in target_assignments.items():
        vector = vectors_by_primary[profile_id]
        expected = tuple(
            sorted(primary_by_profile[item] for item in vector.supporting_specialist_ids)
        )
        if assignment.supporting_capability_ids != expected:
            raise RoutingError(f"{profile_id} supporting edges do not match its vector")
        with_support += bool(expected)
        edge_count += len(expected)

    body = {
        "baseline_catalog_id": baseline.catalog_id,
        "baseline_catalog_version": baseline.catalog_version,
        "baseline_catalog_sha256": baseline.canonical_sha256,
        "target_catalog_id": target.catalog_id,
        "target_catalog_version": target.catalog_version,
        "target_catalog_sha256": target.canonical_sha256,
        "vector_catalog_sha256": vectors.catalog_sha256,
        "preserved_capability_count": len(baseline.capabilities),
        "capability_count": len(target.capabilities),
        "assignment_count": len(target.profile_assignments),
        "assignments_with_supporting_edges": with_support,
        "supporting_edge_count": edge_count,
        "routing_policy_status": "not_created",
        "effect": "none",
    }
    digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
    return CapabilityGraphV2Report(
        report_id=f"CGR-{digest.removeprefix('sha256:')[:32].upper()}",
        report_sha256=digest,
        preserved_capability_count=len(baseline.capabilities),
        capability_count=len(target.capabilities),
        assignment_count=len(target.profile_assignments),
        assignments_with_supporting_edges=with_support,
        supporting_edge_count=edge_count,
    )


__all__ = ["CapabilityGraphV2Report", "validate_capability_graph_v2"]
