"""Project verified synthetic API outcomes into a planning-only attack graph."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .attack_world_model import (
    AttackEdge,
    AttackNode,
    AttackWorldModelError,
    AttackWorldSnapshot,
    EdgeKind,
    EvidenceBinding,
    NodeKind,
    ObservationDelta,
    VerificationState,
    apply_observation_delta,
    build_attack_world_snapshot,
)
from .offline_api_assessment import (
    API_TECHNIQUE_ID,
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    _validate_evidence,
    verify_offline_api_batch,
)
from .reference_adapters import OfflineReferenceAdapter

PROJECTION_DOMAIN = "sunderkey.offline-api-world-projection.v1"
NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "finding_publication": "none",
    "qualification": "none",
    "routing": "none",
    "target_execution": "none",
}


class OfflineApiWorldProjectionError(ValueError):
    """Raised when synthetic API cases cannot be projected conservatively."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _node_id(kind: str, *parts: str) -> str:
    return "api." + kind + "." + _digest({"kind": kind, "parts": list(parts)})[7:39]


def build_offline_api_world_projection(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Create only synthetic hypothesis and negative graph facts."""

    try:
        checked = verify_offline_api_batch(adapter=adapter, sources=sources, batch=batch)
        by_case = {source.case_id: source for source in sources}
        nodes: dict[str, AttackNode] = {}
        edges: list[AttackEdge] = []
        skipped: list[str] = []
        for case in checked.cases:
            if case.disposition not in {
                "corroborated_synthetic_signal",
                "negative_synthetic_result",
            }:
                skipped.append(case.case_id)
                continue
            records = _validate_evidence(by_case[case.case_id].evidence)
            controls = {
                record.content_sha256
                for record in records
                if record.attributes["expected_access"] and 200 <= record.status_code < 300
            }
            if case.disposition == "corroborated_synthetic_signal":
                selected = tuple(
                    record
                    for record in records
                    if not record.attributes["expected_access"]
                    and 200 <= record.status_code < 300
                    and record.content
                    and record.content_sha256 in controls
                )
                state = VerificationState.HYPOTHESIS
            else:
                selected = tuple(
                    record
                    for record in records
                    if not record.attributes["expected_access"]
                    and record.status_code in {401, 403, 404}
                )
                state = VerificationState.NEGATIVE
            if not selected:
                raise OfflineApiWorldProjectionError("case has no projection-safe response")
            for record in selected:
                principal_id = _node_id(
                    "principal", case.target_id, record.attributes["principal_id"]
                )
                object_id = _node_id(
                    "object",
                    case.target_id,
                    record.attributes["object_id"],
                    record.attributes["action"],
                )
                node_evidence = EvidenceBinding(
                    provenance_artifact_digest=checked.batch_sha256,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    confidence=0.0,
                    verification_state=VerificationState.HYPOTHESIS,
                    source_kind="synthetic_api_batch",
                )
                nodes.setdefault(
                    principal_id,
                    AttackNode(
                        node_id=principal_id,
                        node_kind=NodeKind.PRINCIPAL,
                        label="Synthetic API principal",
                        scope_refs=(checked.scope_id,),
                        technique_refs=(API_TECHNIQUE_ID,),
                        evidence=node_evidence,
                    ),
                )
                nodes.setdefault(
                    object_id,
                    AttackNode(
                        node_id=object_id,
                        node_kind=NodeKind.ASSET,
                        label="Synthetic API object and action",
                        scope_refs=(checked.scope_id,),
                        technique_refs=(API_TECHNIQUE_ID,),
                        evidence=node_evidence,
                    ),
                )
                fact_id = _node_id("fact", case.result_sha256, record.evidence_sha256)
                edges.append(
                    AttackEdge(
                        fact_id=fact_id,
                        source_node_id=principal_id,
                        target_node_id=object_id,
                        edge_kind=EdgeKind.AUTHORIZED_TO,
                        scope_refs=(checked.scope_id,),
                        technique_refs=(API_TECHNIQUE_ID,),
                        evidence=EvidenceBinding(
                            provenance_artifact_digest=case.result_sha256,
                            observed_at=observed_at,
                            expires_at=expires_at,
                            confidence=0.0,
                            verification_state=state,
                            source_kind="synthetic_api_case",
                        ),
                    )
                )
        snapshot = build_attack_world_snapshot(nodes.values(), edges)
    except (OfflineApiAssessmentError, AttackWorldModelError) as exc:
        raise OfflineApiWorldProjectionError("API batch or graph source is invalid") from exc
    body = {
        "schema_version": 1,
        "batch_sha256": checked.batch_sha256,
        "snapshot": snapshot.to_dict(),
        "skipped_case_ids": sorted(skipped),
        "origin_authentication": "not_verified",
        "path_verification": "not_established",
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "projection_sha256": _digest({"domain": PROJECTION_DOMAIN, "projection": body}),
    }


def verify_offline_api_world_projection(
    *,
    projection: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Reproduce every source and compare the exact graph projection."""

    expected = build_offline_api_world_projection(
        adapter=adapter,
        sources=sources,
        batch=batch,
        observed_at=observed_at,
        expires_at=expires_at,
    )
    try:
        same = isinstance(projection, Mapping) and _canonical(dict(projection)) == _canonical(
            expected
        )
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiWorldProjectionError("API world projection does not match sources")
    return expected


def append_offline_api_world_projection(
    *,
    parent_snapshot: AttackWorldSnapshot,
    projection: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
) -> AttackWorldSnapshot:
    """Append newly verified synthetic case facts to an immutable parent world."""

    try:
        parent = AttackWorldSnapshot.from_dict(parent_snapshot.to_dict())
        checked = verify_offline_api_world_projection(
            projection=projection,
            adapter=adapter,
            sources=sources,
            batch=batch,
            observed_at=observed_at,
            expires_at=expires_at,
        )
        projected = AttackWorldSnapshot.from_dict(checked["snapshot"])
        scope_id = str(batch["scope_id"])
        if not any(scope_id in node.scope_refs for node in parent.nodes):
            raise OfflineApiWorldProjectionError("API projection scope is absent from parent")
        parent_nodes = {node.node_id: node for node in parent.nodes}
        new_nodes = []
        for node in projected.nodes:
            old = parent_nodes.get(node.node_id)
            if old is None:
                new_nodes.append(node)
            elif (
                old.node_kind != node.node_kind
                or old.label != node.label
                or old.scope_refs != node.scope_refs
                or old.technique_refs != node.technique_refs
            ):
                raise OfflineApiWorldProjectionError("API projection redefines a parent node")
        parent_edges = {edge.fact_id: edge for edge in parent.edges}
        new_edges = []
        for edge in projected.edges:
            old = parent_edges.get(edge.fact_id)
            if old is None:
                new_edges.append(edge)
            elif old != edge:
                raise OfflineApiWorldProjectionError("API projection redefines a parent edge")
        if not new_nodes and not new_edges:
            raise OfflineApiWorldProjectionError("API projection adds no new world facts")
        return apply_observation_delta(
            parent,
            ObservationDelta(nodes=tuple(new_nodes), edges=tuple(new_edges)),
        )
    except (AttackWorldModelError, AttributeError, KeyError, TypeError) as exc:
        raise OfflineApiWorldProjectionError("API projection append inputs are invalid") from exc


__all__ = [
    "OfflineApiWorldProjectionError",
    "append_offline_api_world_projection",
    "build_offline_api_world_projection",
    "verify_offline_api_world_projection",
]
