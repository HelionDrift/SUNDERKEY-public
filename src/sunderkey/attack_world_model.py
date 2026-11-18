"""Deterministic, offline attack world model and evidence graph.

The model is intentionally planning-only. It stores typed facts and evidence
references, never credential material, and cannot authorize, route, qualify, or
deploy anything.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

SNAPSHOT_DOMAIN = "sunderkey.attack-world-model.v1"
CONFLICT_DOMAIN = "sunderkey.attack-world-model-conflict.v1"
FRONTIER_DOMAIN = "sunderkey.attack-world-model-frontier.v1"
SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SNAPSHOT_ID_RE = re.compile(r"AWM-[0-9A-F]{32}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
CREDENTIAL_REF_RE = re.compile(r"credref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)

NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "qualification": "none",
    "routing": "none",
}

HARD_LIMITS = {
    "max_delta_facts": 1024,
    "max_depth": 32,
    "max_edges": 16384,
    "max_nodes": 4096,
    "max_path_expansions": 100000,
    "max_paths": 256,
}


class AttackWorldModelError(ValueError):
    """Raised when an attack world model contract is invalid."""


class NodeKind(StrEnum):
    """Typed node classes supported by the model."""

    ASSET = "asset"
    PRINCIPAL = "principal"
    IDENTITY = "identity"
    ENDPOINT = "endpoint"
    SERVICE = "service"
    DATA_STORE = "data_store"
    FINDING = "finding"
    CONTROL = "control"
    CREDENTIAL = "credential"
    TRUST_ZONE = "trust_zone"


class EdgeKind(StrEnum):
    """Typed directed relations supported by the model."""

    OBSERVED = "observed"
    ASSERTED = "asserted"
    INFERRED = "inferred"
    REACHABLE = "reachable"
    AUTHENTICATED_AS = "authenticated_as"
    AUTHORIZED_TO = "authorized_to"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    COMMUNICATES_WITH = "communicates_with"
    MITIGATED_BY = "mitigated_by"


class VerificationState(StrEnum):
    """Evidence verification states."""

    VERIFIED = "verified"
    NEGATIVE = "negative"
    HYPOTHESIS = "hypothesis"
    ABSTAINED = "abstained"


@dataclass(frozen=True)
class GraphLimits:
    """Resource limits applied to snapshots, deltas, and path queries."""

    max_nodes: int = 2048
    max_edges: int = 8192
    max_delta_facts: int = 512
    max_depth: int = 8
    max_path_expansions: int = 10000
    max_paths: int = 128

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise AttackWorldModelError(f"{name} must be a positive integer")
            if value > HARD_LIMITS[name]:
                raise AttackWorldModelError(f"{name} exceeds its hard safety limit")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_delta_facts": self.max_delta_facts,
            "max_depth": self.max_depth,
            "max_edges": self.max_edges,
            "max_nodes": self.max_nodes,
            "max_path_expansions": self.max_path_expansions,
            "max_paths": self.max_paths,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GraphLimits:
        _require_exact_fields(raw, set(HARD_LIMITS), "graph limits")
        return cls(**raw)


@dataclass(frozen=True)
class EvidenceBinding:
    """Hash-only provenance and temporal state for one graph fact."""

    provenance_artifact_digest: str
    observed_at: str
    confidence: float
    verification_state: VerificationState | str
    source_kind: str
    expires_at: str | None = None

    def __post_init__(self) -> None:
        _sha256(self.provenance_artifact_digest, "provenance artifact digest")
        observed = _utc(self.observed_at, "evidence observed_at")
        confidence = self.confidence
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0.0 <= confidence <= 1.0
        ):
            raise AttackWorldModelError("evidence confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", float(confidence))
        try:
            state = VerificationState(self.verification_state)
        except (TypeError, ValueError) as exc:
            raise AttackWorldModelError("evidence verification_state is invalid") from exc
        object.__setattr__(self, "verification_state", state)
        _token(self.source_kind, "evidence source_kind")
        if self.expires_at is not None:
            expires = _utc(self.expires_at, "evidence expires_at")
            if expires <= observed:
                raise AttackWorldModelError("evidence expires_at must follow observed_at")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "provenance_artifact_digest": self.provenance_artifact_digest,
            "source_kind": self.source_kind,
            "verification_state": self.verification_state.value,
        }
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at
        return result

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceBinding:
        _require_exact_fields(
            raw,
            {
                "confidence",
                "observed_at",
                "provenance_artifact_digest",
                "source_kind",
                "verification_state",
            },
            "evidence binding",
            optional={"expires_at"},
        )
        return cls(
            provenance_artifact_digest=raw["provenance_artifact_digest"],
            observed_at=raw["observed_at"],
            confidence=raw["confidence"],
            verification_state=raw["verification_state"],
            source_kind=raw["source_kind"],
            expires_at=raw.get("expires_at"),
        )

    def is_stale(self, as_of: str) -> bool:
        """Return whether this evidence has expired by the supplied UTC instant."""

        instant = _utc(as_of, "query as_of")
        return (
            self.expires_at is not None and _utc(self.expires_at, "evidence expires_at") <= instant
        )

    def is_active(self, as_of: str) -> bool:
        """Return whether this evidence was observed and has not expired."""

        instant = _utc(as_of, "query as_of")
        observed = _utc(self.observed_at, "evidence observed_at")
        return observed <= instant and not self.is_stale(as_of)


@dataclass(frozen=True)
class AttackNode:
    """One typed node fact."""

    node_id: str
    node_kind: NodeKind | str
    label: str
    scope_refs: tuple[str, ...]
    technique_refs: tuple[str, ...]
    evidence: EvidenceBinding
    credential_ref: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.node_id, "node_id")
        try:
            kind = NodeKind(self.node_kind)
        except (TypeError, ValueError) as exc:
            raise AttackWorldModelError("node_kind is invalid") from exc
        object.__setattr__(self, "node_kind", kind)
        _safe_text(self.label, "node label", 256)
        object.__setattr__(
            self,
            "scope_refs",
            _canonical_refs(self.scope_refs, "node scope_refs"),
        )
        object.__setattr__(
            self,
            "technique_refs",
            _canonical_refs(self.technique_refs, "node technique_refs"),
        )
        if not isinstance(self.evidence, EvidenceBinding):
            raise AttackWorldModelError("node evidence must be an EvidenceBinding")
        if kind is NodeKind.CREDENTIAL:
            if not isinstance(self.credential_ref, str) or not CREDENTIAL_REF_RE.fullmatch(
                self.credential_ref
            ):
                raise AttackWorldModelError("credential nodes require an opaque credref reference")
            _reject_secret_text(self.credential_ref, "credential reference")
        elif self.credential_ref is not None:
            raise AttackWorldModelError("credential_ref is only permitted for credential nodes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential_ref": self.credential_ref,
            "evidence": self.evidence.to_dict(),
            "label": self.label,
            "node_id": self.node_id,
            "node_kind": self.node_kind.value,
            "scope_refs": list(self.scope_refs),
            "technique_refs": list(self.technique_refs),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AttackNode:
        _require_exact_fields(
            raw,
            {
                "credential_ref",
                "evidence",
                "label",
                "node_id",
                "node_kind",
                "scope_refs",
                "technique_refs",
            },
            "attack node",
        )
        return cls(
            node_id=raw["node_id"],
            node_kind=raw["node_kind"],
            label=raw["label"],
            scope_refs=_refs_from_json(raw["scope_refs"], "node scope_refs"),
            technique_refs=_refs_from_json(raw["technique_refs"], "node technique_refs"),
            evidence=EvidenceBinding.from_dict(raw["evidence"]),
            credential_ref=raw["credential_ref"],
        )


@dataclass(frozen=True)
class AttackEdge:
    """One typed directed relation fact."""

    fact_id: str
    source_node_id: str
    target_node_id: str
    edge_kind: EdgeKind | str
    scope_refs: tuple[str, ...]
    technique_refs: tuple[str, ...]
    evidence: EvidenceBinding

    def __post_init__(self) -> None:
        _identifier(self.fact_id, "edge fact_id")
        _identifier(self.source_node_id, "edge source_node_id")
        _identifier(self.target_node_id, "edge target_node_id")
        try:
            kind = EdgeKind(self.edge_kind)
        except (TypeError, ValueError) as exc:
            raise AttackWorldModelError("edge_kind is invalid") from exc
        object.__setattr__(self, "edge_kind", kind)
        object.__setattr__(
            self,
            "scope_refs",
            _canonical_refs(self.scope_refs, "edge scope_refs"),
        )
        object.__setattr__(
            self,
            "technique_refs",
            _canonical_refs(self.technique_refs, "edge technique_refs"),
        )
        if not isinstance(self.evidence, EvidenceBinding):
            raise AttackWorldModelError("edge evidence must be an EvidenceBinding")

    @property
    def claim_key(self) -> tuple[Any, ...]:
        return (
            self.source_node_id,
            self.edge_kind.value,
            self.target_node_id,
            self.scope_refs,
            self.technique_refs,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_kind": self.edge_kind.value,
            "evidence": self.evidence.to_dict(),
            "fact_id": self.fact_id,
            "scope_refs": list(self.scope_refs),
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "technique_refs": list(self.technique_refs),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AttackEdge:
        _require_exact_fields(
            raw,
            {
                "edge_kind",
                "evidence",
                "fact_id",
                "scope_refs",
                "source_node_id",
                "target_node_id",
                "technique_refs",
            },
            "attack edge",
        )
        return cls(
            fact_id=raw["fact_id"],
            source_node_id=raw["source_node_id"],
            target_node_id=raw["target_node_id"],
            edge_kind=raw["edge_kind"],
            scope_refs=_refs_from_json(raw["scope_refs"], "edge scope_refs"),
            technique_refs=_refs_from_json(raw["technique_refs"], "edge technique_refs"),
            evidence=EvidenceBinding.from_dict(raw["evidence"]),
        )


@dataclass(frozen=True)
class EvidenceConflict:
    """Deterministic record of positive and negative evidence for one claim."""

    conflict_id: str
    claim: str
    fact_ids: tuple[str, ...]
    verification_states: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "conflict_id": self.conflict_id,
            "fact_ids": list(self.fact_ids),
            "verification_states": list(self.verification_states),
        }


@dataclass(frozen=True)
class AttackWorldSnapshot:
    """An immutable and content-addressed attack world snapshot."""

    snapshot_id: str
    snapshot_sha256: str
    parent_sha256: str | None
    limits: GraphLimits
    nodes: tuple[AttackNode, ...]
    edges: tuple[AttackEdge, ...]
    conflicts: tuple[EvidenceConflict, ...]

    def to_dict(self) -> dict[str, Any]:
        return _snapshot_document(
            snapshot_id=self.snapshot_id,
            snapshot_sha256=self.snapshot_sha256,
            parent_sha256=self.parent_sha256,
            limits=self.limits,
            nodes=self.nodes,
            edges=self.edges,
            conflicts=self.conflicts,
        )

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        expected_parent: AttackWorldSnapshot | None = None,
    ) -> AttackWorldSnapshot:
        _require_exact_fields(
            raw,
            {
                "conflicts",
                "edges",
                "effects",
                "limits",
                "nodes",
                "parent_sha256",
                "schema_version",
                "snapshot_id",
                "snapshot_sha256",
                "summary",
            },
            "attack world snapshot",
        )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise AttackWorldModelError("snapshot schema_version is invalid")
        if raw["effects"] != NO_EFFECTS:
            raise AttackWorldModelError("snapshot effects must all be none")
        if not isinstance(raw["nodes"], list) or not isinstance(raw["edges"], list):
            raise AttackWorldModelError("snapshot nodes and edges must be lists")
        if not isinstance(raw["conflicts"], list):
            raise AttackWorldModelError("snapshot conflicts must be a list")
        parent_sha256 = raw["parent_sha256"]
        if parent_sha256 is not None:
            _sha256(parent_sha256, "snapshot parent_sha256")
        limits = GraphLimits.from_dict(raw["limits"])
        nodes = tuple(AttackNode.from_dict(item) for item in raw["nodes"])
        edges = tuple(AttackEdge.from_dict(item) for item in raw["edges"])
        candidate = _assemble_snapshot(nodes, edges, limits, parent_sha256)
        if raw != candidate.to_dict():
            raise AttackWorldModelError(
                "snapshot identity, contents, summary, conflicts, or ordering is invalid"
            )
        if expected_parent is not None:
            candidate.verify_parent(expected_parent)
        return candidate

    def verify_parent(self, parent: AttackWorldSnapshot) -> None:
        """Verify the immediate immutable parent binding."""

        if not isinstance(parent, AttackWorldSnapshot):
            raise AttackWorldModelError("snapshot parent must be an attack world snapshot")
        if self.parent_sha256 != parent.snapshot_sha256:
            raise AttackWorldModelError("snapshot parent hash does not match")
        if self.limits != parent.limits:
            raise AttackWorldModelError("snapshot limits changed across the parent chain")


@dataclass(frozen=True)
class ObservationDelta:
    """A bounded append-only set of node and edge observations."""

    nodes: tuple[AttackNode, ...] = ()
    edges: tuple[AttackEdge, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        nodes = sorted(self.nodes, key=_node_sort_key)
        edges = sorted(self.edges, key=_edge_sort_key)
        return {
            "edges": [item.to_dict() for item in edges],
            "nodes": [item.to_dict() for item in nodes],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ObservationDelta:
        _require_exact_fields(raw, {"edges", "nodes"}, "observation delta")
        if not isinstance(raw["nodes"], list) or not isinstance(raw["edges"], list):
            raise AttackWorldModelError("observation delta members must be lists")
        candidate = cls(
            nodes=tuple(AttackNode.from_dict(item) for item in raw["nodes"]),
            edges=tuple(AttackEdge.from_dict(item) for item in raw["edges"]),
        )
        if raw != candidate.to_dict():
            raise AttackWorldModelError("observation delta ordering is not canonical")
        return candidate


@dataclass(frozen=True)
class PathQuery:
    """Bounded constraints for deterministic candidate path discovery."""

    start_node_ids: tuple[str, ...]
    target_node_ids: tuple[str, ...]
    required_scope_refs: tuple[str, ...] = ()
    required_technique_refs: tuple[str, ...] = ()
    as_of: str = "9999-12-31T23:59:59Z"
    max_depth: int | None = None
    max_expansions: int | None = None
    max_paths: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "start_node_ids",
            _canonical_refs(self.start_node_ids, "query start_node_ids", allow_empty=False),
        )
        object.__setattr__(
            self,
            "target_node_ids",
            _canonical_refs(self.target_node_ids, "query target_node_ids", allow_empty=False),
        )
        object.__setattr__(
            self,
            "required_scope_refs",
            _canonical_refs(self.required_scope_refs, "query required_scope_refs"),
        )
        object.__setattr__(
            self,
            "required_technique_refs",
            _canonical_refs(self.required_technique_refs, "query required_technique_refs"),
        )
        _utc(self.as_of, "query as_of")
        for name in ("max_depth", "max_expansions", "max_paths"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                raise AttackWorldModelError(f"query {name} must be a positive integer")


@dataclass(frozen=True)
class AttackPath:
    """A deterministic positive path with its weakest evidence state."""

    node_ids: tuple[str, ...]
    edge_fact_ids: tuple[str, ...]
    scope_refs: tuple[str, ...]
    technique_refs: tuple[str, ...]
    confidence: float
    path_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "edge_fact_ids": list(self.edge_fact_ids),
            "node_ids": list(self.node_ids),
            "path_state": self.path_state,
            "scope_refs": list(self.scope_refs),
            "technique_refs": list(self.technique_refs),
        }


@dataclass(frozen=True)
class AttackPathQueryResult:
    """Separated verified and hypothesis path results."""

    verified_paths: tuple[AttackPath, ...]
    hypothesis_paths: tuple[AttackPath, ...]
    conflicts: tuple[EvidenceConflict, ...]
    expansions: int
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflicts": [item.to_dict() for item in self.conflicts],
            "effects": dict(NO_EFFECTS),
            "expansions": self.expansions,
            "hypothesis_paths": [item.to_dict() for item in self.hypothesis_paths],
            "truncated": self.truncated,
            "verified_paths": [item.to_dict() for item in self.verified_paths],
        }


@dataclass(frozen=True)
class FrontierItem:
    """One deterministic evidence gap for later scheduling."""

    frontier_id: str
    kind: str
    subject_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]
    technique_refs: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "frontier_id": self.frontier_id,
            "kind": self.kind,
            "reason": self.reason,
            "scope_refs": list(self.scope_refs),
            "subject_refs": list(self.subject_refs),
            "technique_refs": list(self.technique_refs),
        }


def build_attack_world_snapshot(
    nodes: Iterable[AttackNode | Mapping[str, Any]],
    edges: Iterable[AttackEdge | Mapping[str, Any]],
    *,
    limits: GraphLimits | Mapping[str, Any] | None = None,
) -> AttackWorldSnapshot:
    """Build a canonical root snapshot from caller-owned facts."""

    parsed_limits = _coerce_limits(limits)
    parsed_nodes = tuple(_coerce_node(item) for item in nodes)
    parsed_edges = tuple(_coerce_edge(item) for item in edges)
    return _assemble_snapshot(parsed_nodes, parsed_edges, parsed_limits, None)


def apply_observation_delta(
    snapshot: AttackWorldSnapshot,
    delta: ObservationDelta | Mapping[str, Any],
) -> AttackWorldSnapshot:
    """Append a bounded observation delta and return a parent-bound snapshot."""

    if not isinstance(snapshot, AttackWorldSnapshot):
        raise AttackWorldModelError("delta parent must be an attack world snapshot")
    parsed = delta if isinstance(delta, ObservationDelta) else ObservationDelta.from_dict(delta)
    fact_count = len(parsed.nodes) + len(parsed.edges)
    if fact_count < 1:
        raise AttackWorldModelError("observation delta must contain at least one fact")
    if fact_count > snapshot.limits.max_delta_facts:
        raise AttackWorldModelError("observation delta exceeds max_delta_facts")

    nodes_by_id = {item.node_id: item for item in snapshot.nodes}
    for node in parsed.nodes:
        existing = nodes_by_id.get(node.node_id)
        if existing is not None and existing != node:
            raise AttackWorldModelError("observation delta redefines an existing node_id")
        nodes_by_id[node.node_id] = node

    edges_by_id = {item.fact_id: item for item in snapshot.edges}
    for edge in parsed.edges:
        existing = edges_by_id.get(edge.fact_id)
        if existing is not None and existing != edge:
            raise AttackWorldModelError("observation delta redefines an existing fact_id")
        edges_by_id[edge.fact_id] = edge

    if len(nodes_by_id) == len(snapshot.nodes) and len(edges_by_id) == len(snapshot.edges):
        raise AttackWorldModelError("observation delta contains no new facts")
    return _assemble_snapshot(
        tuple(nodes_by_id.values()),
        tuple(edges_by_id.values()),
        snapshot.limits,
        snapshot.snapshot_sha256,
    )


def detect_evidence_conflicts(
    snapshot: AttackWorldSnapshot,
    *,
    as_of: str | None = None,
) -> tuple[EvidenceConflict, ...]:
    """Detect positive and negative evidence for the same logical edge claim."""

    if as_of is not None:
        _utc(as_of, "conflict as_of")
    grouped: dict[tuple[Any, ...], list[AttackEdge]] = defaultdict(list)
    for edge in snapshot.edges:
        if as_of is None or edge.evidence.is_active(as_of):
            grouped[edge.claim_key].append(edge)

    conflicts: list[EvidenceConflict] = []
    for claim_key, facts in sorted(grouped.items(), key=lambda item: item[0]):
        states = {item.evidence.verification_state for item in facts}
        positive = states & {VerificationState.VERIFIED, VerificationState.HYPOTHESIS}
        if VerificationState.NEGATIVE not in states or not positive:
            continue
        fact_ids = tuple(sorted(item.fact_id for item in facts))
        state_values = tuple(sorted(item.value for item in states))
        claim = _claim_string(claim_key)
        digest = _canonical_sha256(
            {
                "claim": claim,
                "domain": CONFLICT_DOMAIN,
                "fact_ids": list(fact_ids),
                "verification_states": list(state_values),
            }
        )
        conflicts.append(
            EvidenceConflict(
                conflict_id=f"AWC-{digest.removeprefix('sha256:')[:32].upper()}",
                claim=claim,
                fact_ids=fact_ids,
                verification_states=state_values,
            )
        )
    return tuple(conflicts)


def query_candidate_attack_paths(
    snapshot: AttackWorldSnapshot,
    query: PathQuery | None = None,
    *,
    start_node_ids: Sequence[str] | None = None,
    target_node_ids: Sequence[str] | None = None,
    required_scope_refs: Sequence[str] = (),
    required_technique_refs: Sequence[str] = (),
    as_of: str = "9999-12-31T23:59:59Z",
    max_depth: int | None = None,
    max_expansions: int | None = None,
    max_paths: int | None = None,
) -> AttackPathQueryResult:
    """Find bounded, cycle-safe paths without performing any external action."""

    if query is not None and any(value is not None for value in (start_node_ids, target_node_ids)):
        raise AttackWorldModelError("supply either query or path keyword arguments")
    if query is None:
        if start_node_ids is None or target_node_ids is None:
            raise AttackWorldModelError("path start and target node IDs are required")
        query = PathQuery(
            start_node_ids=tuple(start_node_ids),
            target_node_ids=tuple(target_node_ids),
            required_scope_refs=tuple(required_scope_refs),
            required_technique_refs=tuple(required_technique_refs),
            as_of=as_of,
            max_depth=max_depth,
            max_expansions=max_expansions,
            max_paths=max_paths,
        )
    if not isinstance(query, PathQuery):
        raise AttackWorldModelError("query must be a PathQuery")

    depth_limit = _query_limit(query.max_depth, snapshot.limits.max_depth, "max_depth")
    expansion_limit = _query_limit(
        query.max_expansions,
        snapshot.limits.max_path_expansions,
        "max_expansions",
    )
    path_limit = _query_limit(query.max_paths, snapshot.limits.max_paths, "max_paths")
    nodes = {item.node_id: item for item in snapshot.nodes}
    unknown = (set(query.start_node_ids) | set(query.target_node_ids)) - set(nodes)
    if unknown:
        raise AttackWorldModelError(f"path query references unknown node: {sorted(unknown)[0]}")

    conflicts = detect_evidence_conflicts(snapshot, as_of=query.as_of)
    conflicted_fact_ids = {fact_id for conflict in conflicts for fact_id in conflict.fact_ids}
    required_scopes = set(query.required_scope_refs)

    def eligible_node(node: AttackNode) -> bool:
        return (
            node.evidence.is_active(query.as_of)
            and node.evidence.verification_state
            in {VerificationState.VERIFIED, VerificationState.HYPOTHESIS}
            and required_scopes.issubset(node.scope_refs)
        )

    eligible_nodes = {node_id for node_id, node in nodes.items() if eligible_node(node)}
    grouped: dict[tuple[Any, ...], list[AttackEdge]] = defaultdict(list)
    for edge in snapshot.edges:
        if (
            edge.fact_id not in conflicted_fact_ids
            and edge.evidence.is_active(query.as_of)
            and edge.evidence.verification_state
            in {VerificationState.VERIFIED, VerificationState.HYPOTHESIS}
            and required_scopes.issubset(edge.scope_refs)
            and edge.source_node_id in eligible_nodes
            and edge.target_node_id in eligible_nodes
        ):
            grouped[edge.claim_key].append(edge)

    adjacency: dict[str, list[AttackEdge]] = defaultdict(list)
    for facts in grouped.values():
        chosen = min(facts, key=_preferred_edge_key)
        adjacency[chosen.source_node_id].append(chosen)
    for edges in adjacency.values():
        edges.sort(key=_edge_sort_key)

    queue: deque[tuple[str, tuple[str, ...], tuple[AttackEdge, ...]]] = deque()
    for start in query.start_node_ids:
        if start in eligible_nodes:
            queue.append((start, (start,), ()))
    targets = set(query.target_node_ids)
    required_techniques = set(query.required_technique_refs)
    verified: list[AttackPath] = []
    hypotheses: list[AttackPath] = []
    expansions = 0
    truncated = False

    while queue and len(verified) + len(hypotheses) < path_limit:
        current, node_ids, path_edges = queue.popleft()
        covered_techniques = {
            ref for node_id in node_ids for ref in nodes[node_id].technique_refs
        } | {ref for edge in path_edges for ref in edge.technique_refs}
        if current in targets and required_techniques.issubset(covered_techniques):
            path = _make_path(node_ids, path_edges, nodes)
            if path.path_state == VerificationState.VERIFIED.value:
                verified.append(path)
            else:
                hypotheses.append(path)
        if len(path_edges) >= depth_limit:
            continue
        for edge in adjacency.get(current, ()):
            if expansions >= expansion_limit:
                truncated = True
                queue.clear()
                break
            expansions += 1
            if edge.target_node_id in node_ids:
                continue
            queue.append(
                (
                    edge.target_node_id,
                    (*node_ids, edge.target_node_id),
                    (*path_edges, edge),
                )
            )
    if queue:
        truncated = True
    return AttackPathQueryResult(
        verified_paths=tuple(sorted(verified, key=_path_sort_key)),
        hypothesis_paths=tuple(sorted(hypotheses, key=_path_sort_key)),
        conflicts=conflicts,
        expansions=expansions,
        truncated=truncated,
    )


def compute_uncovered_frontier(
    snapshot: AttackWorldSnapshot,
    *,
    required_scope_refs: Sequence[str] = (),
    required_technique_refs: Sequence[str] = (),
    as_of: str,
    start_node_ids: Sequence[str] = (),
    target_node_ids: Sequence[str] = (),
    limit: int | None = None,
) -> tuple[FrontierItem, ...]:
    """Compute deterministic evidence gaps suitable for later scheduling."""

    _utc(as_of, "frontier as_of")
    scopes = _canonical_refs(required_scope_refs, "frontier scope_refs")
    techniques = _canonical_refs(required_technique_refs, "frontier technique_refs")
    starts = _canonical_refs(start_node_ids, "frontier start_node_ids")
    targets = _canonical_refs(target_node_ids, "frontier target_node_ids")
    effective_limit = snapshot.limits.max_paths if limit is None else limit
    if (
        isinstance(effective_limit, bool)
        or not isinstance(effective_limit, int)
        or not 1 <= effective_limit <= snapshot.limits.max_paths
    ):
        raise AttackWorldModelError("frontier limit is outside snapshot bounds")

    drafts: set[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], str]] = set()
    scope_set = set(scopes)
    active_edges = [
        edge
        for edge in snapshot.edges
        if edge.evidence.is_active(as_of) and scope_set.issubset(edge.scope_refs)
    ]
    for technique in techniques:
        relevant = [edge for edge in active_edges if technique in edge.technique_refs]
        states = {edge.evidence.verification_state for edge in relevant}
        if VerificationState.VERIFIED in states:
            continue
        if VerificationState.HYPOTHESIS in states:
            kind = "hypothesis_requires_verification"
            reason = "The required technique is supported only by hypothesis evidence."
        elif VerificationState.NEGATIVE in states:
            kind = "negative_evidence_requires_review"
            reason = "The required technique has active negative evidence and no verification."
        else:
            kind = "missing_technique_evidence"
            reason = "The required technique has no active positive evidence."
        drafts.add((kind, (technique,), scopes, (technique,), reason))

    for node in snapshot.nodes:
        if node.evidence.is_stale(as_of):
            drafts.add(
                (
                    "stale_evidence",
                    (node.node_id,),
                    node.scope_refs,
                    node.technique_refs,
                    "The node fact expired before the frontier evaluation time.",
                )
            )
    for edge in snapshot.edges:
        if edge.evidence.is_stale(as_of):
            drafts.add(
                (
                    "stale_evidence",
                    (edge.fact_id,),
                    edge.scope_refs,
                    edge.technique_refs,
                    "The edge fact expired before the frontier evaluation time.",
                )
            )
    for conflict in detect_evidence_conflicts(snapshot, as_of=as_of):
        drafts.add(
            (
                "evidence_conflict",
                conflict.fact_ids,
                scopes,
                techniques,
                "Positive and negative evidence conflict for the same claim.",
            )
        )

    if bool(starts) != bool(targets):
        raise AttackWorldModelError("frontier start and target node IDs must be supplied together")
    if starts and targets:
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=starts,
            target_node_ids=targets,
            required_scope_refs=scopes,
            required_technique_refs=techniques,
            as_of=as_of,
        )
        reached_verified = {path.node_ids[-1] for path in result.verified_paths if path.node_ids}
        reached_hypothesis = {
            path.node_ids[-1] for path in result.hypothesis_paths if path.node_ids
        }
        for target in targets:
            if target in reached_verified:
                continue
            if target in reached_hypothesis:
                kind = "target_hypothesis_only"
                reason = "The target is reachable only through hypothesis evidence."
            else:
                kind = "target_not_verified_reachable"
                reason = "No active verified path reaches the required target."
            drafts.add((kind, (target,), scopes, techniques, reason))

    items = tuple(_frontier_item(*draft) for draft in sorted(drafts))
    return items[:effective_limit]


def _assemble_snapshot(
    nodes: tuple[AttackNode, ...],
    edges: tuple[AttackEdge, ...],
    limits: GraphLimits,
    parent_sha256: str | None,
) -> AttackWorldSnapshot:
    if parent_sha256 is not None:
        _sha256(parent_sha256, "snapshot parent_sha256")
    canonical_nodes = tuple(sorted(nodes, key=_node_sort_key))
    canonical_edges = tuple(sorted(edges, key=_edge_sort_key))
    if len(canonical_nodes) > limits.max_nodes:
        raise AttackWorldModelError("snapshot exceeds max_nodes")
    if len(canonical_edges) > limits.max_edges:
        raise AttackWorldModelError("snapshot exceeds max_edges")
    node_ids = [item.node_id for item in canonical_nodes]
    if len(node_ids) != len(set(node_ids)):
        raise AttackWorldModelError("snapshot node_id values must be unique")
    fact_ids = [item.fact_id for item in canonical_edges]
    if len(fact_ids) != len(set(fact_ids)):
        raise AttackWorldModelError("snapshot edge fact_id values must be unique")
    known = set(node_ids)
    for edge in canonical_edges:
        if edge.source_node_id not in known or edge.target_node_id not in known:
            raise AttackWorldModelError("snapshot edge references an unknown node")
    temporary = AttackWorldSnapshot(
        snapshot_id="",
        snapshot_sha256="",
        parent_sha256=parent_sha256,
        limits=limits,
        nodes=canonical_nodes,
        edges=canonical_edges,
        conflicts=(),
    )
    conflicts = detect_evidence_conflicts(temporary)
    body = _snapshot_body(parent_sha256, limits, canonical_nodes, canonical_edges, conflicts)
    digest = _canonical_sha256({"domain": SNAPSHOT_DOMAIN, "snapshot": body})
    return AttackWorldSnapshot(
        snapshot_id=f"AWM-{digest.removeprefix('sha256:')[:32].upper()}",
        snapshot_sha256=digest,
        parent_sha256=parent_sha256,
        limits=limits,
        nodes=canonical_nodes,
        edges=canonical_edges,
        conflicts=conflicts,
    )


def _snapshot_body(
    parent_sha256: str | None,
    limits: GraphLimits,
    nodes: tuple[AttackNode, ...],
    edges: tuple[AttackEdge, ...],
    conflicts: tuple[EvidenceConflict, ...],
) -> dict[str, Any]:
    return {
        "conflicts": [item.to_dict() for item in conflicts],
        "edges": [item.to_dict() for item in edges],
        "effects": dict(NO_EFFECTS),
        "limits": limits.to_dict(),
        "nodes": [item.to_dict() for item in nodes],
        "parent_sha256": parent_sha256,
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "conflict_count": len(conflicts),
            "edge_count": len(edges),
            "node_count": len(nodes),
        },
    }


def _snapshot_document(
    *,
    snapshot_id: str,
    snapshot_sha256: str,
    parent_sha256: str | None,
    limits: GraphLimits,
    nodes: tuple[AttackNode, ...],
    edges: tuple[AttackEdge, ...],
    conflicts: tuple[EvidenceConflict, ...],
) -> dict[str, Any]:
    if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        raise AttackWorldModelError("snapshot_id is invalid")
    _sha256(snapshot_sha256, "snapshot_sha256")
    body = _snapshot_body(parent_sha256, limits, nodes, edges, conflicts)
    return {**body, "snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256}


def _make_path(
    node_ids: tuple[str, ...],
    edges: tuple[AttackEdge, ...],
    nodes: Mapping[str, AttackNode],
) -> AttackPath:
    evidence = [nodes[node_id].evidence for node_id in node_ids]
    evidence.extend(edge.evidence for edge in edges)
    states = {item.verification_state for item in evidence}
    state = (
        VerificationState.HYPOTHESIS.value
        if VerificationState.HYPOTHESIS in states
        else VerificationState.VERIFIED.value
    )
    return AttackPath(
        node_ids=node_ids,
        edge_fact_ids=tuple(edge.fact_id for edge in edges),
        scope_refs=tuple(
            sorted(
                {ref for node_id in node_ids for ref in nodes[node_id].scope_refs}
                | {ref for edge in edges for ref in edge.scope_refs}
            )
        ),
        technique_refs=tuple(
            sorted(
                {ref for node_id in node_ids for ref in nodes[node_id].technique_refs}
                | {ref for edge in edges for ref in edge.technique_refs}
            )
        ),
        confidence=min(item.confidence for item in evidence),
        path_state=state,
    )


def _frontier_item(
    kind: str,
    subject_refs: tuple[str, ...],
    scope_refs: tuple[str, ...],
    technique_refs: tuple[str, ...],
    reason: str,
) -> FrontierItem:
    body = {
        "kind": kind,
        "reason": reason,
        "scope_refs": list(scope_refs),
        "subject_refs": list(subject_refs),
        "technique_refs": list(technique_refs),
    }
    digest = _canonical_sha256({"domain": FRONTIER_DOMAIN, "frontier": body})
    return FrontierItem(
        frontier_id=f"AWF-{digest.removeprefix('sha256:')[:32].upper()}",
        kind=kind,
        subject_refs=subject_refs,
        scope_refs=scope_refs,
        technique_refs=technique_refs,
        reason=reason,
    )


def _coerce_limits(raw: GraphLimits | Mapping[str, Any] | None) -> GraphLimits:
    if raw is None:
        return GraphLimits()
    if isinstance(raw, GraphLimits):
        return raw
    return GraphLimits.from_dict(raw)


def _coerce_node(raw: AttackNode | Mapping[str, Any]) -> AttackNode:
    return raw if isinstance(raw, AttackNode) else AttackNode.from_dict(raw)


def _coerce_edge(raw: AttackEdge | Mapping[str, Any]) -> AttackEdge:
    return raw if isinstance(raw, AttackEdge) else AttackEdge.from_dict(raw)


def _node_sort_key(node: AttackNode) -> tuple[str, str]:
    return node.node_id, _canonical_json(node.to_dict())


def _edge_sort_key(edge: AttackEdge) -> tuple[str, str, str, str]:
    return (
        edge.source_node_id,
        edge.target_node_id,
        edge.edge_kind.value,
        edge.fact_id,
    )


def _preferred_edge_key(edge: AttackEdge) -> tuple[Any, ...]:
    state_rank = 0 if edge.evidence.verification_state is VerificationState.VERIFIED else 1
    return (
        state_rank,
        -edge.evidence.confidence,
        edge.evidence.observed_at,
        edge.fact_id,
    )


def _path_sort_key(path: AttackPath) -> tuple[Any, ...]:
    return (len(path.edge_fact_ids), path.node_ids, path.edge_fact_ids)


def _claim_string(claim_key: tuple[Any, ...]) -> str:
    source, kind, target, scopes, techniques = claim_key
    return _canonical_json(
        {
            "edge_kind": kind,
            "scope_refs": list(scopes),
            "source_node_id": source,
            "target_node_id": target,
            "technique_refs": list(techniques),
        }
    )


def _query_limit(requested: int | None, maximum: int, name: str) -> int:
    if requested is None:
        return maximum
    if requested > maximum:
        raise AttackWorldModelError(f"query {name} exceeds snapshot limits")
    return requested


def _canonical_refs(
    raw: Sequence[str] | tuple[str, ...],
    label: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise AttackWorldModelError(f"{label} must be a sequence")
    values = tuple(_identifier(item, label) for item in raw)
    canonical = tuple(sorted(set(values)))
    if len(values) != len(canonical):
        raise AttackWorldModelError(f"{label} must not contain duplicates")
    if len(canonical) > 64:
        raise AttackWorldModelError(f"{label} exceeds 64 references")
    if not allow_empty and not canonical:
        raise AttackWorldModelError(f"{label} must not be empty")
    return canonical


def _refs_from_json(raw: Any, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise AttackWorldModelError(f"{label} must be a list")
    result = _canonical_refs(raw, label)
    if list(result) != raw:
        raise AttackWorldModelError(f"{label} ordering is not canonical")
    return result


def _safe_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AttackWorldModelError(f"{label} must be nonempty text within {maximum} chars")
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        raise AttackWorldModelError(f"{label} must contain printable ASCII only")
    _reject_secret_text(value, label)
    return value


def _reject_secret_text(value: str, label: str) -> None:
    if SECRET_RE.search(value):
        raise AttackWorldModelError(f"{label} appears to contain secret material")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise AttackWorldModelError(f"{label} is not a portable identifier")
    _reject_secret_text(value, label)
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise AttackWorldModelError(f"{label} is not a lowercase token")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AttackWorldModelError(f"{label} must be a lowercase sha256 digest")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise AttackWorldModelError(f"{label} must use second-precision UTC Z format")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AttackWorldModelError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def _require_exact_fields(
    raw: Any,
    required: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> None:
    if not isinstance(raw, dict):
        raise AttackWorldModelError(f"{label} must be an object")
    optional = optional or set()
    missing = required - set(raw)
    extra = set(raw) - required - optional
    if missing or extra:
        raise AttackWorldModelError(
            f"{label} fields are invalid: missing={sorted(missing)}, extra={sorted(extra)}"
        )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


__all__ = [
    "AttackEdge",
    "AttackNode",
    "AttackPath",
    "AttackPathQueryResult",
    "AttackWorldModelError",
    "AttackWorldSnapshot",
    "EdgeKind",
    "EvidenceBinding",
    "EvidenceConflict",
    "FrontierItem",
    "GraphLimits",
    "NodeKind",
    "ObservationDelta",
    "PathQuery",
    "VerificationState",
    "apply_observation_delta",
    "build_attack_world_snapshot",
    "compute_uncovered_frontier",
    "detect_evidence_conflicts",
    "query_candidate_attack_paths",
]
