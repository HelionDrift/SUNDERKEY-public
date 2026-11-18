"""Repository-only software supply-chain assessment contracts.

The module imports evidence through injected passive adapters and analyzes it
without contacting repositories, registries, build systems, or networks. It
does not execute commands, mutate repositories, or qualify an operational
capability.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Protocol

SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = {
    "command_execution": "none",
    "credential_access": "none",
    "network": "none",
    "registry_contact": "none",
    "repository_mutation": "none",
}

HARD_LIMITS = {
    "max_adapters": 64,
    "max_edges": 100000,
    "max_findings": 25000,
    "max_nodes": 50000,
    "max_proposals": 25000,
    "max_records": 50000,
}


class SupplyChainAssessmentError(ValueError):
    """Raised when supply-chain evidence fails closed."""


class ActionTier(IntEnum):
    """Minimum separately admitted action tier."""

    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3


class EvidenceKind(StrEnum):
    """Supported evidence families."""

    SOURCE_MANIFEST = "source_manifest"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    CICD_CONFIGURATION = "cicd_configuration"
    INFRASTRUCTURE_AS_CODE = "infrastructure_as_code"
    CONTAINER_IMAGE_MANIFEST = "container_image_manifest"
    ARTIFACT_REGISTRY_EXPORT = "artifact_registry_export"
    BUILD_PROVENANCE = "build_provenance"
    SBOM = "sbom"
    SCANNER_FINDING = "scanner_finding"


class NodeKind(StrEnum):
    """Supply-chain graph node families."""

    SOURCE = "source"
    DEPENDENCY = "dependency"
    PIPELINE = "pipeline"
    INFRASTRUCTURE = "infrastructure"
    IMAGE = "image"
    ARTIFACT = "artifact"
    BUILDER = "builder"
    PROVENANCE = "provenance"


class RelationKind(StrEnum):
    """Supply-chain graph relationships."""

    DEPENDS_ON = "depends_on"
    BUILT_BY = "built_by"
    PRODUCES = "produces"
    DERIVED_FROM = "derived_from"
    PUBLISHED_AS = "published_as"
    DEPLOYS = "deploys"


class FindingKind(StrEnum):
    """Conservative graph-derived finding families."""

    STALE_EVIDENCE = "stale_evidence"
    UNPINNED_DEPENDENCY = "unpinned_dependency"
    UNVERIFIED_BUILD_PROVENANCE = "unverified_build_provenance"
    MISSING_ARTIFACT_PROVENANCE = "missing_artifact_provenance"
    CROSS_BOUNDARY_FLOW = "cross_boundary_flow"
    PUBLIC_BUILD_EXPOSURE = "public_build_exposure"


@dataclass(frozen=True)
class AssessmentBudgets:
    """Fail-closed import and analysis ceilings."""

    max_adapters: int = 16
    max_edges: int = 20000
    max_findings: int = 5000
    max_nodes: int = 10000
    max_proposals: int = 5000
    max_records: int = 10000

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SupplyChainAssessmentError(f"{name} must be a positive integer")
            if value > HARD_LIMITS[name]:
                raise SupplyChainAssessmentError(f"{name} exceeds its hard limit")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in sorted(HARD_LIMITS)}

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentBudgets:
        _exact_fields(raw, set(HARD_LIMITS), "assessment budgets")
        return cls(**raw)


@dataclass(frozen=True)
class AssessmentContext:
    """Exact tenant, repository, revision, build, and scope binding."""

    tenant_id: str
    context_id: str
    repository_ref: str
    revision_sha256: str
    build_ref: str
    scope_binding_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.context_id, "context_id")
        _reference(self.repository_ref, "repository_ref", "repository:")
        _sha256(self.revision_sha256, "revision_sha256")
        _reference(self.build_ref, "build_ref", "build:")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")

    def to_dict(self) -> dict[str, str]:
        return {
            "build_ref": self.build_ref,
            "context_id": self.context_id,
            "repository_ref": self.repository_ref,
            "revision_sha256": self.revision_sha256,
            "scope_binding_sha256": self.scope_binding_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentContext:
        fields = {
            "build_ref",
            "context_id",
            "repository_ref",
            "revision_sha256",
            "scope_binding_sha256",
            "tenant_id",
        }
        _exact_fields(raw, fields, "assessment context")
        return cls(**raw)


@dataclass(frozen=True)
class AdapterSpec:
    """A passive, externally supplied evidence adapter declaration."""

    adapter_id: str
    adapter_version: str
    evidence_source_ref: str
    evidence_kinds: tuple[EvidenceKind | str, ...]
    record_limit: int
    required_action_tier: ActionTier | int = ActionTier.R0
    passive_only: bool = True

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "adapter_id")
        _identifier(self.adapter_version, "adapter_version")
        _reference(self.evidence_source_ref, "evidence_source_ref", "evidence:")
        try:
            kinds = tuple(sorted({EvidenceKind(value) for value in self.evidence_kinds}, key=str))
            tier = ActionTier(self.required_action_tier)
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("adapter enumeration is invalid") from exc
        if not kinds:
            raise SupplyChainAssessmentError("adapter requires evidence kinds")
        if tier is not ActionTier.R0:
            raise SupplyChainAssessmentError("passive evidence adapters require R0 admission")
        if self.passive_only is not True:
            raise SupplyChainAssessmentError("adapter must be passive_only")
        if (
            isinstance(self.record_limit, bool)
            or not isinstance(self.record_limit, int)
            or not 1 <= self.record_limit <= HARD_LIMITS["max_records"]
        ):
            raise SupplyChainAssessmentError("adapter record_limit is invalid")
        object.__setattr__(self, "evidence_kinds", kinds)
        object.__setattr__(self, "required_action_tier", tier)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "evidence_kinds": [item.value for item in self.evidence_kinds],
            "evidence_source_ref": self.evidence_source_ref,
            "passive_only": self.passive_only,
            "record_limit": self.record_limit,
            "required_action_tier": self.required_action_tier.name,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterSpec:
        fields = {
            "adapter_id",
            "adapter_version",
            "evidence_kinds",
            "evidence_source_ref",
            "passive_only",
            "record_limit",
            "required_action_tier",
        }
        _exact_fields(raw, fields, "adapter spec")
        return cls(
            adapter_id=raw["adapter_id"],
            adapter_version=raw["adapter_version"],
            evidence_source_ref=raw["evidence_source_ref"],
            evidence_kinds=tuple(raw["evidence_kinds"]),
            record_limit=raw["record_limit"],
            required_action_tier=ActionTier[raw["required_action_tier"]],
            passive_only=raw["passive_only"],
        )


@dataclass(frozen=True)
class AssessmentPlan:
    """Content-addressed and bounded evidence import plan."""

    schema_version: int
    plan_id: str
    plan_sha256: str
    planned_at: str
    valid_until: str
    idempotency_key_sha256: str
    context: AssessmentContext
    adapters: tuple[AdapterSpec, ...]
    budgets: AssessmentBudgets
    no_effects: Mapping[str, str]
    qualification_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SupplyChainAssessmentError("plan schema_version is unsupported")
        if not re.fullmatch(r"SCP-[0-9A-F]{32}", self.plan_id):
            raise SupplyChainAssessmentError("plan_id is invalid")
        _sha256(self.plan_sha256, "plan_sha256")
        if _utc(self.valid_until, "valid_until") <= _utc(self.planned_at, "planned_at"):
            raise SupplyChainAssessmentError("valid_until must follow planned_at")
        _sha256(self.idempotency_key_sha256, "idempotency_key_sha256")
        if not isinstance(self.context, AssessmentContext):
            raise SupplyChainAssessmentError("context must be AssessmentContext")
        if not isinstance(self.budgets, AssessmentBudgets):
            raise SupplyChainAssessmentError("budgets must be AssessmentBudgets")
        adapters = tuple(self.adapters)
        if not adapters or len(adapters) > self.budgets.max_adapters:
            raise SupplyChainAssessmentError("adapter count is outside plan budgets")
        if any(not isinstance(item, AdapterSpec) for item in adapters):
            raise SupplyChainAssessmentError("adapters contain an invalid value")
        canonical = tuple(sorted(adapters, key=lambda item: item.adapter_id))
        if adapters != canonical or len({item.adapter_id for item in adapters}) != len(adapters):
            raise SupplyChainAssessmentError("adapters must be unique and canonically ordered")
        if sum(item.record_limit for item in adapters) > self.budgets.max_records:
            raise SupplyChainAssessmentError("adapter record limits exceed max_records")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        if self.qualification_effect != "none":
            raise SupplyChainAssessmentError("plan cannot create a qualification effect")
        expected = _digest("sunderkey.software-supply-chain-plan.v1", self._identity_payload())
        if self.plan_sha256 != expected or self.plan_id != _derived_id("SCP", expected):
            raise SupplyChainAssessmentError("plan identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "adapters": [item.to_dict() for item in self.adapters],
            "budgets": self.budgets.to_dict(),
            "context": self.context.to_dict(),
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "no_effects": dict(self.no_effects),
            "planned_at": self.planned_at,
            "qualification_effect": self.qualification_effect,
            "schema_version": self.schema_version,
            "valid_until": self.valid_until,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            **self._identity_payload(),
        }

    def request_for(self, adapter_id: str) -> AdapterRequest:
        matches = [item for item in self.adapters if item.adapter_id == adapter_id]
        if len(matches) != 1:
            raise SupplyChainAssessmentError("adapter is not declared by the plan")
        payload = {
            "adapter": matches[0].to_dict(),
            "context": self.context.to_dict(),
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
        }
        request_sha = _digest("sunderkey.software-supply-chain-request.v1", payload)
        return AdapterRequest(request_sha256=request_sha, plan=self, adapter=matches[0])

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentPlan:
        fields = {
            "adapters",
            "budgets",
            "context",
            "idempotency_key_sha256",
            "no_effects",
            "plan_id",
            "plan_sha256",
            "planned_at",
            "qualification_effect",
            "schema_version",
            "valid_until",
        }
        _exact_fields(raw, fields, "assessment plan")
        return cls(
            schema_version=raw["schema_version"],
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            planned_at=raw["planned_at"],
            valid_until=raw["valid_until"],
            idempotency_key_sha256=raw["idempotency_key_sha256"],
            context=AssessmentContext.from_dict(raw["context"]),
            adapters=tuple(AdapterSpec.from_dict(item) for item in raw["adapters"]),
            budgets=AssessmentBudgets.from_dict(raw["budgets"]),
            no_effects=raw["no_effects"],
            qualification_effect=raw["qualification_effect"],
        )


@dataclass(frozen=True)
class AdapterRequest:
    """One exact request passed to an injected adapter."""

    request_sha256: str
    plan: AssessmentPlan
    adapter: AdapterSpec

    def __post_init__(self) -> None:
        _sha256(self.request_sha256, "request_sha256")
        if self.adapter not in self.plan.adapters:
            raise SupplyChainAssessmentError("adapter request is not plan bound")
        payload = {
            "adapter": self.adapter.to_dict(),
            "context": self.plan.context.to_dict(),
            "idempotency_key_sha256": self.plan.idempotency_key_sha256,
            "plan_id": self.plan.plan_id,
            "plan_sha256": self.plan.plan_sha256,
        }
        if self.request_sha256 != _digest("sunderkey.software-supply-chain-request.v1", payload):
            raise SupplyChainAssessmentError("request identity does not match canonical content")


@dataclass(frozen=True)
class GraphNode:
    """Secret-safe supply-chain graph node."""

    node_key_sha256: str
    node_kind: NodeKind | str
    subject_ref: str
    trust_boundary_ref: str
    exposure: str
    integrity_sha256: str | None = None

    def __post_init__(self) -> None:
        _sha256(self.node_key_sha256, "node_key_sha256")
        try:
            object.__setattr__(self, "node_kind", NodeKind(self.node_kind))
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("node_kind is invalid") from exc
        _reference(self.subject_ref, "subject_ref", "subject:")
        _reference(self.trust_boundary_ref, "trust_boundary_ref", "boundary:")
        if self.exposure not in {"private", "internal", "public", "unknown"}:
            raise SupplyChainAssessmentError("node exposure is invalid")
        if self.integrity_sha256 is not None:
            _sha256(self.integrity_sha256, "integrity_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "exposure": self.exposure,
            "integrity_sha256": self.integrity_sha256,
            "node_key_sha256": self.node_key_sha256,
            "node_kind": self.node_kind.value,
            "subject_ref": self.subject_ref,
            "trust_boundary_ref": self.trust_boundary_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GraphNode:
        fields = {
            "exposure",
            "integrity_sha256",
            "node_key_sha256",
            "node_kind",
            "subject_ref",
            "trust_boundary_ref",
        }
        _exact_fields(raw, fields, "graph node")
        return cls(**raw)


@dataclass(frozen=True)
class GraphEdge:
    """Directed graph relationship."""

    source_key_sha256: str
    target_key_sha256: str
    relation_kind: RelationKind | str

    def __post_init__(self) -> None:
        _sha256(self.source_key_sha256, "source_key_sha256")
        _sha256(self.target_key_sha256, "target_key_sha256")
        if self.source_key_sha256 == self.target_key_sha256:
            raise SupplyChainAssessmentError("graph edge cannot be self-referential")
        try:
            object.__setattr__(self, "relation_kind", RelationKind(self.relation_kind))
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("relation_kind is invalid") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "relation_kind": self.relation_kind.value,
            "source_key_sha256": self.source_key_sha256,
            "target_key_sha256": self.target_key_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GraphEdge:
        fields = {"relation_kind", "source_key_sha256", "target_key_sha256"}
        _exact_fields(raw, fields, "graph edge")
        return cls(**raw)


@dataclass(frozen=True)
class EvidenceRecord:
    """One immutable adapter-bound evidence record."""

    record_sha256: str
    request_sha256: str
    sequence: int
    evidence_kind: EvidenceKind | str
    evidence_ref: str
    content_sha256: str
    observed_at: str
    fresh_until: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def __post_init__(self) -> None:
        _sha256(self.record_sha256, "record_sha256")
        _sha256(self.request_sha256, "request_sha256")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise SupplyChainAssessmentError("sequence must be a nonnegative integer")
        try:
            object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("evidence_kind is invalid") from exc
        _reference(self.evidence_ref, "evidence_ref", "evidence:")
        _sha256(self.content_sha256, "content_sha256")
        if _utc(self.fresh_until, "fresh_until") <= _utc(self.observed_at, "observed_at"):
            raise SupplyChainAssessmentError("fresh_until must follow observed_at")
        nodes = tuple(self.nodes)
        edges = tuple(self.edges)
        if nodes != tuple(sorted(nodes, key=lambda item: item.node_key_sha256)):
            raise SupplyChainAssessmentError("record nodes are not canonically ordered")
        if edges != tuple(
            sorted(
                edges,
                key=lambda item: (
                    item.source_key_sha256,
                    item.target_key_sha256,
                    str(item.relation_kind),
                ),
            )
        ):
            raise SupplyChainAssessmentError("record edges are not canonically ordered")
        if len({item.node_key_sha256 for item in nodes}) != len(nodes):
            raise SupplyChainAssessmentError("record node keys must be unique")
        keys = {item.node_key_sha256 for item in nodes}
        if any(
            item.source_key_sha256 not in keys or item.target_key_sha256 not in keys
            for item in edges
        ):
            raise SupplyChainAssessmentError("record edge endpoint is missing")
        expected = _digest("sunderkey.software-supply-chain-record.v1", self._identity_payload())
        if self.record_sha256 != expected:
            raise SupplyChainAssessmentError("record identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "content_sha256": self.content_sha256,
            "edges": [item.to_dict() for item in self.edges],
            "evidence_kind": self.evidence_kind.value,
            "evidence_ref": self.evidence_ref,
            "fresh_until": self.fresh_until,
            "nodes": [item.to_dict() for item in self.nodes],
            "observed_at": self.observed_at,
            "request_sha256": self.request_sha256,
            "sequence": self.sequence,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"record_sha256": self.record_sha256, **self._identity_payload()}

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceRecord:
        fields = {
            "content_sha256",
            "edges",
            "evidence_kind",
            "evidence_ref",
            "fresh_until",
            "nodes",
            "observed_at",
            "record_sha256",
            "request_sha256",
            "sequence",
        }
        _exact_fields(raw, fields, "evidence record")
        return cls(
            record_sha256=raw["record_sha256"],
            request_sha256=raw["request_sha256"],
            sequence=raw["sequence"],
            evidence_kind=raw["evidence_kind"],
            evidence_ref=raw["evidence_ref"],
            content_sha256=raw["content_sha256"],
            observed_at=raw["observed_at"],
            fresh_until=raw["fresh_until"],
            nodes=tuple(GraphNode.from_dict(item) for item in raw["nodes"]),
            edges=tuple(GraphEdge.from_dict(item) for item in raw["edges"]),
        )


@dataclass(frozen=True)
class AdapterResult:
    """Attested result returned by an injected adapter."""

    request_sha256: str
    adapter_id: str
    tenant_id: str
    context_id: str
    repository_ref: str
    revision_sha256: str
    build_ref: str
    scope_binding_sha256: str
    records: tuple[EvidenceRecord, ...]
    network_call_performed: bool = False
    command_execution_performed: bool = False
    repository_mutation_performed: bool = False
    registry_contact_performed: bool = False
    secret_material_returned: bool = False

    def __post_init__(self) -> None:
        _sha256(self.request_sha256, "request_sha256")
        _identifier(self.adapter_id, "adapter_id")
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.context_id, "context_id")
        _reference(self.repository_ref, "repository_ref", "repository:")
        _sha256(self.revision_sha256, "revision_sha256")
        _reference(self.build_ref, "build_ref", "build:")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")
        for name in (
            "network_call_performed",
            "command_execution_performed",
            "repository_mutation_performed",
            "registry_contact_performed",
            "secret_material_returned",
        ):
            if getattr(self, name) is not False:
                raise SupplyChainAssessmentError(f"{name} must be false")
        if tuple(record.sequence for record in self.records) != tuple(range(len(self.records))):
            raise SupplyChainAssessmentError("record sequences must be contiguous")
        if any(record.request_sha256 != self.request_sha256 for record in self.records):
            raise SupplyChainAssessmentError("result record binding mismatch")
        if len({record.record_sha256 for record in self.records}) != len(self.records):
            raise SupplyChainAssessmentError("result contains replayed evidence")


class EvidenceAdapter(Protocol):
    """Injected adapter boundary. No implementation is supplied here."""

    def collect(self, request: AdapterRequest) -> AdapterResult:
        """Return already available passive evidence for one exact request."""


@dataclass(frozen=True)
class EvidenceBatch:
    """Deterministic output of a bounded evidence import."""

    batch_id: str
    batch_sha256: str
    plan: AssessmentPlan
    imported_at: str
    records: tuple[EvidenceRecord, ...]
    evidence_level: str = "repository_only"
    operational_status: str = "nonqualified"
    qualification_effect: str = "none"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"SCB-[0-9A-F]{32}", self.batch_id):
            raise SupplyChainAssessmentError("batch_id is invalid")
        _sha256(self.batch_sha256, "batch_sha256")
        imported = _utc(self.imported_at, "imported_at")
        if (
            not _utc(self.plan.planned_at, "planned_at")
            <= imported
            <= _utc(self.plan.valid_until, "valid_until")
        ):
            raise SupplyChainAssessmentError("imported_at is outside the plan window")
        if len(self.records) > self.plan.budgets.max_records:
            raise SupplyChainAssessmentError("batch exceeds max_records")
        if len({item.record_sha256 for item in self.records}) != len(self.records):
            raise SupplyChainAssessmentError("batch contains replayed evidence")
        if self.evidence_level != "repository_only" or self.operational_status != "nonqualified":
            raise SupplyChainAssessmentError("batch assurance declaration is invalid")
        if self.qualification_effect != "none":
            raise SupplyChainAssessmentError("batch cannot create a qualification effect")
        expected = _digest("sunderkey.software-supply-chain-batch.v1", self._identity_payload())
        if self.batch_sha256 != expected or self.batch_id != _derived_id("SCB", expected):
            raise SupplyChainAssessmentError("batch identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "evidence_level": self.evidence_level,
            "imported_at": self.imported_at,
            "operational_status": self.operational_status,
            "plan": self.plan.to_dict(),
            "qualification_effect": self.qualification_effect,
            "records": [item.to_dict() for item in self.records],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
            **self._identity_payload(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceBatch:
        fields = {
            "batch_id",
            "batch_sha256",
            "evidence_level",
            "imported_at",
            "operational_status",
            "plan",
            "qualification_effect",
            "records",
        }
        _exact_fields(raw, fields, "evidence batch")
        return cls(
            batch_id=raw["batch_id"],
            batch_sha256=raw["batch_sha256"],
            plan=AssessmentPlan.from_dict(raw["plan"]),
            imported_at=raw["imported_at"],
            records=tuple(EvidenceRecord.from_dict(item) for item in raw["records"]),
            evidence_level=raw["evidence_level"],
            operational_status=raw["operational_status"],
            qualification_effect=raw["qualification_effect"],
        )


@dataclass(frozen=True)
class AssessmentFinding:
    """One deterministic, graph-derived finding."""

    finding_id: str
    finding_sha256: str
    finding_kind: FindingKind | str
    priority: int
    subject_key_sha256: str
    related_key_sha256: str | None
    evidence_record_sha256s: tuple[str, ...]
    summary: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"SCF-[0-9A-F]{32}", self.finding_id):
            raise SupplyChainAssessmentError("finding_id is invalid")
        _sha256(self.finding_sha256, "finding_sha256")
        try:
            object.__setattr__(self, "finding_kind", FindingKind(self.finding_kind))
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("finding_kind is invalid") from exc
        if (
            isinstance(self.priority, bool)
            or not isinstance(self.priority, int)
            or not 1 <= self.priority <= 5
        ):
            raise SupplyChainAssessmentError("finding priority is invalid")
        _sha256(self.subject_key_sha256, "subject_key_sha256")
        if self.related_key_sha256 is not None:
            _sha256(self.related_key_sha256, "related_key_sha256")
        object.__setattr__(
            self,
            "evidence_record_sha256s",
            _hashes(self.evidence_record_sha256s, "evidence_record_sha256s"),
        )
        if not self.evidence_record_sha256s:
            raise SupplyChainAssessmentError("finding requires evidence")
        _summary(self.summary)
        expected = _digest("sunderkey.software-supply-chain-finding.v1", self._identity_payload())
        if self.finding_sha256 != expected or self.finding_id != _derived_id("SCF", expected):
            raise SupplyChainAssessmentError("finding identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "evidence_record_sha256s": list(self.evidence_record_sha256s),
            "finding_kind": self.finding_kind.value,
            "priority": self.priority,
            "related_key_sha256": self.related_key_sha256,
            "subject_key_sha256": self.subject_key_sha256,
            "summary": self.summary,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_sha256": self.finding_sha256,
            **self._identity_payload(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentFinding:
        fields = {
            "evidence_record_sha256s",
            "finding_id",
            "finding_kind",
            "finding_sha256",
            "priority",
            "related_key_sha256",
            "subject_key_sha256",
            "summary",
        }
        _exact_fields(raw, fields, "assessment finding")
        return cls(
            finding_id=raw["finding_id"],
            finding_sha256=raw["finding_sha256"],
            finding_kind=raw["finding_kind"],
            priority=raw["priority"],
            subject_key_sha256=raw["subject_key_sha256"],
            related_key_sha256=raw["related_key_sha256"],
            evidence_record_sha256s=tuple(raw["evidence_record_sha256s"]),
            summary=raw["summary"],
        )


@dataclass(frozen=True)
class CandidatePlan:
    """Proposal requiring separate admission before any validation action."""

    proposal_id: str
    proposal_sha256: str
    finding_id: str
    plan_kind: str
    minimum_action_tier: ActionTier | int
    adapter_refs: tuple[str, ...]
    max_records: int
    status: str = "proposal_only"
    separate_admission_required: bool = True
    network_access_permitted: bool = False
    command_execution_permitted: bool = False
    repository_mutation_permitted: bool = False
    registry_contact_permitted: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(r"SCV-[0-9A-F]{32}", self.proposal_id):
            raise SupplyChainAssessmentError("proposal_id is invalid")
        _sha256(self.proposal_sha256, "proposal_sha256")
        if not re.fullmatch(r"SCF-[0-9A-F]{32}", self.finding_id):
            raise SupplyChainAssessmentError("finding_id is invalid")
        _identifier(self.plan_kind, "plan_kind")
        try:
            object.__setattr__(self, "minimum_action_tier", ActionTier(self.minimum_action_tier))
        except (TypeError, ValueError) as exc:
            raise SupplyChainAssessmentError("minimum_action_tier is invalid") from exc
        object.__setattr__(self, "adapter_refs", _refs(self.adapter_refs, "adapter_refs"))
        if (
            isinstance(self.max_records, bool)
            or not isinstance(self.max_records, int)
            or not 1 <= self.max_records <= HARD_LIMITS["max_records"]
        ):
            raise SupplyChainAssessmentError("proposal max_records is invalid")
        if self.status != "proposal_only" or self.separate_admission_required is not True:
            raise SupplyChainAssessmentError("candidate plan must require separate admission")
        for name in (
            "network_access_permitted",
            "command_execution_permitted",
            "repository_mutation_permitted",
            "registry_contact_permitted",
        ):
            if getattr(self, name) is not False:
                raise SupplyChainAssessmentError(f"{name} must be false")
        expected = _digest(
            "sunderkey.software-supply-chain-validation.v1", self._identity_payload()
        )
        if self.proposal_sha256 != expected or self.proposal_id != _derived_id("SCV", expected):
            raise SupplyChainAssessmentError("proposal identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "adapter_refs": list(self.adapter_refs),
            "command_execution_permitted": self.command_execution_permitted,
            "finding_id": self.finding_id,
            "max_records": self.max_records,
            "minimum_action_tier": self.minimum_action_tier.name,
            "network_access_permitted": self.network_access_permitted,
            "plan_kind": self.plan_kind,
            "registry_contact_permitted": self.registry_contact_permitted,
            "repository_mutation_permitted": self.repository_mutation_permitted,
            "separate_admission_required": self.separate_admission_required,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "proposal_sha256": self.proposal_sha256,
            **self._identity_payload(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CandidatePlan:
        fields = {
            "adapter_refs",
            "command_execution_permitted",
            "finding_id",
            "max_records",
            "minimum_action_tier",
            "network_access_permitted",
            "plan_kind",
            "proposal_id",
            "proposal_sha256",
            "registry_contact_permitted",
            "repository_mutation_permitted",
            "separate_admission_required",
            "status",
        }
        _exact_fields(raw, fields, "candidate plan")
        return cls(
            proposal_id=raw["proposal_id"],
            proposal_sha256=raw["proposal_sha256"],
            finding_id=raw["finding_id"],
            plan_kind=raw["plan_kind"],
            minimum_action_tier=ActionTier[raw["minimum_action_tier"]],
            adapter_refs=tuple(raw["adapter_refs"]),
            max_records=raw["max_records"],
            status=raw["status"],
            separate_admission_required=raw["separate_admission_required"],
            network_access_permitted=raw["network_access_permitted"],
            command_execution_permitted=raw["command_execution_permitted"],
            repository_mutation_permitted=raw["repository_mutation_permitted"],
            registry_contact_permitted=raw["registry_contact_permitted"],
        )


@dataclass(frozen=True)
class AssessmentReport:
    """Closed, content-addressed assessment result."""

    schema_version: int
    report_id: str
    report_sha256: str
    generated_at: str
    batch: EvidenceBatch
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    findings: tuple[AssessmentFinding, ...]
    candidate_plans: tuple[CandidatePlan, ...]
    evidence_level: str = "repository_only"
    operational_status: str = "nonqualified"
    qualification_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SupplyChainAssessmentError("report schema_version is unsupported")
        if not re.fullmatch(r"SCR-[0-9A-F]{32}", self.report_id):
            raise SupplyChainAssessmentError("report_id is invalid")
        _sha256(self.report_sha256, "report_sha256")
        if _utc(self.generated_at, "generated_at") < _utc(self.batch.imported_at, "imported_at"):
            raise SupplyChainAssessmentError("generated_at precedes imported_at")
        if len(self.nodes) > self.batch.plan.budgets.max_nodes:
            raise SupplyChainAssessmentError("report exceeds max_nodes")
        if len(self.edges) > self.batch.plan.budgets.max_edges:
            raise SupplyChainAssessmentError("report exceeds max_edges")
        if len(self.findings) > self.batch.plan.budgets.max_findings:
            raise SupplyChainAssessmentError("report exceeds max_findings")
        if len(self.candidate_plans) > self.batch.plan.budgets.max_proposals:
            raise SupplyChainAssessmentError("report exceeds max_proposals")
        if self.nodes != tuple(sorted(self.nodes, key=lambda item: item.node_key_sha256)):
            raise SupplyChainAssessmentError("report nodes are not canonically ordered")

        def edge_key(item: GraphEdge) -> tuple[str, str, str]:
            return (
                item.source_key_sha256,
                item.target_key_sha256,
                str(item.relation_kind),
            )

        if self.edges != tuple(sorted(self.edges, key=edge_key)):
            raise SupplyChainAssessmentError("report edges are not canonically ordered")
        if self.findings != tuple(
            sorted(self.findings, key=lambda item: (item.priority, item.finding_id))
        ):
            raise SupplyChainAssessmentError("report findings are not canonically ordered")
        if self.candidate_plans != tuple(
            sorted(self.candidate_plans, key=lambda item: item.proposal_id)
        ):
            raise SupplyChainAssessmentError("candidate plans are not canonically ordered")
        finding_ids = {item.finding_id for item in self.findings}
        if any(item.finding_id not in finding_ids for item in self.candidate_plans):
            raise SupplyChainAssessmentError("candidate plan references an unknown finding")
        if self.evidence_level != "repository_only" or self.operational_status != "nonqualified":
            raise SupplyChainAssessmentError("report assurance declaration is invalid")
        if self.qualification_effect != "none":
            raise SupplyChainAssessmentError("report cannot create a qualification effect")
        expected = _digest("sunderkey.software-supply-chain-report.v1", self._identity_payload())
        if self.report_sha256 != expected or self.report_id != _derived_id("SCR", expected):
            raise SupplyChainAssessmentError("report identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "batch": self.batch.to_dict(),
            "candidate_plans": [item.to_dict() for item in self.candidate_plans],
            "edges": [item.to_dict() for item in self.edges],
            "evidence_level": self.evidence_level,
            "findings": [item.to_dict() for item in self.findings],
            "generated_at": self.generated_at,
            "nodes": [item.to_dict() for item in self.nodes],
            "operational_status": self.operational_status,
            "qualification_effect": self.qualification_effect,
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            **self._identity_payload(),
        }


def build_assessment_plan(
    context: AssessmentContext,
    adapters: Sequence[AdapterSpec],
    *,
    planned_at: str,
    valid_until: str,
    idempotency_key_sha256: str,
    budgets: AssessmentBudgets | None = None,
) -> AssessmentPlan:
    """Build a canonical repository-only import plan."""

    ordered = tuple(sorted(adapters, key=lambda item: item.adapter_id))
    selected = budgets or AssessmentBudgets()
    payload = {
        "adapters": [item.to_dict() for item in ordered],
        "budgets": selected.to_dict(),
        "context": context.to_dict(),
        "idempotency_key_sha256": idempotency_key_sha256,
        "no_effects": NO_EFFECTS,
        "planned_at": planned_at,
        "qualification_effect": "none",
        "schema_version": SCHEMA_VERSION,
        "valid_until": valid_until,
    }
    digest = _digest("sunderkey.software-supply-chain-plan.v1", payload)
    return AssessmentPlan(
        plan_id=_derived_id("SCP", digest),
        plan_sha256=digest,
        context=context,
        adapters=ordered,
        budgets=selected,
        no_effects=NO_EFFECTS,
        planned_at=planned_at,
        valid_until=valid_until,
        idempotency_key_sha256=idempotency_key_sha256,
        schema_version=SCHEMA_VERSION,
    )


def build_evidence_record(
    request: AdapterRequest,
    *,
    sequence: int,
    evidence_kind: EvidenceKind,
    evidence_ref: str,
    content_sha256: str,
    observed_at: str,
    fresh_until: str,
    nodes: Sequence[GraphNode],
    edges: Sequence[GraphEdge],
) -> EvidenceRecord:
    """Build a canonical, request-bound evidence record."""

    if evidence_kind not in request.adapter.evidence_kinds:
        raise SupplyChainAssessmentError("evidence kind is not declared by adapter")
    ordered_nodes = tuple(sorted(nodes, key=lambda item: item.node_key_sha256))
    ordered_edges = tuple(
        sorted(
            edges,
            key=lambda item: (
                item.source_key_sha256,
                item.target_key_sha256,
                str(item.relation_kind),
            ),
        )
    )
    payload = {
        "content_sha256": content_sha256,
        "edges": [item.to_dict() for item in ordered_edges],
        "evidence_kind": evidence_kind.value,
        "evidence_ref": evidence_ref,
        "fresh_until": fresh_until,
        "nodes": [item.to_dict() for item in ordered_nodes],
        "observed_at": observed_at,
        "request_sha256": request.request_sha256,
        "sequence": sequence,
    }
    digest = _digest("sunderkey.software-supply-chain-record.v1", payload)
    return EvidenceRecord(
        record_sha256=digest,
        nodes=ordered_nodes,
        edges=ordered_edges,
        **{k: v for k, v in payload.items() if k not in {"nodes", "edges"}},
    )


def build_adapter_result(
    request: AdapterRequest, records: Sequence[EvidenceRecord]
) -> AdapterResult:
    """Build a no-effect adapter result bound to the request context."""

    context = request.plan.context
    return AdapterResult(
        request_sha256=request.request_sha256,
        adapter_id=request.adapter.adapter_id,
        tenant_id=context.tenant_id,
        context_id=context.context_id,
        repository_ref=context.repository_ref,
        revision_sha256=context.revision_sha256,
        build_ref=context.build_ref,
        scope_binding_sha256=context.scope_binding_sha256,
        records=tuple(records),
    )


def import_evidence(
    plan: AssessmentPlan,
    adapters: Mapping[str, EvidenceAdapter],
    *,
    imported_at: str,
    seen_record_sha256s: Sequence[str] = (),
) -> EvidenceBatch:
    """Call each injected adapter once and fail closed on any mismatch."""

    _utc(imported_at, "imported_at")
    if set(adapters) != {item.adapter_id for item in plan.adapters}:
        raise SupplyChainAssessmentError("injected adapter set does not match plan")
    seen = set(_hashes(seen_record_sha256s, "seen_record_sha256s"))
    records: list[EvidenceRecord] = []
    context = plan.context
    for spec in plan.adapters:
        request = plan.request_for(spec.adapter_id)
        result = adapters[spec.adapter_id].collect(request)
        if not isinstance(result, AdapterResult):
            raise SupplyChainAssessmentError("adapter returned an invalid result")
        expected_binding = (
            request.request_sha256,
            spec.adapter_id,
            context.tenant_id,
            context.context_id,
            context.repository_ref,
            context.revision_sha256,
            context.build_ref,
            context.scope_binding_sha256,
        )
        actual_binding = (
            result.request_sha256,
            result.adapter_id,
            result.tenant_id,
            result.context_id,
            result.repository_ref,
            result.revision_sha256,
            result.build_ref,
            result.scope_binding_sha256,
        )
        if actual_binding != expected_binding:
            raise SupplyChainAssessmentError("adapter result binding mismatch")
        if len(result.records) > spec.record_limit:
            raise SupplyChainAssessmentError("adapter result exceeds record limit")
        if any(item.evidence_kind not in spec.evidence_kinds for item in result.records):
            raise SupplyChainAssessmentError("adapter returned an undeclared evidence kind")
        for record in result.records:
            if record.record_sha256 in seen:
                raise SupplyChainAssessmentError("replayed evidence record")
            seen.add(record.record_sha256)
            records.append(record)
    ordered = tuple(sorted(records, key=lambda item: item.record_sha256))
    payload = {
        "evidence_level": "repository_only",
        "imported_at": imported_at,
        "operational_status": "nonqualified",
        "plan": plan.to_dict(),
        "qualification_effect": "none",
        "records": [item.to_dict() for item in ordered],
    }
    digest = _digest("sunderkey.software-supply-chain-batch.v1", payload)
    return EvidenceBatch(
        batch_id=_derived_id("SCB", digest),
        batch_sha256=digest,
        plan=plan,
        imported_at=imported_at,
        records=ordered,
    )


def analyze_supply_chain(batch: EvidenceBatch, *, generated_at: str) -> AssessmentReport:
    """Analyze dependency, provenance, boundary, exposure, and freshness gaps."""

    generated = _utc(generated_at, "generated_at")
    node_map: dict[str, GraphNode] = {}
    edge_map: dict[tuple[str, str, RelationKind], GraphEdge] = {}
    evidence_by_node: dict[str, set[str]] = {}
    stale_nodes: set[str] = set()
    for record in batch.records:
        stale = _utc(record.fresh_until, "fresh_until") < generated
        for node in record.nodes:
            previous = node_map.get(node.node_key_sha256)
            if previous is not None and previous != node:
                raise SupplyChainAssessmentError("conflicting node claims fail closed")
            node_map[node.node_key_sha256] = node
            evidence_by_node.setdefault(node.node_key_sha256, set()).add(record.record_sha256)
            if stale:
                stale_nodes.add(node.node_key_sha256)
        for edge in record.edges:
            edge_map[(edge.source_key_sha256, edge.target_key_sha256, edge.relation_kind)] = edge
    nodes = tuple(sorted(node_map.values(), key=lambda item: item.node_key_sha256))
    edges = tuple(
        sorted(
            edge_map.values(),
            key=lambda item: (
                item.source_key_sha256,
                item.target_key_sha256,
                str(item.relation_kind),
            ),
        )
    )
    if len(nodes) > batch.plan.budgets.max_nodes or len(edges) > batch.plan.budgets.max_edges:
        raise SupplyChainAssessmentError("graph exceeds plan budgets")

    findings: list[AssessmentFinding] = []

    def add(
        kind: FindingKind,
        priority: int,
        subject: str,
        related: str | None,
        summary: str,
        evidence: set[str],
    ) -> None:
        payload = {
            "evidence_record_sha256s": sorted(evidence),
            "finding_kind": kind.value,
            "priority": priority,
            "related_key_sha256": related,
            "subject_key_sha256": subject,
            "summary": summary,
        }
        digest = _digest("sunderkey.software-supply-chain-finding.v1", payload)
        findings.append(
            AssessmentFinding(
                finding_id=_derived_id("SCF", digest),
                finding_sha256=digest,
                finding_kind=kind,
                priority=priority,
                subject_key_sha256=subject,
                related_key_sha256=related,
                evidence_record_sha256s=tuple(payload["evidence_record_sha256s"]),
                summary=summary,
            )
        )

    for node in nodes:
        evidence = evidence_by_node[node.node_key_sha256]
        if node.node_key_sha256 in stale_nodes:
            add(
                FindingKind.STALE_EVIDENCE,
                1,
                node.node_key_sha256,
                None,
                "Evidence is stale",
                evidence,
            )
        if node.node_kind is NodeKind.DEPENDENCY and node.integrity_sha256 is None:
            add(
                FindingKind.UNPINNED_DEPENDENCY,
                2,
                node.node_key_sha256,
                None,
                "Dependency lacks an integrity pin",
                evidence,
            )
        if node.node_kind is NodeKind.PROVENANCE and node.integrity_sha256 is None:
            add(
                FindingKind.UNVERIFIED_BUILD_PROVENANCE,
                1,
                node.node_key_sha256,
                None,
                "Build provenance lacks verified integrity",
                evidence,
            )
        if node.node_kind in {NodeKind.PIPELINE, NodeKind.BUILDER} and node.exposure == "public":
            add(
                FindingKind.PUBLIC_BUILD_EXPOSURE,
                1,
                node.node_key_sha256,
                None,
                "Build control is publicly exposed",
                evidence,
            )

    provenance_targets = {
        edge.target_key_sha256
        for edge in edges
        if edge.relation_kind
        in {RelationKind.PRODUCES, RelationKind.DERIVED_FROM, RelationKind.PUBLISHED_AS}
        and node_map[edge.source_key_sha256].node_kind
        in {NodeKind.PROVENANCE, NodeKind.BUILDER, NodeKind.PIPELINE}
    }
    for node in nodes:
        if (
            node.node_kind in {NodeKind.IMAGE, NodeKind.ARTIFACT}
            and node.node_key_sha256 not in provenance_targets
        ):
            add(
                FindingKind.MISSING_ARTIFACT_PROVENANCE,
                1,
                node.node_key_sha256,
                None,
                "Artifact has no admitted provenance relationship",
                evidence_by_node[node.node_key_sha256],
            )
    for edge in edges:
        source = node_map[edge.source_key_sha256]
        target = node_map[edge.target_key_sha256]
        if source.trust_boundary_ref != target.trust_boundary_ref:
            add(
                FindingKind.CROSS_BOUNDARY_FLOW,
                2,
                source.node_key_sha256,
                target.node_key_sha256,
                "Relationship crosses a declared trust boundary",
                evidence_by_node[source.node_key_sha256] | evidence_by_node[target.node_key_sha256],
            )

    ordered_findings = tuple(sorted(findings, key=lambda item: (item.priority, item.finding_id)))
    if len(ordered_findings) > batch.plan.budgets.max_findings:
        raise SupplyChainAssessmentError("findings exceed plan budget")
    proposals = tuple(
        sorted(
            (_proposal(item, batch.plan) for item in ordered_findings),
            key=lambda item: item.proposal_id,
        )
    )
    if len(proposals) > batch.plan.budgets.max_proposals:
        raise SupplyChainAssessmentError("candidate plans exceed plan budget")
    payload = {
        "batch": batch.to_dict(),
        "candidate_plans": [item.to_dict() for item in proposals],
        "edges": [item.to_dict() for item in edges],
        "evidence_level": "repository_only",
        "findings": [item.to_dict() for item in ordered_findings],
        "generated_at": generated_at,
        "nodes": [item.to_dict() for item in nodes],
        "operational_status": "nonqualified",
        "qualification_effect": "none",
        "schema_version": SCHEMA_VERSION,
    }
    digest = _digest("sunderkey.software-supply-chain-report.v1", payload)
    return AssessmentReport(
        schema_version=SCHEMA_VERSION,
        report_id=_derived_id("SCR", digest),
        report_sha256=digest,
        generated_at=generated_at,
        batch=batch,
        nodes=nodes,
        edges=edges,
        findings=ordered_findings,
        candidate_plans=proposals,
    )


def parse_assessment_report(raw: str | bytes | Mapping[str, Any]) -> AssessmentReport:
    """Parse and revalidate a closed serialized report."""

    try:
        value = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SupplyChainAssessmentError("report is not valid JSON") from exc
    fields = {
        "batch",
        "candidate_plans",
        "edges",
        "evidence_level",
        "findings",
        "generated_at",
        "nodes",
        "operational_status",
        "qualification_effect",
        "report_id",
        "report_sha256",
        "schema_version",
    }
    _exact_fields(value, fields, "assessment report")
    return AssessmentReport(
        schema_version=value["schema_version"],
        report_id=value["report_id"],
        report_sha256=value["report_sha256"],
        generated_at=value["generated_at"],
        batch=EvidenceBatch.from_dict(value["batch"]),
        nodes=tuple(GraphNode.from_dict(item) for item in value["nodes"]),
        edges=tuple(GraphEdge.from_dict(item) for item in value["edges"]),
        findings=tuple(AssessmentFinding.from_dict(item) for item in value["findings"]),
        candidate_plans=tuple(CandidatePlan.from_dict(item) for item in value["candidate_plans"]),
        evidence_level=value["evidence_level"],
        operational_status=value["operational_status"],
        qualification_effect=value["qualification_effect"],
    )


def canonical_json(value: Any) -> str:
    """Return the canonical serialization used for content identities."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _proposal(finding: AssessmentFinding, plan: AssessmentPlan) -> CandidatePlan:
    tier = ActionTier.R0 if finding.finding_kind is FindingKind.STALE_EVIDENCE else ActionTier.R1
    plan_kind = {
        FindingKind.STALE_EVIDENCE: "refresh_passive_evidence",
        FindingKind.UNPINNED_DEPENDENCY: "verify_dependency_pin",
        FindingKind.UNVERIFIED_BUILD_PROVENANCE: "verify_provenance_attestation",
        FindingKind.MISSING_ARTIFACT_PROVENANCE: "collect_artifact_provenance",
        FindingKind.CROSS_BOUNDARY_FLOW: "validate_trust_boundary_control",
        FindingKind.PUBLIC_BUILD_EXPOSURE: "validate_build_control_exposure",
    }[finding.finding_kind]
    payload = {
        "adapter_refs": sorted(item.adapter_id for item in plan.adapters),
        "command_execution_permitted": False,
        "finding_id": finding.finding_id,
        "max_records": min(plan.budgets.max_records, 1000),
        "minimum_action_tier": tier.name,
        "network_access_permitted": False,
        "plan_kind": plan_kind,
        "registry_contact_permitted": False,
        "repository_mutation_permitted": False,
        "separate_admission_required": True,
        "status": "proposal_only",
    }
    digest = _digest("sunderkey.software-supply-chain-validation.v1", payload)
    return CandidatePlan(
        proposal_id=_derived_id("SCV", digest),
        proposal_sha256=digest,
        finding_id=finding.finding_id,
        plan_kind=plan_kind,
        minimum_action_tier=tier,
        adapter_refs=tuple(payload["adapter_refs"]),
        max_records=payload["max_records"],
    )


def _digest(domain: str, value: Any) -> str:
    material = f"{domain}\n{canonical_json(value)}".encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _derived_id(prefix: str, digest: str) -> str:
    _sha256(digest, "digest")
    return f"{prefix}-{digest[7:39].upper()}"


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise SupplyChainAssessmentError(f"{label} fields are not exact")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise SupplyChainAssessmentError(f"{label} is invalid")
    return value


def _reference(value: Any, label: str, prefix: str) -> str:
    _identifier(value, label)
    if not value.startswith(prefix):
        raise SupplyChainAssessmentError(f"{label} must start with {prefix}")
    if any(token in value.lower() for token in ("secret", "token", "password", "credential")):
        raise SupplyChainAssessmentError(f"{label} is not secret-safe")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise SupplyChainAssessmentError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise SupplyChainAssessmentError(f"{label} is not canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SupplyChainAssessmentError(f"{label} is not a valid timestamp") from exc


def _refs(values: Sequence[str], label: str) -> tuple[str, ...]:
    try:
        normalized = tuple(sorted(set(values)))
    except TypeError as exc:
        raise SupplyChainAssessmentError(f"{label} is invalid") from exc
    if tuple(values) != normalized or not normalized:
        raise SupplyChainAssessmentError(f"{label} must be nonempty, unique, and ordered")
    for value in normalized:
        _identifier(value, label)
    return normalized


def _hashes(values: Sequence[str], label: str) -> tuple[str, ...]:
    try:
        normalized = tuple(sorted(set(values)))
    except TypeError as exc:
        raise SupplyChainAssessmentError(f"{label} is invalid") from exc
    if tuple(values) != normalized:
        raise SupplyChainAssessmentError(f"{label} must be unique and ordered")
    for value in normalized:
        _sha256(value, label)
    return normalized


def _summary(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or value != value.strip():
        raise SupplyChainAssessmentError("summary is invalid")
    return value


def _no_effects(value: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise SupplyChainAssessmentError("no_effects declaration is invalid")
    snapshot = dict(value)
    if snapshot != NO_EFFECTS:
        raise SupplyChainAssessmentError("no_effects declaration is invalid")
    return MappingProxyType(snapshot)
