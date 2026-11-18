"""Inert per-hop evidence checklist for a replayed identity path plan."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .identity_cloud_reasoning import (
    MAX_DEPTH,
    MAX_PATHS,
    MAX_RECORDS,
    NO_EFFECTS,
    CompletePathValidationPlan,
    IdentityCloudReasoningError,
    IdentityCloudSnapshot,
    PathSearchResult,
    ResolutionState,
    SECRET_RE,
    canonical_sha256,
    resolve_effective_permission,
    verify_complete_path_validation_plan,
)

SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class IdentityPathHopPlanError(ValueError):
    """Raised when a hop checklist or its source replay fails closed."""


class HopKind(StrEnum):
    WORKLOAD_BINDING = "workload_binding"
    TRUST_RELATION = "trust_relation"
    SESSION_TRANSITION = "session_transition"
    EFFECTIVE_PERMISSION = "effective_permission"


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise IdentityPathHopPlanError(f"{label} must be a sha256 digest")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None or SECRET_RE.search(value):
        raise IdentityPathHopPlanError(f"{label} must be a safe identifier")
    return value


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IdentityPathHopPlanError(f"{label} fields are invalid")
    return value


def _identity(prefix: str, domain: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": body, "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


@dataclass(frozen=True)
class PathHopValidationStep:
    path_id: str
    ordinal: int
    source_id: str
    target_id: str
    relation_id: str
    kind: HopKind | str
    record_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    credential_reference_id: str | None = None
    step_id: str = field(init=False)
    step_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("path_id", "source_id", "target_id", "relation_id"):
            _id(getattr(self, name), name)
        if (
            isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or not 0 <= self.ordinal <= MAX_DEPTH
        ):
            raise IdentityPathHopPlanError("hop ordinal is invalid")
        try:
            kind = HopKind(self.kind)
        except (ValueError, TypeError) as exc:
            raise IdentityPathHopPlanError("hop kind is invalid") from exc
        object.__setattr__(self, "kind", kind)
        for name in ("record_ids", "evidence_ids"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values or len(values) > MAX_RECORDS:
                raise IdentityPathHopPlanError(f"{name} is invalid")
            for value in values:
                _id(value, name)
            if len(set(values)) != len(values):
                raise IdentityPathHopPlanError(f"{name} contains duplicates")
            object.__setattr__(self, name, tuple(sorted(values)))
        if self.credential_reference_id is not None:
            _id(self.credential_reference_id, "credential_reference_id")
            if kind != HopKind.SESSION_TRANSITION:
                raise IdentityPathHopPlanError(
                    "credential reference is outside a session transition"
                )
        step_id, digest = _identity("IHS", "identity-path-hop-step.v1", self._body())
        object.__setattr__(self, "step_id", step_id)
        object.__setattr__(self, "step_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "credential_reference_id": self.credential_reference_id,
            "evidence_ids": list(self.evidence_ids),
            "kind": self.kind.value,
            "ordinal": self.ordinal,
            "path_id": self.path_id,
            "record_ids": list(self.record_ids),
            "relation_id": self.relation_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "step_id": self.step_id, "step_sha256": self.step_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> PathHopValidationStep:
        fields = {
            "credential_reference_id",
            "evidence_ids",
            "kind",
            "ordinal",
            "path_id",
            "record_ids",
            "relation_id",
            "source_id",
            "target_id",
            "step_id",
            "step_sha256",
        }
        value = _exact(raw, fields, "hop step")
        if not isinstance(value["record_ids"], list) or not isinstance(value["evidence_ids"], list):
            raise IdentityPathHopPlanError("hop reference arrays are invalid")
        built = cls(
            value["path_id"],
            value["ordinal"],
            value["source_id"],
            value["target_id"],
            value["relation_id"],
            value["kind"],
            tuple(value["record_ids"]),
            tuple(value["evidence_ids"]),
            value["credential_reference_id"],
        )
        if value["step_id"] != built.step_id or value["step_sha256"] != built.step_sha256:
            raise IdentityPathHopPlanError("hop step content address is invalid")
        return built


@dataclass(frozen=True)
class IdentityPathHopValidationPlan:
    snapshot_sha256: str
    search_result_sha256: str
    review_plan_sha256: str
    attributes_sha256: str
    evaluated_at: str
    path_ids: tuple[str, ...]
    steps: tuple[PathHopValidationStep, ...]
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name in (
            "snapshot_sha256",
            "search_result_sha256",
            "review_plan_sha256",
            "attributes_sha256",
        ):
            _digest(getattr(self, name), name)
        if not isinstance(self.evaluated_at, str) or TIME_RE.fullmatch(self.evaluated_at) is None:
            raise IdentityPathHopPlanError("evaluated_at is invalid")
        try:
            datetime.strptime(self.evaluated_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise IdentityPathHopPlanError("evaluated_at is invalid") from exc
        if not isinstance(self.path_ids, tuple) or not 1 <= len(self.path_ids) <= MAX_PATHS:
            raise IdentityPathHopPlanError("path set is invalid")
        for path_id in self.path_ids:
            _id(path_id, "path_id")
        if tuple(sorted(set(self.path_ids))) != self.path_ids:
            raise IdentityPathHopPlanError("path set must be unique and ordered")
        if not isinstance(self.steps, tuple) or not 1 <= len(self.steps) <= MAX_PATHS * (
            MAX_DEPTH + 1
        ):
            raise IdentityPathHopPlanError("hop step count is invalid")
        grouped: dict[str, list[PathHopValidationStep]] = {path_id: [] for path_id in self.path_ids}
        for step in self.steps:
            if not isinstance(step, PathHopValidationStep) or step.path_id not in grouped:
                raise IdentityPathHopPlanError("hop step path binding is invalid")
            grouped[step.path_id].append(step)
        if tuple(sorted(self.steps, key=lambda item: (item.path_id, item.ordinal))) != self.steps:
            raise IdentityPathHopPlanError("hop steps are not ordered")
        for path_steps in grouped.values():
            if not path_steps or [item.ordinal for item in path_steps] != list(
                range(len(path_steps))
            ):
                raise IdentityPathHopPlanError("hop sequence is incomplete")
            if path_steps[-1].kind != HopKind.EFFECTIVE_PERMISSION:
                raise IdentityPathHopPlanError("hop sequence lacks final permission evidence")
            if any(item.kind == HopKind.EFFECTIVE_PERMISSION for item in path_steps[:-1]):
                raise IdentityPathHopPlanError("permission evidence is not terminal")
            if any(
                left.target_id != right.source_id for left, right in zip(path_steps, path_steps[1:])
            ):
                raise IdentityPathHopPlanError("hop sequence is disconnected")
        plan_id, digest = _identity("IHP", "identity-path-hop-plan.v1", self._body())
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "attributes_sha256": self.attributes_sha256,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": "sunderkey.identity-path-hop-plan.v1",
            "path_ids": list(self.path_ids),
            "review_plan_sha256": self.review_plan_sha256,
            "schema_version": 1,
            "search_result_sha256": self.search_result_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "steps": [step.to_dict() for step in self.steps],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> IdentityPathHopValidationPlan:
        fields = {
            "attributes_sha256",
            "effects",
            "evaluated_at",
            "kind",
            "path_ids",
            "plan_id",
            "plan_sha256",
            "review_plan_sha256",
            "schema_version",
            "search_result_sha256",
            "snapshot_sha256",
            "steps",
        }
        value = _exact(raw, fields, "hop plan")
        if (
            value["kind"] != "sunderkey.identity-path-hop-plan.v1"
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
        ):
            raise IdentityPathHopPlanError("hop plan version is invalid")
        if not isinstance(value["effects"], Mapping) or dict(value["effects"]) != dict(NO_EFFECTS):
            raise IdentityPathHopPlanError("hop plan effects are invalid")
        if not isinstance(value["path_ids"], list) or not isinstance(value["steps"], list):
            raise IdentityPathHopPlanError("hop plan arrays are invalid")
        built = cls(
            value["snapshot_sha256"],
            value["search_result_sha256"],
            value["review_plan_sha256"],
            value["attributes_sha256"],
            value["evaluated_at"],
            tuple(value["path_ids"]),
            tuple(PathHopValidationStep.from_dict(step) for step in value["steps"]),
        )
        if value["plan_id"] != built.plan_id or value["plan_sha256"] != built.plan_sha256:
            raise IdentityPathHopPlanError("hop plan content address is invalid")
        return built


def build_identity_path_hop_plan(
    snapshot: IdentityCloudSnapshot,
    result: PathSearchResult,
    review_plan: CompletePathValidationPlan,
    *,
    attributes: Mapping[str, str],
    as_of: str,
) -> IdentityPathHopValidationPlan:
    """Recheck the inert reviewed plan and list exact graph evidence per hop."""

    try:
        verify_complete_path_validation_plan(
            snapshot, result, review_plan, attributes=attributes, as_of=as_of
        )
    except IdentityCloudReasoningError as exc:
        raise IdentityPathHopPlanError("reviewed path source replay failed") from exc
    workloads = {item.workload_identity_id: item for item in snapshot.workload_identities}
    trusts = {item.trust_relation_id: item for item in snapshot.trust_relations}
    transitions = {item.session_transition_id: item for item in snapshot.session_transitions}
    facts = {item.permission_fact_id: item for item in snapshot.permission_facts}
    steps: list[PathHopValidationStep] = []
    for path in result.paths:
        for ordinal, edge_id in enumerate(path.edge_ids):
            source, target = path.node_ids[ordinal : ordinal + 2]
            if edge_id in workloads:
                record = workloads[edge_id]
                kind = HopKind.WORKLOAD_BINDING
                expected = (record.workload_identity_id, record.principal_id)
                credential_id = None
            elif edge_id in trusts:
                record = trusts[edge_id]
                kind = HopKind.TRUST_RELATION
                expected = (record.source_id, record.target_role_id)
                credential_id = None
            elif edge_id in transitions:
                record = transitions[edge_id]
                kind = HopKind.SESSION_TRANSITION
                expected = (record.source_id, record.target_id)
                credential_id = record.credential_id
            else:
                raise IdentityPathHopPlanError("path edge is absent from the snapshot")
            if (source, target) != expected:
                raise IdentityPathHopPlanError("path edge topology is invalid")
            evidence_ids = {record.evidence_id}
            if credential_id is not None:
                credential = next(
                    item for item in snapshot.credentials if item.credential_id == credential_id
                )
                evidence_ids.add(credential.evidence_id)
            steps.append(
                PathHopValidationStep(
                    path.path_id,
                    ordinal,
                    source,
                    target,
                    edge_id,
                    kind,
                    (edge_id,),
                    tuple(evidence_ids),
                    credential_id,
                )
            )
        subject_id, resource_id = path.node_ids[-2:]
        resolution = resolve_effective_permission(
            snapshot,
            subject_id=subject_id,
            resource_id=resource_id,
            action=result.action,
            attributes=attributes,
            as_of=as_of,
        )
        if (
            resolution.resolution_id != path.resolution_id
            or resolution.state != ResolutionState.ALLOWED
        ):
            raise IdentityPathHopPlanError("final permission resolution changed")
        direct_facts = tuple(
            facts[fact_id]
            for fact_id in resolution.allow_fact_ids
            if facts[fact_id].subject_id == subject_id
        )
        if not direct_facts:
            raise IdentityPathHopPlanError("final permission lacks a direct allow fact")
        direct_ids = {fact.permission_fact_id for fact in direct_facts}
        active_policies = tuple(
            policy
            for policy in snapshot.policies
            if policy.policy_id in resolution.provenance_ids
            and direct_ids.intersection(policy.permission_fact_ids)
        )
        if not active_policies:
            raise IdentityPathHopPlanError("final permission lacks a current policy")
        steps.append(
            PathHopValidationStep(
                path.path_id,
                len(path.edge_ids),
                subject_id,
                resource_id,
                path.resolution_id,
                HopKind.EFFECTIVE_PERMISSION,
                tuple(direct_ids | {policy.policy_id for policy in active_policies}),
                tuple(
                    {fact.evidence_id for fact in direct_facts}
                    | {policy.evidence_id for policy in active_policies}
                ),
            )
        )
    if len(steps) != review_plan.maximum_validation_steps:
        raise IdentityPathHopPlanError("hop count differs from the reviewed plan")
    return IdentityPathHopValidationPlan(
        snapshot.snapshot_sha256,
        result.result_sha256,
        review_plan.plan_sha256,
        review_plan.attributes_sha256,
        review_plan.evaluated_at,
        review_plan.path_ids,
        tuple(sorted(steps, key=lambda item: (item.path_id, item.ordinal))),
    )


def verify_identity_path_hop_plan(
    snapshot: IdentityCloudSnapshot,
    result: PathSearchResult,
    review_plan: CompletePathValidationPlan,
    hop_plan: IdentityPathHopValidationPlan,
    *,
    attributes: Mapping[str, str],
    as_of: str,
) -> IdentityPathHopValidationPlan:
    """Require exact source reconstruction for a stored hop checklist."""

    expected = build_identity_path_hop_plan(
        snapshot, result, review_plan, attributes=attributes, as_of=as_of
    )
    if hop_plan != expected:
        raise IdentityPathHopPlanError("hop plan does not match source replay")
    return hop_plan


__all__ = [
    "HopKind",
    "IdentityPathHopPlanError",
    "IdentityPathHopValidationPlan",
    "PathHopValidationStep",
    "build_identity_path_hop_plan",
    "verify_identity_path_hop_plan",
]
