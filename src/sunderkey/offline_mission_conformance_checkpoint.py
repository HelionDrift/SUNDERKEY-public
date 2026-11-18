"""Restartable, read-only checkpoint for offline mission conformance evidence.

This module validates a supplied evidence prefix. It never invokes an adapter,
performs target work, publishes a finding, or grants action authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .end_to_end_conformance import (
    STAGE_DEFINITIONS,
    Budget,
    ConformancePlan,
    ConformanceResult,
    ConformanceStage,
    EndToEndConformanceError,
    ReceiptStatus,
    StageEvidence,
    StageRequest,
    StageStatus,
    _canonical_document,
    _evidence_gaps,
    _identity,
    _request_for,
    assess_conformance,
    canonical_json,
)


class OfflineMissionCheckpointError(ValueError):
    """Raised when a resumed offline evidence prefix fails closed."""


def _validated_prefix(
    plan: ConformancePlan, evidence: Sequence[StageEvidence]
) -> tuple[StageEvidence, ...]:
    if len(evidence) > len(STAGE_DEFINITIONS):
        raise OfflineMissionCheckpointError("evidence prefix exceeds the stage order")
    version = plan.start_version
    prior_stage: str | None = None
    prior_custody: str | None = None
    used = Budget(0, 0, 0, 0)
    by_stage: dict[ConformanceStage, StageEvidence] = {}
    validated: list[StageEvidence] = []
    for definition, raw in zip(STAGE_DEFINITIONS, evidence, strict=False):
        try:
            item = StageEvidence.from_dict(raw.to_dict())
            request = _request_for(
                plan,
                definition,
                current_version=version,
                prior_stage_sha256=prior_stage,
                prior_custody_sha256=prior_custody,
                budget_used=used,
                evidence_by_stage=by_stage,
            )
            gaps = _evidence_gaps(plan, request, item, used)
        except (EndToEndConformanceError, KeyError, TypeError, ValueError) as exc:
            raise OfflineMissionCheckpointError("stage evidence is invalid") from exc
        if gaps or item.status is not StageStatus.PASSED:
            raise OfflineMissionCheckpointError("stage evidence does not form a valid prefix")
        validated.append(item)
        version = item.version_after
        prior_stage = item.evidence_sha256
        prior_custody = item.custody_sha256
        used = used.plus(item.budget_used)
        by_stage[item.stage] = item
    return tuple(validated)


@dataclass(frozen=True, slots=True)
class OfflineMissionCheckpoint:
    """Content-addressed evidence prefix that can be restored after process exit."""

    plan: ConformancePlan
    evidence: tuple[StageEvidence, ...]
    checkpoint_id: str
    checkpoint_sha256: str

    KIND = "sunderkey.offline-mission-conformance-checkpoint.v1"
    DOMAIN = KIND
    PREFIX = "OMC"

    @classmethod
    def create(
        cls, plan: ConformancePlan, evidence: Sequence[StageEvidence] = ()
    ) -> OfflineMissionCheckpoint:
        try:
            checked_plan = ConformancePlan.from_dict(plan.to_dict())
            checked_evidence = _validated_prefix(checked_plan, evidence)
        except (AttributeError, EndToEndConformanceError, TypeError, ValueError) as exc:
            raise OfflineMissionCheckpointError("checkpoint plan or prefix is invalid") from exc
        body = {
            "effects": {"network": "none", "target_execution": "none", "qualification": "none"},
            "evidence": [item.to_dict() for item in checked_evidence],
            "kind": cls.KIND,
            "plan": checked_plan.to_dict(),
            "schema_version": 1,
        }
        checkpoint_id, checkpoint_sha256 = _identity(cls.PREFIX, cls.DOMAIN, body)
        return cls(checked_plan, checked_evidence, checkpoint_id, checkpoint_sha256)

    @property
    def next_request(self) -> StageRequest | None:
        if len(self.evidence) == len(STAGE_DEFINITIONS):
            return None
        latest = self.evidence[-1] if self.evidence else None
        used = Budget(0, 0, 0, 0)
        by_stage = {}
        for item in self.evidence:
            used = used.plus(item.budget_used)
            by_stage[item.stage] = item
        return _request_for(
            self.plan,
            STAGE_DEFINITIONS[len(self.evidence)],
            current_version=self.plan.start_version + len(self.evidence),
            prior_stage_sha256=None if latest is None else latest.evidence_sha256,
            prior_custody_sha256=None if latest is None else latest.custody_sha256,
            budget_used=used,
            evidence_by_stage=by_stage,
        )

    def append(self, evidence: StageEvidence | Mapping[str, Any]) -> OfflineMissionCheckpoint:
        if self.next_request is None:
            raise OfflineMissionCheckpointError("checkpoint already includes every stage")
        try:
            item = (
                StageEvidence.from_dict(evidence.to_dict())
                if isinstance(evidence, StageEvidence)
                else StageEvidence.from_dict(evidence)
            )
        except (EndToEndConformanceError, KeyError, TypeError, ValueError) as exc:
            raise OfflineMissionCheckpointError("stage evidence is invalid") from exc
        return self.create(self.plan, (*self.evidence, item))

    def assess_completion(self, *, completed_at: str) -> ConformanceResult:
        if self.next_request is not None:
            raise OfflineMissionCheckpointError("checkpoint is not complete")
        result = assess_conformance(self.plan, self.evidence, completed_at=completed_at)
        if result.receipt.status is not ReceiptStatus.CONFORMANT:
            raise OfflineMissionCheckpointError("completed checkpoint is nonconformant")
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_sha256": self.checkpoint_sha256,
            "effects": {"network": "none", "target_execution": "none", "qualification": "none"},
            "evidence": [item.to_dict() for item in self.evidence],
            "kind": self.KIND,
            "plan": self.plan.to_dict(),
            "schema_version": 1,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> OfflineMissionCheckpoint:
        expected = {
            "checkpoint_id",
            "checkpoint_sha256",
            "effects",
            "evidence",
            "kind",
            "plan",
            "schema_version",
        }
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise OfflineMissionCheckpointError("checkpoint fields are invalid")
        if raw["kind"] != cls.KIND or raw["schema_version"] != 1:
            raise OfflineMissionCheckpointError("checkpoint kind or schema is invalid")
        if raw["effects"] != {
            "network": "none",
            "target_execution": "none",
            "qualification": "none",
        }:
            raise OfflineMissionCheckpointError("checkpoint effects are invalid")
        if not isinstance(raw["evidence"], list):
            raise OfflineMissionCheckpointError("checkpoint evidence must be a list")
        try:
            rebuilt = cls.create(
                ConformancePlan.from_dict(raw["plan"]),
                tuple(StageEvidence.from_dict(item) for item in raw["evidence"]),
            )
        except (EndToEndConformanceError, KeyError, TypeError, ValueError) as exc:
            raise OfflineMissionCheckpointError("checkpoint content is invalid") from exc
        if (
            raw["checkpoint_id"] != rebuilt.checkpoint_id
            or raw["checkpoint_sha256"] != rebuilt.checkpoint_sha256
        ):
            raise OfflineMissionCheckpointError("checkpoint content address is invalid")
        return rebuilt

    @classmethod
    def from_json(cls, document: str) -> OfflineMissionCheckpoint:
        try:
            return cls.from_dict(_canonical_document(document))
        except EndToEndConformanceError as exc:
            raise OfflineMissionCheckpointError("checkpoint document is not canonical") from exc
