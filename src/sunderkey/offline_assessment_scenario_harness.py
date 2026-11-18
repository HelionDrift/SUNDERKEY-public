"""Deterministic, inert whole-mission scenario probes over injected observations.

Callbacks in this module are test doubles. The harness never opens a network
connection, contacts a target, dispatches an action, or publishes a finding.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .end_to_end_conformance import Budget, ExecutionBinding, canonical_sha256

SCHEMA_VERSION = 1
KIND = "sunderkey.offline-assessment-scenario-receipt.v1"
PLAN_KIND = "sunderkey.offline-assessment-scenario-plan.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CASE_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{2,95}\Z")
TENANT_RE = re.compile(r"tenantref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
REVIEWER_RE = re.compile(r"reviewerref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "credentials": "not_accessed",
    "dispatch": "none",
    "network": "none",
    "publication": "none",
    "qualification": "none",
    "target_execution": "none",
}
MAX_EPOCH = (1 << 63) - 1
MAX_BUDGET_VALUE = 1_000_000_000_000


class ScenarioError(ValueError):
    """A scenario input or receipt failed closed."""


class Checkpoint(StrEnum):
    INTAKE = "intake"
    ADMISSION = "admission"
    PRE_DISPATCH = "pre_dispatch"
    DISPATCH_ACK = "dispatch_ack"
    EVIDENCE = "evidence"
    REVIEW = "review"
    REPORT = "report"
    PRE_PUBLICATION = "pre_publication"


CHECKPOINTS = tuple(Checkpoint)


class AckState(StrEnum):
    ACCEPTED = "accepted"
    LOST = "lost"
    DUPLICATE = "duplicate"


def _digest(value: str | None, label: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ScenarioError(f"{label} must be a SHA-256 content address")


def _exact(raw: Mapping[str, Any], keys: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != keys:
        raise ScenarioError(f"{label} fields are invalid")


def _epoch(value: int, label: str) -> None:
    if type(value) is not int or not 0 <= value <= MAX_EPOCH:
        raise ScenarioError(f"{label} must be a bounded non-negative integer")


def _bounded_budget(value: Budget, label: str) -> None:
    if type(value) is not Budget or any(
        type(getattr(value, field)) is not int
        or not 0 <= getattr(value, field) <= MAX_BUDGET_VALUE
        for field in ("requests", "tokens", "elapsed_ms", "evidence_bytes")
    ):
        raise ScenarioError(f"{label} must have bounded native integer fields")


@dataclass(frozen=True, slots=True)
class ScenarioPlan:
    case_id: str
    binding: ExecutionBinding
    source_sha256: str
    authority_epoch: int
    fence_epoch: int
    reviewer_ref: str
    budget_ceiling: Budget
    plan_sha256: str

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        binding: ExecutionBinding,
        source_sha256: str,
        authority_epoch: int,
        fence_epoch: int,
        reviewer_ref: str,
        budget_ceiling: Budget,
    ) -> ScenarioPlan:
        _epoch(authority_epoch, "authority_epoch")
        _epoch(fence_epoch, "fence_epoch")
        _bounded_budget(budget_ceiling, "budget_ceiling")
        if type(binding) is not ExecutionBinding:
            raise ScenarioError("binding is invalid")
        try:
            ExecutionBinding.from_dict(binding.to_dict())
        except (TypeError, ValueError) as exc:
            raise ScenarioError("binding is invalid") from exc
        body = {
            "authority_epoch": authority_epoch,
            "binding": binding.to_dict(),
            "budget_ceiling": budget_ceiling.to_dict(),
            "case_id": case_id,
            "fence_epoch": fence_epoch,
            "kind": PLAN_KIND,
            "reviewer_ref": reviewer_ref,
            "schema_version": SCHEMA_VERSION,
            "source_sha256": source_sha256,
        }
        return cls(
            case_id,
            binding,
            source_sha256,
            authority_epoch,
            fence_epoch,
            reviewer_ref,
            budget_ceiling,
            canonical_sha256(body),
        )

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or CASE_RE.fullmatch(self.case_id) is None:
            raise ScenarioError("case_id is invalid")
        if not isinstance(self.binding, ExecutionBinding):
            raise ScenarioError("binding is invalid")
        _digest(self.source_sha256, "source_sha256")
        _epoch(self.authority_epoch, "authority_epoch")
        _epoch(self.fence_epoch, "fence_epoch")
        if (
            not isinstance(self.reviewer_ref, str)
            or REVIEWER_RE.fullmatch(self.reviewer_ref) is None
            or self.reviewer_ref
            == self.binding.operator_ref.replace("operatorref:", "reviewerref:", 1)
        ):
            raise ScenarioError("reviewer_ref must identify an independent reviewer")
        _bounded_budget(self.budget_ceiling, "budget_ceiling")
        body = self.to_dict()
        expected = canonical_sha256(
            {key: value for key, value in body.items() if key != "plan_sha256"}
        )
        if self.plan_sha256 != expected:
            raise ScenarioError("plan content address does not match content")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_epoch": self.authority_epoch,
            "binding": self.binding.to_dict(),
            "budget_ceiling": self.budget_ceiling.to_dict(),
            "case_id": self.case_id,
            "fence_epoch": self.fence_epoch,
            "kind": PLAN_KIND,
            "plan_sha256": self.plan_sha256,
            "reviewer_ref": self.reviewer_ref,
            "schema_version": SCHEMA_VERSION,
            "source_sha256": self.source_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ScenarioPlan:
        _exact(
            raw,
            {
                "authority_epoch", "binding", "budget_ceiling", "case_id",
                "fence_epoch", "kind", "plan_sha256", "reviewer_ref",
                "schema_version", "source_sha256",
            },
            "scenario plan",
        )
        if (
            type(raw["kind"]) is not str
            or raw["kind"] != PLAN_KIND
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != SCHEMA_VERSION
        ):
            raise ScenarioError("scenario plan envelope is invalid")
        return cls(
            raw["case_id"],
            ExecutionBinding.from_dict(raw["binding"]),
            raw["source_sha256"],
            raw["authority_epoch"],
            raw["fence_epoch"],
            raw["reviewer_ref"],
            Budget.from_dict(raw["budget_ceiling"]),
            raw["plan_sha256"],
        )


@dataclass(frozen=True, slots=True)
class ScenarioProbe:
    checkpoint: Checkpoint
    plan_sha256: str
    prior_observation_sha256: str | None
    remaining_budget: Budget


@dataclass(frozen=True, slots=True)
class ScenarioObservation:
    checkpoint: Checkpoint
    tenant_ref: str
    source_sha256: str
    authority_epoch: int
    fence_epoch: int
    authority_active: bool
    health_ready: bool
    budget_used: Budget
    admission_granted: bool | None = None
    ack_state: AckState | None = None
    artifact_sha256: str | None = None
    reviewer_ref: str | None = None
    reviewed_artifact_sha256: str | None = None
    report_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "checkpoint", Checkpoint(self.checkpoint))
        if not isinstance(self.tenant_ref, str) or TENANT_RE.fullmatch(self.tenant_ref) is None:
            raise ScenarioError("tenant_ref is invalid")
        _digest(self.source_sha256, "source_sha256")
        _epoch(self.authority_epoch, "authority_epoch")
        _epoch(self.fence_epoch, "fence_epoch")
        if not isinstance(self.authority_active, bool) or not isinstance(self.health_ready, bool):
            raise ScenarioError("authority and health signals must be booleans")
        _bounded_budget(self.budget_used, "budget_used")
        if self.admission_granted is not None and not isinstance(self.admission_granted, bool):
            raise ScenarioError("admission_granted is invalid")
        if self.ack_state is not None:
            object.__setattr__(self, "ack_state", AckState(self.ack_state))
        _digest(self.artifact_sha256, "artifact_sha256", optional=True)
        _digest(self.reviewed_artifact_sha256, "reviewed_artifact_sha256", optional=True)
        _digest(self.report_sha256, "report_sha256", optional=True)
        if self.reviewer_ref is not None and (
            not isinstance(self.reviewer_ref, str)
            or REVIEWER_RE.fullmatch(self.reviewer_ref) is None
        ):
            raise ScenarioError("reviewer_ref is invalid")

    def to_dict(self) -> dict[str, Any]:
        body = {
            "ack_state": None if self.ack_state is None else self.ack_state.value,
            "admission_granted": self.admission_granted,
            "artifact_sha256": self.artifact_sha256,
            "authority_active": self.authority_active,
            "authority_epoch": self.authority_epoch,
            "budget_used": self.budget_used.to_dict(),
            "checkpoint": self.checkpoint.value,
            "fence_epoch": self.fence_epoch,
            "health_ready": self.health_ready,
            "report_sha256": self.report_sha256,
            "reviewed_artifact_sha256": self.reviewed_artifact_sha256,
            "reviewer_ref": self.reviewer_ref,
            "source_sha256": self.source_sha256,
            "tenant_ref": self.tenant_ref,
        }
        return {**body, "observation_sha256": canonical_sha256(body)}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ScenarioObservation:
        _exact(
            raw,
            {
                "ack_state", "admission_granted", "artifact_sha256", "authority_active",
                "authority_epoch", "budget_used", "checkpoint", "fence_epoch",
                "health_ready", "observation_sha256", "report_sha256",
                "reviewed_artifact_sha256", "reviewer_ref", "source_sha256", "tenant_ref",
            },
            "scenario observation",
        )
        item = cls(
            Checkpoint(raw["checkpoint"]),
            raw["tenant_ref"],
            raw["source_sha256"],
            raw["authority_epoch"],
            raw["fence_epoch"],
            raw["authority_active"],
            raw["health_ready"],
            Budget.from_dict(raw["budget_used"]),
            raw["admission_granted"],
            raw["ack_state"],
            raw["artifact_sha256"],
            raw["reviewer_ref"],
            raw["reviewed_artifact_sha256"],
            raw["report_sha256"],
        )
        if item.to_dict()["observation_sha256"] != raw["observation_sha256"]:
            raise ScenarioError("observation content address does not match content")
        return item


Observer = Callable[[ScenarioProbe], ScenarioObservation | Mapping[str, Any]]


def _snapshot_plan(plan: ScenarioPlan) -> ScenarioPlan:
    if type(plan) is not ScenarioPlan:
        raise ScenarioError("plan must be an exact scenario plan")
    try:
        return ScenarioPlan.from_dict(plan.to_dict())
    except (AttributeError, TypeError, ValueError) as exc:
        raise ScenarioError("plan or nested binding no longer matches its address") from exc


def _require_current_plan(original: ScenarioPlan, snapshot: ScenarioPlan) -> None:
    if _snapshot_plan(original).to_dict() != snapshot.to_dict():
        raise ScenarioError("plan source changed during scenario replay")


def _reason(
    plan: ScenarioPlan,
    item: ScenarioObservation,
    artifact: str | None,
    report: str | None,
) -> str | None:
    if item.tenant_ref != plan.binding.tenant_ref:
        return "cross_tenant_handoff"
    if item.source_sha256 != plan.source_sha256:
        return "stale_source"
    if item.authority_epoch != plan.authority_epoch or not item.authority_active:
        return "authority_revoked_or_stale"
    if item.fence_epoch != plan.fence_epoch:
        return "stale_fence"
    if not item.health_ready:
        return "health_pause"
    if item.admission_granted is False:
        return "admission_denied"
    if item.checkpoint is Checkpoint.ADMISSION and item.admission_granted is not True:
        return "admission_denied"
    if item.checkpoint in {Checkpoint.PRE_DISPATCH, Checkpoint.PRE_PUBLICATION} and (
        item.admission_granted is not True
    ):
        return "admission_not_current"
    if item.checkpoint is Checkpoint.DISPATCH_ACK:
        if item.ack_state is AckState.LOST:
            return "ack_lost_reconciliation_required"
        if item.ack_state is AckState.DUPLICATE:
            return "ack_duplicate_reconciliation_required"
        if item.ack_state is not AckState.ACCEPTED:
            return "ack_missing_reconciliation_required"
    if item.checkpoint is Checkpoint.EVIDENCE and item.artifact_sha256 is None:
        return "evidence_missing"
    if item.checkpoint is Checkpoint.REVIEW and (
        item.reviewer_ref != plan.reviewer_ref or item.reviewed_artifact_sha256 != artifact
    ):
        return "reviewer_or_evidence_mismatch"
    if item.checkpoint is Checkpoint.REPORT and item.report_sha256 is None:
        return "report_missing"
    if item.checkpoint is Checkpoint.PRE_PUBLICATION and item.report_sha256 != report:
        return "report_rebound"
    return None


def _receipt(
    plan: ScenarioPlan,
    observations: list[ScenarioObservation],
    *,
    reason: str | None,
    prior_receipt_sha256: str | None,
) -> dict[str, Any]:
    total = Budget(0, 0, 0, 0)
    for item in observations:
        total = total.plus(item.budget_used)
    spent = Budget(0, 0, 0, 0)
    dispatches = 0
    artifact: str | None = None
    report: str | None = None
    for item in observations:
        spent = spent.plus(item.budget_used)
        if spent.exceeds(plan.budget_ceiling) or _reason(plan, item, artifact, report) is not None:
            break
        if item.checkpoint is Checkpoint.PRE_DISPATCH:
            dispatches = 1
        elif item.checkpoint is Checkpoint.EVIDENCE:
            artifact = item.artifact_sha256
        elif item.checkpoint is Checkpoint.REPORT:
            report = item.report_sha256
    publications = int(reason is None and len(observations) == len(CHECKPOINTS))
    body = {
        "case_id": plan.case_id,
        "effects": dict(NO_EFFECTS),
        "kind": KIND,
        "observations": [item.to_dict() for item in observations],
        "outcome": "simulated_complete" if publications else "denied",
        "plan_sha256": plan.plan_sha256,
        "prior_receipt_sha256": prior_receipt_sha256,
        "proof_scope": "repository_only_injected_scenario",
        "qualification_effect": "none",
        "reason": reason,
        "schema_version": SCHEMA_VERSION,
        "simulated_dispatches": dispatches,
        "simulated_positive_publications": publications,
        "total_budget_used": total.to_dict(),
    }
    return {**body, "receipt_sha256": canonical_sha256(body)}


def run_scenario(
    plan: ScenarioPlan,
    observers: Mapping[Checkpoint | str, Observer],
    *,
    prior_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run at most eight injected, local observations with no real-world effects."""

    original_plan = plan
    plan = _snapshot_plan(plan)
    normalized = {Checkpoint(key): value for key, value in observers.items()}
    if prior_receipt is not None:
        prior = verify_scenario_receipt(plan, prior_receipt)
        if prior["prior_receipt_sha256"] is not None:
            raise ScenarioError("chained restart receipts require independent reconciliation")
        if prior["simulated_positive_publications"]:
            reason = "already_simulated_published"
        elif prior["simulated_dispatches"]:
            reason = "restart_reconciliation_required"
        else:
            reason = "prior_terminal_plan"
        _require_current_plan(original_plan, plan)
        return _receipt(plan, [], reason=reason, prior_receipt_sha256=prior["receipt_sha256"])

    observations: list[ScenarioObservation] = []
    budget = Budget(0, 0, 0, 0)
    artifact: str | None = None
    report: str | None = None
    reason: str | None = None
    for checkpoint in CHECKPOINTS:
        observer = normalized.get(checkpoint)
        if observer is None:
            reason = "missing_observer"
            break
        probe = ScenarioProbe(
            checkpoint,
            plan.plan_sha256,
            observations[-1].to_dict()["observation_sha256"] if observations else None,
            plan.budget_ceiling.remaining(budget),
        )
        try:
            raw = observer(probe)
            item = (
                ScenarioObservation.from_dict(raw.to_dict())
                if isinstance(raw, ScenarioObservation)
                else ScenarioObservation.from_dict(raw)
            )
        except Exception:  # noqa: BLE001 - injected observer boundary fails closed
            reason = "observer_failure"
            break
        try:
            _require_current_plan(original_plan, plan)
        except ScenarioError:
            reason = "plan_source_changed"
            break
        if item.checkpoint is not checkpoint:
            reason = "invalid_observation"
            break
        observations.append(item)
        budget = budget.plus(item.budget_used)
        if budget.exceeds(plan.budget_ceiling):
            reason = "budget_exceeded"
            break
        reason = _reason(plan, item, artifact, report)
        if reason is not None:
            break
        if checkpoint is Checkpoint.EVIDENCE:
            artifact = item.artifact_sha256
        elif checkpoint is Checkpoint.REPORT:
            report = item.report_sha256
    _require_current_plan(original_plan, plan)
    return _receipt(plan, observations, reason=reason, prior_receipt_sha256=None)


def verify_scenario_receipt(
    plan: ScenarioPlan,
    raw: Mapping[str, Any],
    *,
    prior_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify receipt integrity and replay its recorded gate outcomes."""

    original_plan = plan
    plan = _snapshot_plan(plan)
    _exact(
        raw,
        {
            "case_id", "effects", "kind", "observations", "outcome", "plan_sha256",
            "prior_receipt_sha256", "proof_scope", "qualification_effect", "reason",
            "receipt_sha256", "schema_version", "simulated_dispatches",
            "simulated_positive_publications", "total_budget_used",
        },
        "scenario receipt",
    )
    if (
        raw["case_id"] != plan.case_id
        or raw["plan_sha256"] != plan.plan_sha256
        or raw["effects"] != NO_EFFECTS
        or raw["kind"] != KIND
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != SCHEMA_VERSION
        or raw["proof_scope"] != "repository_only_injected_scenario"
        or raw["qualification_effect"] != "none"
    ):
        raise ScenarioError("receipt envelope or plan binding is invalid")
    for key in ("simulated_dispatches", "simulated_positive_publications"):
        if type(raw[key]) is not int or raw[key] not in {0, 1}:
            raise ScenarioError(f"{key} must be zero or one")
    Budget.from_dict(raw["total_budget_used"])
    if not isinstance(raw["observations"], list) or len(raw["observations"]) > len(CHECKPOINTS):
        raise ScenarioError("receipt observation count is invalid")
    observations = [ScenarioObservation.from_dict(item) for item in raw["observations"]]
    for index, item in enumerate(observations):
        if item.checkpoint is not CHECKPOINTS[index]:
            raise ScenarioError("receipt checkpoint order is invalid")
    reason: str | None = None
    if raw["prior_receipt_sha256"] is not None:
        if prior_receipt is None or observations:
            raise ScenarioError("restart receipt requires its prior receipt and no observations")
        prior = verify_scenario_receipt(plan, prior_receipt)
        if prior["prior_receipt_sha256"] is not None:
            raise ScenarioError("chained restart receipts are unsupported")
        reason = (
            "already_simulated_published" if prior["simulated_positive_publications"]
            else "restart_reconciliation_required" if prior["simulated_dispatches"]
            else "prior_terminal_plan"
        )
        if raw["prior_receipt_sha256"] != prior["receipt_sha256"]:
            raise ScenarioError("restart receipt does not bind prior receipt")
    else:
        budget = Budget(0, 0, 0, 0)
        artifact: str | None = None
        report: str | None = None
        for item in observations:
            budget = budget.plus(item.budget_used)
            if budget.exceeds(plan.budget_ceiling):
                reason = "budget_exceeded"
                break
            reason = _reason(plan, item, artifact, report)
            if reason is not None:
                break
            if item.checkpoint is Checkpoint.EVIDENCE:
                artifact = item.artifact_sha256
            elif item.checkpoint is Checkpoint.REPORT:
                report = item.report_sha256
        if reason is not None and observations[-1] is not item:
            raise ScenarioError("receipt contains observations after denial")
        if reason is None and len(observations) < len(CHECKPOINTS):
            if raw["reason"] not in {"observer_failure", "missing_observer", "invalid_observation"}:
                raise ScenarioError("receipt ended without a terminal reason")
            reason = raw["reason"]
    expected = _receipt(
        plan, observations, reason=reason,
        prior_receipt_sha256=raw["prior_receipt_sha256"],
    )
    if dict(raw) != expected:
        raise ScenarioError("receipt integrity or replay outcome is invalid")
    _require_current_plan(original_plan, plan)
    return expected
