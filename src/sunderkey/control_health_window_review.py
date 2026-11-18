"""Offline review of declared control health across an exact action window."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from .detection_validation_contracts import (
    DetectionValidationContract,
    DetectionValidationError,
    OutcomeState,
)
from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes

DOMAIN = "sunderkey.control-health-window-review.v1"
DECLARATION_DOMAIN = "sunderkey.control-health-declaration.v1"
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
HEALTH_STATES = frozenset({"operational", "degraded", "unavailable", "unknown"})
MAX_DECLARATIONS = 512
MAX_BYTES = 2_000_000


class ControlHealthWindowReviewError(ValueError):
    """A health declaration or its source replay failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value, max_bytes=MAX_BYTES)
    except JsonContractIntegrityError as exc:
        raise ControlHealthWindowReviewError("review exceeds the closed JSON contract") from exc


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise ControlHealthWindowReviewError(f"{label} is not a SHA-256 digest")
    return value


def _instant(value: Any, label: str) -> datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise ControlHealthWindowReviewError(f"{label} must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ControlHealthWindowReviewError(f"{label} is invalid") from exc


def _declaration(
    raw: Any,
    objectives: dict[str, Any],
    contract: DetectionValidationContract,
    as_of: datetime,
) -> dict[str, Any]:
    fields = {
        "objective_id", "control_id", "control_config_sha256", "scope_sha256",
        "action_sha256", "valid_from", "valid_through", "health_state",
        "source_sha256", "declaration_sha256",
    }
    if type(raw) is not dict or set(raw) != fields or any(type(key) is not str for key in raw):
        raise ControlHealthWindowReviewError("health declaration fields are invalid")
    objective_id = raw["objective_id"]
    if type(objective_id) is not str or objective_id not in objectives:
        raise ControlHealthWindowReviewError("health declaration names an unknown objective")
    objective = objectives[objective_id]
    if (
        type(raw["control_id"]) is not str
        or raw["control_id"] != objective.control_id
        or _digest(raw["control_config_sha256"], "control_config_sha256")
        != objective.control_config_sha256
        or _digest(raw["scope_sha256"], "scope_sha256")
        != contract.binding.scope_sha256
        or _digest(raw["action_sha256"], "action_sha256")
        != contract.binding.action_sha256
    ):
        raise ControlHealthWindowReviewError("health declaration differs from exact action")
    state = raw["health_state"]
    if type(state) is not str or state not in HEALTH_STATES:
        raise ControlHealthWindowReviewError("health_state is invalid")
    started = _instant(raw["valid_from"], "valid_from")
    ended = _instant(raw["valid_through"], "valid_through")
    if not timedelta(0) <= ended - started <= timedelta(hours=24) or ended > as_of:
        raise ControlHealthWindowReviewError("health interval exceeds the hard limit")
    _digest(raw["source_sha256"], "source_sha256")
    _digest(raw["declaration_sha256"], "declaration_sha256")
    body = {key: raw[key] for key in fields if key != "declaration_sha256"}
    if _sha({"domain": DECLARATION_DOMAIN, "body": body}) != raw["declaration_sha256"]:
        raise ControlHealthWindowReviewError("health declaration content address is invalid")
    return {**body, "declaration_sha256": raw["declaration_sha256"]}


def build_control_health_window_review(
    *,
    contract: DetectionValidationContract,
    health_declarations: tuple[dict[str, Any], ...],
    as_of: str,
) -> dict[str, Any]:
    """Reconcile asserted health intervals without verifying deployed control state."""

    if type(contract) is not DetectionValidationContract:
        raise ControlHealthWindowReviewError("contract must be a typed base record")
    try:
        verified = DetectionValidationContract.from_dict(contract.to_dict())
    except (DetectionValidationError, TypeError, ValueError, AttributeError) as exc:
        raise ControlHealthWindowReviewError("detection contract integrity is invalid") from exc
    if verified != contract:
        raise ControlHealthWindowReviewError("detection contract integrity is invalid")
    as_of_time = _instant(as_of, "as_of")
    if as_of_time < _instant(verified.evaluated_at, "evaluated_at"):
        raise ControlHealthWindowReviewError("review predates the detection contract")
    if type(health_declarations) is not tuple or len(health_declarations) > MAX_DECLARATIONS:
        raise ControlHealthWindowReviewError("health declarations exceed the hard limit")
    objectives = {item.objective_id: item for item in verified.objectives}
    checked: dict[str, dict[str, Any]] = {}
    for raw in health_declarations:
        item = _declaration(raw, objectives, verified, as_of_time)
        prior = checked.get(item["declaration_sha256"])
        if prior is not None:
            raise ControlHealthWindowReviewError("health declaration is repeated")
        checked[item["declaration_sha256"]] = item
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in checked.values():
        grouped[item["objective_id"]].append(item)

    action_start = _instant(verified.binding.execution_started_at, "execution_started_at")
    action_end = _instant(verified.binding.execution_completed_at, "execution_completed_at")
    outcomes = {item.objective_id: item for item in verified.control_outcomes}
    entries: list[dict[str, Any]] = []
    for objective in sorted(verified.objectives, key=lambda item: item.objective_id):
        supplied = grouped[objective.objective_id]
        covering = [
            item for item in supplied
            if _instant(item["valid_from"], "valid_from") <= action_start
            and _instant(item["valid_through"], "valid_through") >= action_end
        ]
        overlapping = [
            item for item in supplied
            if _instant(item["valid_from"], "valid_from") <= action_end
            and _instant(item["valid_through"], "valid_through") >= action_start
        ]
        states = {item["health_state"] for item in overlapping}
        if len(states) > 1:
            disposition = "conflict"
        elif covering:
            disposition = "declared_" + next(iter(states))
        else:
            disposition = "partial_coverage" if overlapping else "missing"
        outcome = outcomes[objective.objective_id].outcome_state
        entries.append({
            "objective_id": objective.objective_id,
            "control_id": objective.control_id,
            "control_config_sha256": objective.control_config_sha256,
            "contract_outcome_state": outcome.value,
            "health_disposition": disposition,
            "full_window_coverage_declared": bool(covering),
            "overlapping_declaration_sha256": sorted(
                item["declaration_sha256"] for item in overlapping
            ),
            "covering_declaration_sha256": sorted(
                item["declaration_sha256"] for item in covering
            ),
            "effective_claim_needs_health_review": (
                outcome is OutcomeState.EFFECTIVE
                and disposition != "declared_operational"
            ),
        })
    body = {
        "schema_version": 1,
        "contract_id": verified.contract_id,
        "contract_sha256": verified.contract_sha256,
        "assessment_id": verified.binding.assessment_id,
        "execution_id": verified.binding.execution_id,
        "scope_sha256": verified.binding.scope_sha256,
        "action_sha256": verified.binding.action_sha256,
        "action_window_started_at": verified.binding.execution_started_at,
        "action_window_completed_at": verified.binding.execution_completed_at,
        "as_of": as_of,
        "declarations_sha256": _sha([
            checked[key] for key in sorted(checked)
        ]),
        "objective_count": len(entries),
        "missing_or_partial_count": sum(
            not item["full_window_coverage_declared"] for item in entries
        ),
        "conflict_count": sum(item["health_disposition"] == "conflict" for item in entries),
        "effective_claim_health_review_count": sum(
            item["effective_claim_needs_health_review"] for item in entries
        ),
        "objectives": entries,
        "source_provenance": "caller_asserted_not_authenticated",
        "control_health_authenticated": False,
        "authorization_effect": "none",
        "execution_effect": "none",
        "network_call_performed": False,
        "qualification_effect": "none",
        "review_status": "independent_review_required",
    }
    digest = _sha({"domain": DOMAIN, "body": body})
    return {**body, "review_id": "CHWR-" + digest[7:39].upper(), "review_sha256": digest}


def verify_control_health_window_review_from_sources(
    review: dict[str, Any],
    *,
    contract: DetectionValidationContract,
    health_declarations: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    """Rebuild the exact historical review from its original declared sources."""

    if type(review) is not dict:
        raise ControlHealthWindowReviewError("review must be an exact object")
    expected = build_control_health_window_review(
        contract=contract,
        health_declarations=health_declarations,
        as_of=review.get("as_of"),
    )
    if _canonical(review) != _canonical(expected):
        raise ControlHealthWindowReviewError("control health review differs from source replay")
    return expected
