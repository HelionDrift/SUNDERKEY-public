"""Offline review of declared cross-service action and evidence chains."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes

DOMAIN = "sunderkey.cross-service-chain-review.v1"
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REF_RE = re.compile(
    r"(tenantref|missionref|chainref|hopref|actorref|attemptref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z"
)
SURFACE_RE = re.compile(r"surfaceref:sha256:[0-9a-f]{64}\Z")
CREDENTIAL_RE = re.compile(r"credentialref:sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
DOMAINS = frozenset({
    "application", "identity", "cloud", "container", "host", "network", "data",
})
MAX_HOPS = 16
EFFECTS = {
    "admission": "none",
    "authorization": "none",
    "credential_access": "none",
    "execution": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class CrossServiceChainReviewError(ValueError):
    """A chain source or reproduced review failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value, max_bytes=1_000_000)
    except JsonContractIntegrityError as exc:
        raise CrossServiceChainReviewError("source must be bounded exact JSON") from exc


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(
        type(key) is not str for key in value
    ):
        raise CrossServiceChainReviewError(f"{label} fields are invalid")
    return value


def _ref(value: Any, prefix: str, label: str) -> str:
    if type(value) is not str or REF_RE.fullmatch(value) is None or not value.startswith(
        prefix + ":",
    ):
        raise CrossServiceChainReviewError(f"{label} is not an opaque {prefix} reference")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise CrossServiceChainReviewError(f"{label} is not a SHA-256 reference")
    return value


def _instant(value: Any, label: str) -> datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise CrossServiceChainReviewError(f"{label} must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CrossServiceChainReviewError(f"{label} is invalid") from exc


def _plan(raw: Any, as_of: datetime) -> dict[str, Any]:
    plan = _exact(raw, {
        "schema_version", "tenant_ref", "mission_ref", "scope_sha256",
        "chain_ref", "source_plan_sha256", "created_at", "expires_at", "hops",
    }, "chain plan")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise CrossServiceChainReviewError("plan version is invalid")
    for field, prefix in (
        ("tenant_ref", "tenantref"), ("mission_ref", "missionref"),
        ("chain_ref", "chainref"),
    ):
        _ref(plan[field], prefix, field)
    _digest(plan["scope_sha256"], "scope_sha256")
    _digest(plan["source_plan_sha256"], "source_plan_sha256")
    created = _instant(plan["created_at"], "created_at")
    expires = _instant(plan["expires_at"], "expires_at")
    if created > as_of or not timedelta(0) < expires - created <= timedelta(hours=24):
        raise CrossServiceChainReviewError("plan time window exceeds hard limit")
    hops = plan["hops"]
    if type(hops) is not list or not 1 <= len(hops) <= MAX_HOPS:
        raise CrossServiceChainReviewError("hop plan exceeds bound or is empty")
    seen: set[str] = set()
    prior_target: str | None = None
    prior_domain: str | None = None
    for index, item in enumerate(hops):
        hop = _exact(item, {
            "hop_ref", "from_surface_ref", "to_surface_ref", "from_domain",
            "to_domain", "boundary_kind", "action_tier", "action_sha256",
            "policy_snapshot_sha256", "evidence_requirement_sha256",
            "cleanup_requirement_sha256", "credential_transition",
            "credential_ref", "credential_binding_sha256",
        }, f"planned hop {index}")
        ref = _ref(hop["hop_ref"], "hopref", "hop_ref")
        if ref in seen:
            raise CrossServiceChainReviewError("hop references must be unique")
        seen.add(ref)
        source = hop["from_surface_ref"]
        target = hop["to_surface_ref"]
        if (
            type(source) is not str or SURFACE_RE.fullmatch(source) is None
            or type(target) is not str or SURFACE_RE.fullmatch(target) is None
            or source == target
        ):
            raise CrossServiceChainReviewError("surface references are not opaque and distinct")
        if prior_target is not None and source != prior_target:
            raise CrossServiceChainReviewError("planned hops are disconnected")
        for field in ("from_domain", "to_domain"):
            if type(hop[field]) is not str or hop[field] not in DOMAINS:
                raise CrossServiceChainReviewError("domain classification is invalid")
        if prior_domain is not None and hop["from_domain"] != prior_domain:
            raise CrossServiceChainReviewError("domain lineage is disconnected")
        expected_boundary = (
            "same_domain" if hop["from_domain"] == hop["to_domain"]
            else "cross_domain"
        )
        if hop["boundary_kind"] != expected_boundary:
            raise CrossServiceChainReviewError("boundary kind contradicts domain transition")
        if type(hop["action_tier"]) is not str or hop["action_tier"] not in {
            "R0", "R1", "R2", "R3", "R4",
        }:
            raise CrossServiceChainReviewError("action tier is invalid")
        for field in (
            "action_sha256", "policy_snapshot_sha256", "evidence_requirement_sha256",
            "cleanup_requirement_sha256",
        ):
            _digest(hop[field], field)
        transition = hop["credential_transition"]
        credential = hop["credential_ref"]
        binding = hop["credential_binding_sha256"]
        if transition == "none":
            if credential is not None or binding is not None:
                raise CrossServiceChainReviewError("credential transition fields conflict")
        elif transition in ("synthetic_seed", "brokered_opaque"):
            if transition == "synthetic_seed" and index != 0:
                raise CrossServiceChainReviewError("synthetic seed is only valid at start")
            if type(credential) is not str or CREDENTIAL_RE.fullmatch(credential) is None:
                raise CrossServiceChainReviewError("credential reference is not opaque")
            _digest(binding, "credential binding")
        else:
            raise CrossServiceChainReviewError("credential transition is invalid")
        prior_target = target
        prior_domain = hop["to_domain"]
    return plan


def _observations(
    raw: Any, plan: dict[str, Any], as_of: datetime,
) -> list[dict[str, Any]]:
    if type(raw) is not list or len(raw) > len(plan["hops"]):
        raise CrossServiceChainReviewError("observation count exceeds hop plan")
    created = _instant(plan["created_at"], "created_at")
    expires = _instant(plan["expires_at"], "expires_at")
    admissions: set[str] = set()
    attempts: set[str] = set()
    prior_time = created
    prior_outcome = "declared_passed"
    for index, item in enumerate(raw):
        observation = _exact(item, {
            "hop_ref", "planned_hop_sha256", "admission_sha256",
            "admission_issued_at", "admission_expires_at", "admission_scope_sha256",
            "admission_action_sha256", "admission_credential_binding_sha256",
            "actor_ref", "attempt_ref", "attempted_at", "declared_outcome",
            "evidence_sha256", "custody_sha256", "cleanup_status", "cleanup_at",
            "cleanup_evidence_sha256",
        }, f"observation {index}")
        hop = plan["hops"][index]
        if prior_outcome != "declared_passed":
            raise CrossServiceChainReviewError("observation continues after a stopped hop")
        if observation["hop_ref"] != hop["hop_ref"] or (
            observation["planned_hop_sha256"] != _sha(hop)
        ):
            raise CrossServiceChainReviewError("observation does not bind planned hop")
        admission = _digest(observation["admission_sha256"], "admission")
        attempt = _ref(observation["attempt_ref"], "attemptref", "attempt_ref")
        if admission in admissions or attempt in attempts:
            raise CrossServiceChainReviewError("per-hop admission or attempt was reused")
        admissions.add(admission)
        attempts.add(attempt)
        if (
            observation["admission_scope_sha256"] != plan["scope_sha256"]
            or observation["admission_action_sha256"] != hop["action_sha256"]
            or observation["admission_credential_binding_sha256"]
            != hop["credential_binding_sha256"]
        ):
            raise CrossServiceChainReviewError("admission does not bind exact hop")
        _ref(observation["actor_ref"], "actorref", "actor_ref")
        for field in ("evidence_sha256", "custody_sha256"):
            _digest(observation[field], field)
        issued = _instant(observation["admission_issued_at"], "admission_issued_at")
        admitted_until = _instant(
            observation["admission_expires_at"], "admission_expires_at",
        )
        attempted = _instant(observation["attempted_at"], "attempted_at")
        if not (
            created <= issued <= attempted < admitted_until <= expires
            and prior_time < attempted <= as_of
        ):
            raise CrossServiceChainReviewError("admission or attempt timing is invalid")
        prior_time = attempted
        outcome = observation["declared_outcome"]
        if type(outcome) is not str or outcome not in {
            "declared_passed", "declared_blocked", "unknown",
        }:
            raise CrossServiceChainReviewError("declared outcome is invalid")
        prior_outcome = outcome
        cleanup_status = observation["cleanup_status"]
        if cleanup_status == "pending":
            if observation["cleanup_at"] is not None or (
                observation["cleanup_evidence_sha256"] is not None
            ):
                raise CrossServiceChainReviewError("pending cleanup has receipt")
        elif cleanup_status == "declared_complete":
            cleaned = _instant(observation["cleanup_at"], "cleanup_at")
            _digest(observation["cleanup_evidence_sha256"], "cleanup evidence")
            if not attempted <= cleaned <= as_of:
                raise CrossServiceChainReviewError("cleanup timing is invalid")
        else:
            raise CrossServiceChainReviewError("cleanup status is invalid")
    return raw


def build_cross_service_chain_review(
    plan: Any, observations: Any, *, as_of: str,
) -> dict[str, Any]:
    """Replay opaque per-hop assertions without proving a live transition."""

    now = _instant(as_of, "as_of")
    _canonical(plan)
    _canonical(observations)
    checked_plan = _plan(plan, now)
    checked_observations = _observations(observations, checked_plan, now)
    completed = sum(
        item["declared_outcome"] == "declared_passed"
        for item in checked_observations
    )
    if not checked_observations:
        terminal = "not_started"
    elif checked_observations[-1]["declared_outcome"] != "declared_passed":
        terminal = "declared_stopped"
    elif len(checked_observations) == len(checked_plan["hops"]):
        terminal = "declared_complete_pending_independent_review"
    else:
        terminal = "declared_partial"
    credential_refs = [
        hop["credential_ref"] for hop in checked_plan["hops"]
        if hop["credential_ref"] is not None
    ]
    body = {
        "schema_version": 1,
        "tenant_ref": checked_plan["tenant_ref"],
        "mission_ref": checked_plan["mission_ref"],
        "scope_sha256": checked_plan["scope_sha256"],
        "chain_ref": checked_plan["chain_ref"],
        "plan_sha256": _sha(checked_plan),
        "observations_sha256": _sha(checked_observations),
        "as_of": as_of,
        "planned_hop_count": len(checked_plan["hops"]),
        "observed_hop_count": len(checked_observations),
        "declared_passed_hop_count": completed,
        "declared_terminal_state": terminal,
        "declared_end_surface_ref": (
            checked_plan["hops"][-1]["to_surface_ref"]
            if terminal == "declared_complete_pending_independent_review" else None
        ),
        "planned_credential_reuse_count": len(credential_refs) - len(set(credential_refs)),
        "cleanup_due_hop_refs": [
            item["hop_ref"] for item in checked_observations
            if item["cleanup_status"] != "declared_complete"
        ],
        "plan_authority_authenticated": False,
        "per_hop_admission_authenticated": False,
        "credential_custody_verified": False,
        "transition_proof_verified": False,
        "cleanup_verified": False,
        "source_provenance": "caller_asserted_not_authenticated",
        "review_status": "independent_review_required",
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        **body,
        "review_id": "CSR-" + digest[:32].upper(),
        "review_sha256": "sha256:" + digest,
    }


def verify_cross_service_chain_review(
    plan: Any, observations: Any, *, as_of: str, result: Any,
) -> dict[str, str]:
    """Reproduce a supplied review without authenticating its evidence."""

    expected = build_cross_service_chain_review(plan, observations, as_of=as_of)
    if _canonical(result) != _canonical(expected):
        raise CrossServiceChainReviewError("cross-service review does not reproduce")
    return {
        "status": "valid", "review_id": expected["review_id"],
        "review_sha256": expected["review_sha256"], "qualification_effect": "none",
    }
