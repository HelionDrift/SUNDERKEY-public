"""Signed, historical reviewer statements for offline escalation proposals."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sunderkey.expert_review import ReviewerRole
from sunderkey.human_escalation_routing import (
    HumanReviewRoutingPlan,
    _time,
    plan_human_review,
)

DOMAIN = "sunderkey.human-review-statement.v1"
SIGNATURE_DOMAIN = "sunderkey.human-review-statement.signature.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
KEY_ID_RE = re.compile(r"HRK-[0-9A-F]{32}\Z")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
DISPOSITIONS = frozenset({"supports", "challenges", "insufficient_evidence"})
NO_EFFECTS = {
    "admission": "none",
    "assignment": "none",
    "authority": "none",
    "notification": "none",
    "qualification": "none",
    "review_approval": "none",
    "target_interaction": "none",
}


class HumanReviewStatementError(ValueError):
    """The statement, source proposal, pinned key, or signature is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HumanReviewStatementError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise HumanReviewStatementError("pinned Ed25519 public key must be 32 bytes")
    return "HRK-" + hashlib.sha256(public_key).hexdigest()[:32].upper()


def _replayed_plan(plan: HumanReviewRoutingPlan) -> HumanReviewRoutingPlan:
    if type(plan) is not HumanReviewRoutingPlan:
        raise HumanReviewStatementError("routing plan must be the exact reference type")
    try:
        replayed = plan_human_review(
            tenant_id=plan.tenant_id,
            planned_at=plan.planned_at,
            cases=plan.cases,
            roster=plan.roster,
        )
        if replayed.to_dict() != plan.to_dict():
            raise HumanReviewStatementError("routing plan differs from source replay")
    except (TypeError, ValueError, AttributeError) as exc:
        raise HumanReviewStatementError("routing plan failed source replay") from exc
    return replayed


def build_human_review_statement(
    plan: HumanReviewRoutingPlan,
    *,
    case_id: str,
    role: ReviewerRole | str,
    reviewer_id: str,
    disposition: str,
    rationale_sha256: str,
    reviewed_at: str,
    pinned_public_key: bytes,
) -> dict[str, Any]:
    """Build an unsigned opinion bound to one proposed reviewer slot."""

    plan = _replayed_plan(plan)
    key_id = _key_id(pinned_public_key)
    try:
        role = ReviewerRole(role)
    except (TypeError, ValueError) as exc:
        raise HumanReviewStatementError("reviewer role is invalid") from exc
    if type(disposition) is not str or disposition not in DISPOSITIONS:
        raise HumanReviewStatementError("disposition is invalid")
    if type(rationale_sha256) is not str or SHA256_RE.fullmatch(rationale_sha256) is None:
        raise HumanReviewStatementError("rationale digest is invalid")
    if type(reviewed_at) is not str or TIME_RE.fullmatch(reviewed_at) is None:
        raise HumanReviewStatementError("reviewed_at must be canonical UTC seconds")
    try:
        reviewed_time = _time(reviewed_at, "reviewed_at")
        planned_time = _time(plan.planned_at, "planned_at")
    except ValueError as exc:
        raise HumanReviewStatementError("review time is invalid") from exc
    cases = [item for item in plan.cases if item.case_id == case_id]
    reviewers = [item for item in plan.roster if item.reviewer_id == reviewer_id]
    slots = [
        item for item in plan.slots
        if item.case_id == case_id and item.role is role
    ]
    if (
        len(cases) != 1
        or len(reviewers) != 1
        or len(slots) != 1
        or slots[0].disposition != "proposed"
        or slots[0].reviewer_id != reviewer_id
    ):
        raise HumanReviewStatementError("reviewer was not proposed for this exact slot")
    case, reviewer = cases[0], reviewers[0]
    try:
        if not (
            planned_time <= reviewed_time < _time(case.response_due_at, "response_due_at")
            and _time(reviewer.available_from, "available_from") <= reviewed_time
            < _time(reviewer.available_until, "available_until")
        ):
            raise HumanReviewStatementError("review time is outside the proposal window")
    except ValueError as exc:
        raise HumanReviewStatementError("review time is invalid") from exc
    body = {
        "schema_version": 1,
        "tenant_id": plan.tenant_id,
        "routing_plan_sha256": plan.plan_sha256,
        "case_id": case.case_id,
        "case_sha256": case.case_sha256,
        "evidence_sha256": case.evidence_sha256,
        "scope_binding_sha256": case.scope_binding_sha256,
        "role": role.value,
        "reviewer_id": reviewer.reviewer_id,
        "roster_entry_sha256": reviewer.roster_entry_sha256,
        "disposition": disposition,
        "rationale_sha256": rationale_sha256,
        "reviewed_at": reviewed_at,
        "signer_key_id": key_id,
        "effects": dict(NO_EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        "statement_id": "HRS-" + digest[:32].upper(),
        "statement_sha256": "sha256:" + digest,
        **body,
    }


def human_review_statement_signing_bytes(unsigned: dict[str, Any]) -> bytes:
    """Return exact domain-separated bytes for an external signer."""

    expected_fields = {
        "statement_id", "statement_sha256", "schema_version", "tenant_id",
        "routing_plan_sha256", "case_id", "case_sha256", "evidence_sha256",
        "scope_binding_sha256", "role", "reviewer_id", "roster_entry_sha256",
        "disposition", "rationale_sha256", "reviewed_at", "signer_key_id", "effects",
    }
    if type(unsigned) is not dict or set(unsigned) != expected_fields:
        raise HumanReviewStatementError("unsigned statement fields are invalid")
    body = {key: value for key, value in unsigned.items() if key not in {
        "statement_id", "statement_sha256"
    }}
    if (
        type(body["schema_version"]) is not int
        or body["schema_version"] != 1
        or type(body["effects"]) is not dict
        or body["effects"] != NO_EFFECTS
        or type(body["disposition"]) is not str
        or body["disposition"] not in DISPOSITIONS
        or type(body["role"]) is not str
        or body["role"] not in {role.value for role in ReviewerRole}
        or type(body["reviewed_at"]) is not str
        or TIME_RE.fullmatch(body["reviewed_at"]) is None
        or type(body["signer_key_id"]) is not str
        or KEY_ID_RE.fullmatch(body["signer_key_id"]) is None
    ):
        raise HumanReviewStatementError("unsigned statement semantics are invalid")
    for key in ("tenant_id", "case_id", "reviewer_id"):
        if type(body[key]) is not str or IDENTIFIER_RE.fullmatch(body[key]) is None:
            raise HumanReviewStatementError("unsigned statement identifier is invalid")
    for key in (
        "routing_plan_sha256", "case_sha256", "evidence_sha256",
        "scope_binding_sha256", "roster_entry_sha256", "rationale_sha256",
    ):
        if type(body[key]) is not str or SHA256_RE.fullmatch(body[key]) is None:
            raise HumanReviewStatementError("unsigned statement digest is invalid")
    try:
        _time(body["reviewed_at"], "reviewed_at")
    except ValueError as exc:
        raise HumanReviewStatementError("unsigned statement time is invalid") from exc
    try:
        digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
        if (
            unsigned["statement_id"] != "HRS-" + digest[:32].upper()
            or unsigned["statement_sha256"] != "sha256:" + digest
        ):
            raise HumanReviewStatementError("statement content address is invalid")
        return SIGNATURE_DOMAIN.encode() + b"\0" + _canonical(unsigned)
    except (TypeError, ValueError) as exc:
        raise HumanReviewStatementError("statement is not canonical JSON") from exc


def verify_human_review_statement(
    raw: Any,
    plan: HumanReviewRoutingPlan,
    *,
    pinned_public_key: bytes,
) -> dict[str, Any]:
    """Check a signed historical opinion against exact routing-plan sources."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeError as exc:
            raise HumanReviewStatementError("statement is not UTF-8") from exc
    if isinstance(raw, str):
        try:
            raw = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (TypeError, ValueError) as exc:
            raise HumanReviewStatementError("statement is not valid JSON") from exc
    if type(raw) is not dict or set(raw) != {
        "statement_id", "statement_sha256", "schema_version", "tenant_id",
        "routing_plan_sha256", "case_id", "case_sha256", "evidence_sha256",
        "scope_binding_sha256", "role", "reviewer_id", "roster_entry_sha256",
        "disposition", "rationale_sha256", "reviewed_at", "signer_key_id",
        "effects", "signature_b64url",
    }:
        raise HumanReviewStatementError("signed statement fields are invalid")
    signature_text = raw["signature_b64url"]
    if type(signature_text) is not str or SIGNATURE_RE.fullmatch(signature_text) is None:
        raise HumanReviewStatementError("signature encoding is invalid")
    expected = build_human_review_statement(
        plan,
        case_id=raw["case_id"],
        role=raw["role"],
        reviewer_id=raw["reviewer_id"],
        disposition=raw["disposition"],
        rationale_sha256=raw["rationale_sha256"],
        reviewed_at=raw["reviewed_at"],
        pinned_public_key=pinned_public_key,
    )
    unsigned = {key: value for key, value in raw.items() if key != "signature_b64url"}
    try:
        if _canonical(unsigned) != _canonical(expected):
            raise HumanReviewStatementError("statement differs from exact source replay")
        signature = base64.urlsafe_b64decode(signature_text + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
            != signature_text
        ):
            raise HumanReviewStatementError("signature is not canonical")
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(
            signature, human_review_statement_signing_bytes(expected)
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise HumanReviewStatementError("statement signature or content is invalid") from exc
    return {**expected, "signature_b64url": signature_text}
