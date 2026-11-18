"""Local signature checks for non-authoritative task work-product review."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .coverage_scheduler import CoverageSchedule, CoverageSchedulerError

CANDIDATE_DOMAIN = "sunderkey.offline-task-work-product.v1"
ATTESTATION_DOMAIN = "sunderkey.offline-task-review-attestation.v1"
PACKET_DOMAIN = "sunderkey.offline-task-review-packet.v1"
ROLES = frozenset({"independent_control", "independent_assurance"})
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
NO_EFFECTS = {
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "qualification": "none",
    "source_authentication": "none",
}


class OfflineTaskReviewReceiptError(ValueError):
    """Raised when an offline work-product or review binding is invalid."""


@dataclass(frozen=True, slots=True)
class ReviewerKeyBinding:
    key_id: str
    reviewer_id: str
    role: str
    public_key: Ed25519PublicKey

    def __post_init__(self) -> None:
        _binding(self)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        raise OfflineTaskReviewReceiptError(f"{label} is invalid")
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise OfflineTaskReviewReceiptError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> str:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise OfflineTaskReviewReceiptError(f"{label} is invalid")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineTaskReviewReceiptError(f"{label} is invalid") from exc
    return value


def _native_keys(value: Any) -> bool:
    return isinstance(value, Mapping) and all(type(key) is str for key in value)


def _choice(value: Any, choices: frozenset[str], label: str) -> str:
    if type(value) is not str or value not in choices:
        raise OfflineTaskReviewReceiptError(f"{label} is invalid")
    return value


def _binding(value: Any) -> tuple[str, str, str, Ed25519PublicKey]:
    if type(value) is not ReviewerKeyBinding:
        raise OfflineTaskReviewReceiptError("reviewer key binding is invalid")
    key_id, reviewer_id, role, public_key = (
        value.key_id,
        value.reviewer_id,
        value.role,
        value.public_key,
    )
    _identifier(key_id, "key_id")
    _identifier(reviewer_id, "reviewer_id")
    _choice(role, ROLES, "review role")
    if not isinstance(public_key, Ed25519PublicKey):
        raise OfflineTaskReviewReceiptError("Ed25519 public key is required")
    return key_id, reviewer_id, role, public_key


def _attestation(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "work_product_sha256",
        "reviewer_id",
        "role",
        "key_id",
        "reviewed_at",
        "decision",
        "signature_base64",
    }
    if not _native_keys(value) or set(value) != fields:
        raise OfflineTaskReviewReceiptError("review attestation fields are invalid")
    item = dict(value)
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise OfflineTaskReviewReceiptError("review attestation version is invalid")
    _hash(item["work_product_sha256"], "work_product_sha256")
    _identifier(item["reviewer_id"], "reviewer_id")
    _identifier(item["key_id"], "key_id")
    _choice(item["role"], ROLES, "review role")
    _choice(item["decision"], frozenset({"accepted", "rejected"}), "review decision")
    _time(item["reviewed_at"], "reviewed_at")
    if type(item["signature_base64"]) is not str or len(item["signature_base64"]) != 88:
        raise OfflineTaskReviewReceiptError("review signature fields are invalid")
    return item


def _task(schedule: CoverageSchedule, task_id: str):
    _identifier(task_id, "task_id")
    if not isinstance(schedule, CoverageSchedule):
        raise OfflineTaskReviewReceiptError("typed schedule is required")
    _identifier(schedule.schedule_id, "schedule_id")
    for field in ("schedule_sha256", "scope_sha256", "world_snapshot_sha256"):
        _hash(getattr(schedule, field), field)
    _time(schedule.limits.as_of, "schedule as_of")
    for item in schedule.tasks:
        for field in (
            "task_id",
            "task_key",
            "required_specialist_profile_id",
            "required_commander_id",
        ):
            _identifier(getattr(item, field), field)
        for field in ("task_sha256", "scope_sha256", "world_snapshot_sha256"):
            _hash(getattr(item, field), field)
    try:
        checked = CoverageSchedule.from_dict(schedule.to_dict())
    except CoverageSchedulerError as exc:
        raise OfflineTaskReviewReceiptError("schedule identity is invalid") from exc
    task = next((item for item in checked.tasks if item.task_id == task_id), None)
    if task is None:
        raise OfflineTaskReviewReceiptError("task is absent from schedule")
    return checked, task


def build_offline_task_work_product(
    *,
    schedule: CoverageSchedule,
    task_id: str,
    work_result_sha256: str,
    evidence_sha256s: Sequence[str],
    completed_at: str,
) -> dict[str, Any]:
    """Bind a caller-supplied work product to one immutable planned task."""

    checked, task = _task(schedule, task_id)
    _hash(work_result_sha256, "work_result_sha256")
    _time(completed_at, "completed_at")
    if completed_at < checked.limits.as_of:
        raise OfflineTaskReviewReceiptError("work product precedes its schedule")
    if not isinstance(evidence_sha256s, (tuple, list)) or not 1 <= len(evidence_sha256s) <= 64:
        raise OfflineTaskReviewReceiptError("work product evidence count is invalid")
    evidence = [_hash(item, "evidence_sha256") for item in evidence_sha256s]
    if len(set(evidence)) != len(evidence):
        raise OfflineTaskReviewReceiptError("work product evidence is duplicated")
    body = {
        "schema_version": 1,
        "schedule_sha256": checked.schedule_sha256,
        "task_id": task.task_id,
        "task_sha256": task.task_sha256,
        "task_key": task.task_key,
        "scope_sha256": task.scope_sha256,
        "world_snapshot_sha256": task.world_snapshot_sha256,
        "specialist_profile_id": task.required_specialist_profile_id,
        "commander_id": task.required_commander_id,
        "work_result_sha256": work_result_sha256,
        "evidence_sha256s": sorted(evidence),
        "completed_at": completed_at,
        "source_assurance": "caller_supplied_digests_only",
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "work_product_sha256": _digest({"domain": CANDIDATE_DOMAIN, "body": body}),
    }


def verify_offline_task_work_product(
    schedule: CoverageSchedule, candidate: Mapping[str, Any]
) -> dict[str, Any]:
    if not _native_keys(candidate):
        raise OfflineTaskReviewReceiptError("work product document is invalid")
    try:
        expected = build_offline_task_work_product(
            schedule=schedule,
            task_id=candidate["task_id"],
            work_result_sha256=candidate["work_result_sha256"],
            evidence_sha256s=candidate["evidence_sha256s"],
            completed_at=candidate["completed_at"],
        )
        if _canonical(dict(candidate)) != _canonical(expected):
            raise OfflineTaskReviewReceiptError("work product does not match schedule")
        return expected
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, OfflineTaskReviewReceiptError):
            raise
        raise OfflineTaskReviewReceiptError("work product document is invalid") from exc


def sign_offline_task_review_attestation(
    *,
    schedule: CoverageSchedule,
    candidate: Mapping[str, Any],
    reviewer_id: str,
    role: str,
    key_id: str,
    reviewed_at: str,
    decision: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign only an offline candidate digest, never an authority grant."""

    checked = verify_offline_task_work_product(schedule, candidate)
    _identifier(reviewer_id, "reviewer_id")
    _identifier(key_id, "key_id")
    _time(reviewed_at, "reviewed_at")
    _choice(role, ROLES, "review role")
    _choice(decision, frozenset({"accepted", "rejected"}), "review decision")
    if reviewed_at < checked["completed_at"]:
        raise OfflineTaskReviewReceiptError("review precedes work product")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise OfflineTaskReviewReceiptError("Ed25519 private key is required")
    body = {
        "schema_version": 1,
        "work_product_sha256": checked["work_product_sha256"],
        "reviewer_id": reviewer_id,
        "role": role,
        "key_id": key_id,
        "reviewed_at": reviewed_at,
        "decision": decision,
    }
    signature = private_key.sign(
        _canonical({"domain": ATTESTATION_DOMAIN, "body": body}).encode("ascii")
    )
    return {**body, "signature_base64": base64.b64encode(signature).decode("ascii")}


def build_offline_task_review_packet(
    *,
    schedule: CoverageSchedule,
    candidate: Mapping[str, Any],
    attestations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    checked = verify_offline_task_work_product(schedule, candidate)
    if not isinstance(attestations, (tuple, list)) or len(attestations) != 2:
        raise OfflineTaskReviewReceiptError("exactly two review attestations are required")
    items = [_attestation(item) for item in attestations]
    items.sort(key=lambda item: item["role"])
    body = {
        "schema_version": 1,
        "work_product": checked,
        "attestations": items,
        "review_state": (
            "locally_accepted"
            if all(item.get("decision") == "accepted" for item in items)
            else "locally_declined"
        ),
        "key_binding_assurance": "caller_provided",
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "packet_sha256": _digest({"domain": PACKET_DOMAIN, "body": body})}


def verify_offline_task_review_packet(
    *,
    schedule: CoverageSchedule,
    packet: Mapping[str, Any],
    reviewer_keys: Mapping[str, ReviewerKeyBinding],
) -> dict[str, Any]:
    """Verify local signatures under caller-provided keys, not live identity."""

    if not _native_keys(packet) or not _native_keys(reviewer_keys):
        raise OfflineTaskReviewReceiptError("review packet or key bindings are invalid")
    try:
        expected = build_offline_task_review_packet(
            schedule=schedule,
            candidate=packet["work_product"],
            attestations=packet["attestations"],
        )
        if _canonical(dict(packet)) != _canonical(expected):
            raise OfflineTaskReviewReceiptError("review packet content identity is invalid")
        candidate = expected["work_product"]
        items = expected["attestations"]
        if {item["role"] for item in items} != ROLES:
            raise OfflineTaskReviewReceiptError("independent review roles are incomplete")
        if len({item["reviewer_id"] for item in items}) != 2:
            raise OfflineTaskReviewReceiptError("reviewers are not distinct")
        if len({item["key_id"] for item in items}) != 2:
            raise OfflineTaskReviewReceiptError("review keys are not distinct")
        for item in items:
            key_id, reviewer_id, role, public_key = _binding(reviewer_keys.get(item["key_id"]))
            if (
                key_id != item["key_id"]
                or reviewer_id != item["reviewer_id"]
                or role != item["role"]
                or item["reviewer_id"]
                in {candidate["specialist_profile_id"], candidate["commander_id"]}
                or item["work_product_sha256"] != candidate["work_product_sha256"]
                or item["reviewed_at"] < candidate["completed_at"]
            ):
                raise OfflineTaskReviewReceiptError("review attestation binding is invalid")
            signature = base64.b64decode(item["signature_base64"], validate=True)
            if len(signature) != 64:
                raise OfflineTaskReviewReceiptError("review signature length is invalid")
            signed_body = {key: value for key, value in item.items() if key != "signature_base64"}
            public_key.verify(
                signature,
                _canonical({"domain": ATTESTATION_DOMAIN, "body": signed_body}).encode("ascii"),
            )
        return expected
    except (
        InvalidSignature,
        binascii.Error,
        KeyError,
        TypeError,
        ValueError,
        CoverageSchedulerError,
    ) as exc:
        if isinstance(exc, OfflineTaskReviewReceiptError):
            raise
        raise OfflineTaskReviewReceiptError(
            "review packet signature or binding is invalid"
        ) from exc


__all__ = [
    "OfflineTaskReviewReceiptError",
    "ReviewerKeyBinding",
    "build_offline_task_review_packet",
    "build_offline_task_work_product",
    "sign_offline_task_review_attestation",
    "verify_offline_task_review_packet",
    "verify_offline_task_work_product",
]
