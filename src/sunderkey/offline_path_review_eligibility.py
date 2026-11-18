"""Fail-closed, verifier-conditional eligibility for review of a supplied path."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Protocol

DOMAIN = "sunderkey.offline-path-review-eligibility.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_EFFECTS = dict.fromkeys(
    ("authority", "target", "network", "credential", "execution", "routing",
     "qualification", "publication", "deployment", "assignment"),
    "none",
)


class PathReviewEligibilityError(ValueError):
    """The path, injected verification, or replay boundary failed."""


class PathReviewVerifier(Protocol):
    """Caller-supplied trusted verification port, not implemented here."""

    def verify_time(
        self, candidate_body_sha256: str, evaluated_at: str
    ) -> dict[str, Any]: ...

    def verify_observation(
        self, observation: dict[str, Any], candidate_body_sha256: str, evaluated_at: str
    ) -> dict[str, Any]: ...

    def verify_lineage(
        self, observations: tuple[dict[str, Any], ...], candidate_body_sha256: str,
        evaluated_at: str,
    ) -> dict[str, Any]: ...

    def verify_review(
        self, review: dict[str, Any], candidate_body_sha256: str, evaluated_at: str
    ) -> dict[str, Any]: ...


def _native(value: Any, *, depth: int = 0) -> None:
    if depth > 20:
        raise PathReviewEligibilityError("input nesting limit exceeded")
    if type(value) is dict:
        if len(value) > 128 or any(type(key) is not str for key in value):
            raise PathReviewEligibilityError("invalid native mapping")
        for key, child in value.items():
            _native(key, depth=depth + 1)
            _native(child, depth=depth + 1)
    elif type(value) is list:
        if len(value) > 128:
            raise PathReviewEligibilityError("input collection limit exceeded")
        for child in value:
            _native(child, depth=depth + 1)
    elif type(value) is str:
        if len(value) > 1024:
            raise PathReviewEligibilityError("input text limit exceeded")
    elif value is not None and type(value) not in (bool, int):
        raise PathReviewEligibilityError("native JSON values required")


def _copy(value: Any) -> Any:
    _native(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PathReviewEligibilityError("invalid JSON input") from exc
    if len(raw.encode("utf-8")) > 131_072:
        raise PathReviewEligibilityError("input byte limit exceeded")
    return json.loads(raw)


def _sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fields(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != expected:
        raise PathReviewEligibilityError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise PathReviewEligibilityError(f"{label} is invalid")


def _digest(value: Any, label: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise PathReviewEligibilityError(f"{label} is invalid")


def _instant(value: Any, label: str) -> datetime:
    if type(value) is not str or _TIME.fullmatch(value) is None:
        raise PathReviewEligibilityError(f"{label} is invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PathReviewEligibilityError(f"{label} is invalid") from exc


def _bound_receipt(value: Any, expected: dict[str, Any], label: str) -> dict[str, Any]:
    receipt = _copy(value)
    _fields(receipt, set(expected) | {"verifier_id"}, label)
    _identifier(receipt["verifier_id"], f"{label} verifier")
    for key, wanted in expected.items():
        if type(receipt[key]) is not type(wanted) or receipt[key] != wanted:
            raise PathReviewEligibilityError(f"{label} {key} binding failed")
    return receipt


def _validate_candidate(candidate: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    _fields(candidate, {"schema_version", "tenant_id", "context_sha256", "scope_sha256",
                        "evaluated_at", "path", "observations", "reviews"}, "candidate")
    if type(candidate["schema_version"]) is not int or candidate["schema_version"] != 1:
        raise PathReviewEligibilityError("candidate schema is invalid")
    _identifier(candidate["tenant_id"], "tenant")
    _digest(candidate["context_sha256"], "context")
    _digest(candidate["scope_sha256"], "scope")
    now = _instant(candidate["evaluated_at"], "evaluation time")

    path = candidate["path"]
    _fields(path, {"nodes", "node_proofs", "edges"}, "path")
    nodes = path["nodes"]
    node_proofs = path["node_proofs"]
    edges = path["edges"]
    if type(nodes) is not list or not 2 <= len(nodes) <= 8:
        raise PathReviewEligibilityError("path nodes must be distinct and bounded")
    for node in nodes:
        _identifier(node, "path node")
    if len(nodes) != len(set(nodes)):
        raise PathReviewEligibilityError("path nodes must be distinct and bounded")
    if type(node_proofs) is not list or len(node_proofs) != len(nodes):
        raise PathReviewEligibilityError("every path node needs a proof")
    if type(edges) is not list or len(edges) != len(nodes) - 1:
        raise PathReviewEligibilityError("every path edge needs a proof")

    claims: dict[str, tuple[str, str, str | None]] = {}
    for position, binding in enumerate(node_proofs):
        _fields(binding, {"node_id", "proof_id"}, "node proof")
        if binding["node_id"] != nodes[position]:
            raise PathReviewEligibilityError("node proof order or identity differs")
        _identifier(binding["proof_id"], "node proof ID")
        if binding["proof_id"] in claims:
            raise PathReviewEligibilityError("proof ID reused")
        claims[binding["proof_id"]] = ("node", nodes[position], None)
    for position, binding in enumerate(edges):
        _fields(binding, {"from_id", "to_id", "proof_id"}, "edge proof")
        if binding["from_id"] != nodes[position] or binding["to_id"] != nodes[position + 1]:
            raise PathReviewEligibilityError("edge does not prove the contiguous path")
        _identifier(binding["proof_id"], "edge proof ID")
        if binding["proof_id"] in claims:
            raise PathReviewEligibilityError("proof ID reused")
        claims[binding["proof_id"]] = ("edge", nodes[position], nodes[position + 1])

    observations = candidate["observations"]
    if type(observations) is not list or not 3 <= len(observations) <= 32:
        raise PathReviewEligibilityError("observation count is invalid")
    seen: set[str] = set()
    producers: set[str] = set()
    source_hashes: set[str] = set()
    for obs in observations:
        _fields(obs, {"proof_id", "claim_kind", "subject_id", "object_id", "disposition",
                      "evidence_class", "source_sha256", "lineage_sha256s", "producer_id",
                      "tenant_id", "context_sha256", "scope_sha256", "observed_at",
                      "expires_at"}, "observation")
        proof_id = obs["proof_id"]
        _identifier(proof_id, "observation proof ID")
        if proof_id in seen:
            raise PathReviewEligibilityError("duplicate observation proof")
        seen.add(proof_id)
        if obs["evidence_class"] != "independently_authenticated_observation":
            raise PathReviewEligibilityError("offline or operator evidence cannot enter this gate")
        if obs["disposition"] != "supports":
            raise PathReviewEligibilityError("contrary or uncertain path observation")
        if (obs["claim_kind"], obs["subject_id"], obs["object_id"]) != claims.get(proof_id):
            raise PathReviewEligibilityError("observation does not prove its exact path claim")
        if (obs["tenant_id"] != candidate["tenant_id"] or
                obs["context_sha256"] != candidate["context_sha256"] or
                obs["scope_sha256"] != candidate["scope_sha256"]):
            raise PathReviewEligibilityError("observation tenant, context, or scope differs")
        observed_at = _instant(obs["observed_at"], "observation time")
        expires_at = _instant(obs["expires_at"], "expiry time")
        if observed_at > now or expires_at <= now:
            raise PathReviewEligibilityError("observation is future-dated or stale")
        _identifier(obs["producer_id"], "producer")
        producers.add(obs["producer_id"])
        _digest(obs["source_sha256"], "source")
        source_hashes.add(obs["source_sha256"])
        lineage = obs["lineage_sha256s"]
        if (type(lineage) is not list or not 1 <= len(lineage) <= 16 or
                lineage != sorted(set(lineage)) or obs["source_sha256"] not in lineage):
            raise PathReviewEligibilityError("lineage is missing, unordered, or incomplete")
        for item in lineage:
            _digest(item, "lineage source")
            source_hashes.add(item)
    if seen != set(claims):
        raise PathReviewEligibilityError("path has a missing or unbound observation")

    reviews = candidate["reviews"]
    if type(reviews) is not list or len(reviews) != 2:
        raise PathReviewEligibilityError("independent Control and Assurance reviews required")
    body = {key: value for key, value in candidate.items() if key != "reviews"}
    body_sha = _sha({"domain": DOMAIN + ".candidate-body", "body": body})
    roles: set[str] = set()
    reviewer_ids: set[str] = set()
    review_ids: set[str] = set()
    for review in reviews:
        _fields(review, {"review_id", "role", "reviewer_id", "decision",
                         "candidate_body_sha256", "reviewed_at"}, "review")
        for key in ("review_id", "reviewer_id"):
            _identifier(review[key], key)
        if review["role"] not in ("control", "assurance") or review["decision"] != "accept":
            raise PathReviewEligibilityError("required independent reviews did not accept")
        if review["candidate_body_sha256"] != body_sha:
            raise PathReviewEligibilityError("review does not bind the exact path body")
        reviewed_at = _instant(review["reviewed_at"], "review time")
        if reviewed_at > now or any(
            reviewed_at < _instant(obs["observed_at"], "observation time")
            for obs in observations
        ):
            raise PathReviewEligibilityError("review time does not follow observations")
        roles.add(review["role"])
        reviewer_ids.add(review["reviewer_id"])
        review_ids.add(review["review_id"])
    if (roles != {"control", "assurance"} or len(reviewer_ids) != 2 or
            len(review_ids) != 2 or reviewer_ids & producers):
        raise PathReviewEligibilityError("review roles or identities are not independent")
    return body_sha, tuple(sorted(source_hashes))


def evaluate_path_review_eligibility(
    candidate: dict[str, Any], verifier: PathReviewVerifier
) -> dict[str, Any]:
    """Return only conditional review eligibility after exact injected checks."""
    current = _copy(candidate)
    body_sha, source_hashes = _validate_candidate(current)
    try:
        time_result = verifier.verify_time(body_sha, current["evaluated_at"])
    except AttributeError as exc:
        raise PathReviewEligibilityError("trusted time verifier is required") from exc
    time_receipt = _bound_receipt(time_result, {
        "candidate_body_sha256": body_sha,
        "evaluated_at": current["evaluated_at"],
        "decision": "within_trusted_current_window",
    }, "time receipt")
    observation_receipts = []
    for obs in current["observations"]:
        receipt = verifier.verify_observation(_copy(obs), body_sha, current["evaluated_at"])
        observation_receipts.append(_bound_receipt(receipt, {
            "proof_id": obs["proof_id"],
            "source_sha256": obs["source_sha256"],
            "candidate_body_sha256": body_sha,
            "verification_kind": "independently_authenticated_observation",
            "accepted": True,
        }, "observation receipt"))
    lineage = verifier.verify_lineage(
        tuple(_copy(obs) for obs in current["observations"]), body_sha,
        current["evaluated_at"],
    )
    lineage_receipt = _bound_receipt(lineage, {
        "candidate_body_sha256": body_sha,
        "source_sha256s": list(source_hashes),
        "complete": True,
        "conflict_free": True,
    }, "lineage receipt")
    review_receipts = []
    for review in current["reviews"]:
        receipt = verifier.verify_review(_copy(review), body_sha, current["evaluated_at"])
        review_receipts.append(_bound_receipt(receipt, {
            "review_id": review["review_id"],
            "reviewer_id": review["reviewer_id"],
            "role": review["role"],
            "candidate_body_sha256": body_sha,
            "decision": "accept",
            "accepted": True,
        }, "review receipt"))

    packet = {
        "schema_version": 1,
        "candidate_sha256": _sha({"domain": DOMAIN + ".candidate", "candidate": current}),
        "candidate_body_sha256": body_sha,
        "eligibility": "conditional_review_eligible_under_injected_verifier",
        "verifier_trust": "externally_assumed_not_established_by_this_module",
        "world_edge_promotion": "none",
        "finding_eligibility": "none",
        "operational_effects": dict(_EFFECTS),
        "verification_receipts": {
            "time": time_receipt,
            "observations": observation_receipts,
            "lineage": lineage_receipt,
            "reviews": review_receipts,
        },
    }
    packet["packet_sha256"] = _sha({"domain": DOMAIN + ".packet", "packet": packet})
    return packet


def verify_path_review_eligibility(
    packet: dict[str, Any], candidate: dict[str, Any], verifier: PathReviewVerifier
) -> dict[str, Any]:
    """Freshly replay a packet against separate original input and verifier."""
    supplied = _copy(packet)
    expected = evaluate_path_review_eligibility(candidate, verifier)
    if supplied != expected:
        raise PathReviewEligibilityError("packet does not replay from current sources")
    return expected


__all__ = [
    "PathReviewEligibilityError",
    "PathReviewVerifier",
    "evaluate_path_review_eligibility",
    "verify_path_review_eligibility",
]
