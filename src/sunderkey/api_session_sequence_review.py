"""Offline, nonqualifying review of caller-declared API session sequences."""

from __future__ import annotations

import hashlib
import re
import uuid
from collections import defaultdict
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes
from .service_contract_extractor import ServiceContractEndpointBundle
from .traffic_derived_api_inventory import (
    MAX_OBSERVATIONS,
    SanitizedApiTrafficObservation,
    TrafficApiInventory,
    TrafficApiInventoryError,
    _verified_observation,
    verify_traffic_api_inventory_from_sources,
)

DOMAIN = "sunderkey.api-session-sequence-review.v1"
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SESSION_RE = re.compile(
    r"sessionref:uuidv4:([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\Z"
)
MAX_SESSIONS = 2000
MAX_REVIEW_JSON_BYTES = 8_000_000


class ApiSessionSequenceReviewError(ValueError):
    """The supplied sequence or its source replay failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value, max_bytes=MAX_REVIEW_JSON_BYTES)
    except JsonContractIntegrityError as exc:
        raise ApiSessionSequenceReviewError(
            "session sequence exceeds the closed JSON contract"
        ) from exc


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise ApiSessionSequenceReviewError(f"{label} must be a SHA-256 digest")
    return value


def _session_ref(value: Any) -> str:
    if type(value) is not str:
        raise ApiSessionSequenceReviewError("session_ref must be an opaque UUIDv4 reference")
    match = SESSION_RE.fullmatch(value)
    if match is None or str(uuid.UUID(match.group(1))) != match.group(1):
        raise ApiSessionSequenceReviewError("session_ref must be an opaque UUIDv4 reference")
    return value


def _source_claims(
    claims: tuple[dict[str, Any], ...],
    by_event: dict[str, SanitizedApiTrafficObservation],
) -> tuple[dict[str, Any], ...]:
    if type(claims) is not tuple or not 1 <= len(claims) <= MAX_OBSERVATIONS:
        raise ApiSessionSequenceReviewError("sequence claims exceed the hard limit or are empty")
    checked: list[dict[str, Any]] = []
    seen_events: set[str] = set()
    seen_positions: set[tuple[str, int]] = set()
    for raw in claims:
        if type(raw) is not dict or set(raw) != {
            "event_id", "observation_sha256", "session_ref", "position",
        } or any(type(key) is not str for key in raw):
            raise ApiSessionSequenceReviewError("sequence claim fields are invalid")
        event_id = raw["event_id"]
        if type(event_id) is not str or event_id not in by_event:
            raise ApiSessionSequenceReviewError("sequence claim names an unknown event")
        if event_id in seen_events:
            raise ApiSessionSequenceReviewError("event has more than one session binding")
        seen_events.add(event_id)
        digest = _digest(raw["observation_sha256"], "observation_sha256")
        if digest != by_event[event_id].observation_sha256:
            raise ApiSessionSequenceReviewError("sequence claim event digest differs from source")
        session_ref = _session_ref(raw["session_ref"])
        position = raw["position"]
        if type(position) is not int or not 0 <= position < MAX_OBSERVATIONS:
            raise ApiSessionSequenceReviewError("sequence position is invalid")
        key = (session_ref, position)
        if key in seen_positions:
            raise ApiSessionSequenceReviewError("session sequence position is repeated")
        seen_positions.add(key)
        checked.append({
            "event_id": event_id,
            "observation_sha256": digest,
            "session_ref": session_ref,
            "position": position,
        })
    if len({claim["session_ref"] for claim in checked}) > MAX_SESSIONS:
        raise ApiSessionSequenceReviewError("session count exceeds the hard limit")
    return tuple(sorted(checked, key=lambda item: (item["session_ref"], item["position"])))


def build_api_session_sequence_review(
    *,
    inventory: TrafficApiInventory,
    observations: tuple[SanitizedApiTrafficObservation, ...],
    claims: tuple[dict[str, Any], ...],
    redaction_review_sha256: str,
    contract_bundle: ServiceContractEndpointBundle | None = None,
) -> dict[str, Any]:
    """Summarize supplied session order without authenticating linkage or authorizing use."""

    _digest(redaction_review_sha256, "redaction_review_sha256")
    if type(observations) is not tuple or len(observations) > MAX_OBSERVATIONS:
        raise ApiSessionSequenceReviewError("observations exceed the hard limit")
    try:
        captured = tuple(_verified_observation(item) for item in observations)
        verified = verify_traffic_api_inventory_from_sources(
            inventory, observations=captured, contract_bundle=contract_bundle,
        )
    except TrafficApiInventoryError as exc:
        raise ApiSessionSequenceReviewError("traffic inventory source replay failed") from exc
    by_event: dict[str, SanitizedApiTrafficObservation] = {}
    for item in captured:
        prior = by_event.get(item.event_id)
        if prior is not None and prior.observation_sha256 != item.observation_sha256:
            raise ApiSessionSequenceReviewError("conflicting event identities")
        by_event[item.event_id] = item
    checked = _source_claims(claims, by_event)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim in checked:
        grouped[claim["session_ref"]].append(claim)

    sessions: list[dict[str, Any]] = []
    edge_count = role_changes = origin_changes = timestamp_ties = 0
    for session_ref, entries in sorted(grouped.items()):
        if [item["position"] for item in entries] != list(range(len(entries))):
            raise ApiSessionSequenceReviewError("session positions must be contiguous from zero")
        session_edges: list[dict[str, Any]] = []
        for left, right in zip(entries, entries[1:]):
            earlier = by_event[left["event_id"]]
            later = by_event[right["event_id"]]
            if later.observed_at < earlier.observed_at:
                raise ApiSessionSequenceReviewError("sequence order contradicts observation times")
            same_second = earlier.observed_at == later.observed_at
            role_change = earlier.role_ref != later.role_ref
            origin_change = earlier.origin != later.origin
            timestamp_ties += int(same_second)
            role_changes += int(role_change)
            origin_changes += int(origin_change)
            session_edges.append({
                "from_observation_sha256": earlier.observation_sha256,
                "to_observation_sha256": later.observation_sha256,
                "same_second_order_uncertain": same_second,
                "role_label_changed": role_change,
                "origin_changed": origin_change,
            })
        edge_count += len(session_edges)
        sessions.append({
            "session_ref": session_ref,
            "event_observation_sha256": [item["observation_sha256"] for item in entries],
            "edges": session_edges,
        })

    body = {
        "schema_version": 1,
        "tenant_id": verified.tenant_id,
        "context_id": verified.context_id,
        "context_sha256": verified.context_sha256,
        "scope_id": verified.scope_id,
        "scope_sha256": verified.scope_sha256,
        "inventory_sha256": verified.inventory_sha256,
        "claims_sha256": _sha(list(checked)),
        "redaction_review_sha256": redaction_review_sha256,
        "observation_count": len(by_event),
        "bound_event_count": len(checked),
        "unbound_event_count": len(by_event) - len(checked),
        "session_count": len(sessions),
        "edge_count": edge_count,
        "role_label_change_edge_count": role_changes,
        "cross_origin_edge_count": origin_changes,
        "same_second_order_uncertain_edge_count": timestamp_ties,
        "sessions": sessions,
        "ordering_basis": "caller_asserted_session_sequence",
        "session_linkage_authenticated": False,
        "redaction_assurance_verified": False,
        "authorization_effect": "none",
        "release_gate_effect": "none",
        "qualification_effect": "none",
        "network_call_performed": False,
        "review_status": "independent_review_required",
    }
    digest = _sha({"domain": DOMAIN, "body": body})
    return {**body, "review_id": "ASSR-" + digest[7:39].upper(), "review_sha256": digest}


def verify_api_session_sequence_review_from_sources(
    review: dict[str, Any],
    *,
    inventory: TrafficApiInventory,
    observations: tuple[SanitizedApiTrafficObservation, ...],
    claims: tuple[dict[str, Any], ...],
    contract_bundle: ServiceContractEndpointBundle | None = None,
) -> dict[str, Any]:
    """Rebuild the review from exact sources, rejecting any changed output."""

    if type(review) is not dict:
        raise ApiSessionSequenceReviewError("review must be an exact object")
    _digest(review.get("redaction_review_sha256"), "redaction_review_sha256")
    expected = build_api_session_sequence_review(
        inventory=inventory,
        observations=observations,
        claims=claims,
        redaction_review_sha256=review["redaction_review_sha256"],
        contract_bundle=contract_bundle,
    )
    if _canonical(review) != _canonical(expected):
        raise ApiSessionSequenceReviewError("session review does not match source replay")
    return expected
