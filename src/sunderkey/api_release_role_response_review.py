"""Offline release review preserving supplied role-response associations.

Response statuses are observations, not authorization verdicts. Missing
associations do not prove removal or denial. This module performs no collection,
adapter invocation, release approval, scheduling, or target action.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .api_release_delta_review import ApiReleaseDeltaError, compare_api_release_inventories
from .api_role_response_matrix import ApiRoleResponseError, build_api_role_response_matrix
from .traffic_derived_api_inventory import (
    MAX_OBSERVATIONS,
    SanitizedApiTrafficObservation,
    TrafficApiInventory,
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _origin,
    _path_shape,
    _timestamp,
    _verified_inventory,
)

SCHEMA_VERSION = 1
DOMAIN = "sunderkey.api-release-role-response-review.v1"
NO_DIFFERENCE_REASON = "no_difference_observed_without_coverage_proof"
NEW_ASSOCIATION_REASON = "new_role_status_association_observed"
MISSING_ASSOCIATION_REASON = "prior_role_status_association_not_reobserved"
LEGACY_CHANGE_REASONS = frozenset(
    {
        "new_endpoint_observed",
        "prior_endpoint_not_reobserved",
        "new_role_observed",
        "new_status_observed",
        "contract_mapping_changed",
        "contract_bundle_changed",
    }
)
NO_EFFECTS = MappingProxyType(
    {
        "authority": "none",
        "authorization_verdict": "none",
        "deployment": "none",
        "execution": "none",
        "finding_publication": "none",
        "network": "none",
        "qualification": "none",
        "release_approval": "none",
        "routing": "none",
        "scheduler": "none",
    }
)
_ID_FIELDS = ("release_id", "tenant_id", "context_id", "scope_id")
_DIGEST_FIELDS = (
    "release_artifact_sha256",
    "context_sha256",
    "scope_sha256",
    "baseline_inventory_sha256",
    "current_inventory_sha256",
    "baseline_matrix_sha256",
    "current_matrix_sha256",
    "inventory_delta_sha256",
)
_TIME_FIELDS = ("release_at", "baseline_snapshot_at", "current_snapshot_at")
_ASSOCIATION_FIELDS = frozenset({"origin", "method", "path_shape", "role_ref", "status_code"})
_FIELDS = frozenset(
    {
        "schema_version",
        *_ID_FIELDS,
        *_DIGEST_FIELDS,
        *_TIME_FIELDS,
        "inventory_delta_gate_status",
        "inventory_delta_review_reasons",
        "new_associations",
        "not_reobserved_associations",
        "reobserved_count",
        "review_reasons",
        "gate_status",
        "effects",
        "review_sha256",
    }
)


class ApiReleaseRoleResponseReviewError(ValueError):
    """Source evidence or a release role-response review is inconsistent."""


def _exact_object(value: Any, fields: frozenset[str], label: str) -> dict:
    if (
        type(value) is not dict
        or len(value) != len(fields)
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise ApiReleaseRoleResponseReviewError(f"{label} fields are invalid")
    return value


def _string(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ApiReleaseRoleResponseReviewError(f"{label} must be an exact string")
    return value


def _reasons(value: Any, allowed: frozenset[str], label: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > len(allowed):
        raise ApiReleaseRoleResponseReviewError(f"{label} is invalid")
    if any(type(item) is not str or item not in allowed for item in value):
        raise ApiReleaseRoleResponseReviewError(f"{label} is invalid")
    if value != tuple(sorted(set(value))):
        raise ApiReleaseRoleResponseReviewError(f"{label} is not canonical")
    return value


@dataclass(frozen=True, slots=True, order=True)
class ApiRoleStatusAssociation:
    origin: str
    method: str
    path_shape: str
    role_ref: str
    status_code: int

    def __post_init__(self) -> None:
        for name in ("origin", "method", "path_shape", "role_ref"):
            _string(getattr(self, name), name)
        try:
            _origin(self.origin)
            _path_shape(self.path_shape)
            if self.role_ref != "anonymous":
                if not self.role_ref.startswith("role:"):
                    raise TrafficApiInventoryError("role_ref must be opaque")
                _identifier(self.role_ref, "role_ref")
        except TrafficApiInventoryError as exc:
            raise ApiReleaseRoleResponseReviewError("association metadata is invalid") from exc
        if self.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ApiReleaseRoleResponseReviewError("association method is invalid")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ApiReleaseRoleResponseReviewError("association status_code is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "method": self.method,
            "path_shape": self.path_shape,
            "role_ref": self.role_ref,
            "status_code": self.status_code,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ApiRoleStatusAssociation:
        return cls(**_exact_object(value, _ASSOCIATION_FIELDS, "association"))


@dataclass(frozen=True, slots=True)
class ApiReleaseRoleResponseReview:
    schema_version: int
    release_id: str
    release_artifact_sha256: str
    release_at: str
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    baseline_snapshot_at: str
    current_snapshot_at: str
    baseline_inventory_sha256: str
    current_inventory_sha256: str
    baseline_matrix_sha256: str
    current_matrix_sha256: str
    inventory_delta_sha256: str
    inventory_delta_gate_status: str
    inventory_delta_review_reasons: tuple[str, ...]
    new_associations: tuple[ApiRoleStatusAssociation, ...]
    not_reobserved_associations: tuple[ApiRoleStatusAssociation, ...]
    reobserved_count: int
    review_reasons: tuple[str, ...]
    gate_status: str
    review_sha256: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ApiReleaseRoleResponseReviewError("schema_version is invalid")
        try:
            for name in _ID_FIELDS:
                _identifier(_string(getattr(self, name), name), name)
            for name in _DIGEST_FIELDS:
                _digest(_string(getattr(self, name), name), name)
            times = {
                name: _timestamp(_string(getattr(self, name), name), name) for name in _TIME_FIELDS
            }
        except TrafficApiInventoryError as exc:
            raise ApiReleaseRoleResponseReviewError("review binding metadata is invalid") from exc
        if not times["baseline_snapshot_at"] < times["release_at"] <= times["current_snapshot_at"]:
            raise ApiReleaseRoleResponseReviewError("release boundary is outside snapshot order")
        _string(self.inventory_delta_gate_status, "inventory_delta_gate_status")
        _string(self.gate_status, "gate_status")
        legacy = _reasons(
            self.inventory_delta_review_reasons,
            LEGACY_CHANGE_REASONS | {NO_DIFFERENCE_REASON},
            "inventory_delta_review_reasons",
        )
        if self.inventory_delta_gate_status == "inconclusive":
            if legacy != (NO_DIFFERENCE_REASON,):
                raise ApiReleaseRoleResponseReviewError("legacy gate and reasons disagree")
        elif self.inventory_delta_gate_status == "review_required":
            if NO_DIFFERENCE_REASON in legacy:
                raise ApiReleaseRoleResponseReviewError("legacy gate and reasons disagree")
        else:
            raise ApiReleaseRoleResponseReviewError("legacy gate is invalid")
        for name in ("new_associations", "not_reobserved_associations"):
            values = getattr(self, name)
            if (
                type(values) is not tuple
                or len(values) > MAX_OBSERVATIONS
                or any(type(item) is not ApiRoleStatusAssociation for item in values)
            ):
                raise ApiReleaseRoleResponseReviewError(f"{name} is not a bounded typed tuple")
            for item in values:
                ApiRoleStatusAssociation.from_dict(item.to_dict())
            if values != tuple(sorted(set(values))):
                raise ApiReleaseRoleResponseReviewError(f"{name} is not canonical")
        if set(self.new_associations).intersection(self.not_reobserved_associations):
            raise ApiReleaseRoleResponseReviewError(
                "association cannot be both new and not reobserved"
            )
        if (
            type(self.reobserved_count) is not int
            or not 0 <= self.reobserved_count <= MAX_OBSERVATIONS
        ):
            raise ApiReleaseRoleResponseReviewError("reobserved_count is invalid")
        if (
            len(self.new_associations) + self.reobserved_count > MAX_OBSERVATIONS
            or len(self.not_reobserved_associations) + self.reobserved_count > MAX_OBSERVATIONS
        ):
            raise ApiReleaseRoleResponseReviewError(
                "association accounting exceeds a source window"
            )
        expected_reasons = set(legacy)
        if self.new_associations or self.not_reobserved_associations:
            expected_reasons.discard(NO_DIFFERENCE_REASON)
        if self.new_associations:
            expected_reasons.add(NEW_ASSOCIATION_REASON)
        if self.not_reobserved_associations:
            expected_reasons.add(MISSING_ASSOCIATION_REASON)
        _reasons(
            self.review_reasons,
            LEGACY_CHANGE_REASONS
            | {NO_DIFFERENCE_REASON, NEW_ASSOCIATION_REASON, MISSING_ASSOCIATION_REASON},
            "review_reasons",
        )
        if self.review_reasons != tuple(sorted(expected_reasons)):
            raise ApiReleaseRoleResponseReviewError(
                "review reasons disagree with observed differences"
            )
        expected_gate = (
            "review_required"
            if self.new_associations or self.inventory_delta_gate_status == "review_required"
            else "inconclusive"
        )
        if self.gate_status != expected_gate:
            raise ApiReleaseRoleResponseReviewError("gate_status overclaims observed differences")
        _string(self.review_sha256, "review_sha256")
        expected = _canonical_sha(DOMAIN, self._payload())
        if self.review_sha256:
            try:
                _digest(self.review_sha256, "review_sha256")
            except TrafficApiInventoryError as exc:
                raise ApiReleaseRoleResponseReviewError("review_sha256 is invalid") from exc
            if self.review_sha256 != expected:
                raise ApiReleaseRoleResponseReviewError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            **{name: getattr(self, name) for name in (*_ID_FIELDS, *_DIGEST_FIELDS, *_TIME_FIELDS)},
            "inventory_delta_gate_status": self.inventory_delta_gate_status,
            "inventory_delta_review_reasons": list(self.inventory_delta_review_reasons),
            "new_associations": [item.to_dict() for item in self.new_associations],
            "not_reobserved_associations": [
                item.to_dict() for item in self.not_reobserved_associations
            ],
            "reobserved_count": self.reobserved_count,
            "review_reasons": list(self.review_reasons),
            "gate_status": self.gate_status,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}

    @classmethod
    def from_dict(cls, value: Any) -> ApiReleaseRoleResponseReview:
        raw = _exact_object(value, _FIELDS, "review")
        effects = _exact_object(raw["effects"], frozenset(NO_EFFECTS), "effects")
        if any(type(item) is not str or item != "none" for item in effects.values()):
            raise ApiReleaseRoleResponseReviewError("effects must all be none")
        for name in ("inventory_delta_review_reasons", "review_reasons"):
            maximum = len(LEGACY_CHANGE_REASONS) + (
                1 if name == "inventory_delta_review_reasons" else 3
            )
            if type(raw[name]) is not list or not 1 <= len(raw[name]) <= maximum:
                raise ApiReleaseRoleResponseReviewError(f"{name} must be a bounded exact list")
        associations = {}
        for name in ("new_associations", "not_reobserved_associations"):
            if type(raw[name]) is not list or len(raw[name]) > MAX_OBSERVATIONS:
                raise ApiReleaseRoleResponseReviewError(f"{name} must be a bounded exact list")
            associations[name] = tuple(
                ApiRoleStatusAssociation.from_dict(item) for item in raw[name]
            )
        try:
            _digest(_string(raw["review_sha256"], "review_sha256"), "review_sha256")
        except TrafficApiInventoryError as exc:
            raise ApiReleaseRoleResponseReviewError("wire review_sha256 is invalid") from exc
        return cls(
            **{
                name: raw[name]
                for name in _FIELDS
                - {
                    "effects",
                    "new_associations",
                    "not_reobserved_associations",
                    "inventory_delta_review_reasons",
                    "review_reasons",
                }
            },
            **associations,
            inventory_delta_review_reasons=tuple(raw["inventory_delta_review_reasons"]),
            review_reasons=tuple(raw["review_reasons"]),
        )


def compare_api_release_role_responses(
    *,
    baseline: TrafficApiInventory,
    current: TrafficApiInventory,
    baseline_observations: tuple[SanitizedApiTrafficObservation, ...],
    current_observations: tuple[SanitizedApiTrafficObservation, ...],
    release_id: str,
    release_artifact_sha256: str,
    release_at: str,
) -> ApiReleaseRoleResponseReview:
    """Replay supplied inventory windows without issuing an authorization verdict."""
    try:
        baseline = _verified_inventory(baseline)
        current = _verified_inventory(current)
        delta = compare_api_release_inventories(
            baseline=baseline,
            current=current,
            release_id=release_id,
            release_artifact_sha256=release_artifact_sha256,
            release_at=release_at,
        )
        before_matrix = build_api_role_response_matrix(
            inventory=baseline, observations=baseline_observations
        )
        after_matrix = build_api_role_response_matrix(
            inventory=current, observations=current_observations
        )
    except (ApiReleaseDeltaError, ApiRoleResponseError, TrafficApiInventoryError) as exc:
        raise ApiReleaseRoleResponseReviewError("release source replay failed") from exc

    def flatten(matrix) -> set[ApiRoleStatusAssociation]:
        return {
            ApiRoleStatusAssociation(row.origin, row.method, row.path_shape, row.role_ref, status)
            for row in matrix.rows
            for status in row.status_codes
        }

    before, after = flatten(before_matrix), flatten(after_matrix)
    new, missing = tuple(sorted(after - before)), tuple(sorted(before - after))
    reasons = set(delta.review_reasons)
    if new or missing:
        reasons.discard(NO_DIFFERENCE_REASON)
    if new:
        reasons.add(NEW_ASSOCIATION_REASON)
    if missing:
        reasons.add(MISSING_ASSOCIATION_REASON)
    return ApiReleaseRoleResponseReview(
        schema_version=SCHEMA_VERSION,
        **{
            name: getattr(delta, name)
            for name in (
                *_ID_FIELDS,
                "release_artifact_sha256",
                "release_at",
                "context_sha256",
                "scope_sha256",
                "baseline_inventory_sha256",
                "current_inventory_sha256",
            )
        },
        baseline_snapshot_at=baseline.snapshot_at,
        current_snapshot_at=current.snapshot_at,
        baseline_matrix_sha256=before_matrix.matrix_sha256,
        current_matrix_sha256=after_matrix.matrix_sha256,
        inventory_delta_sha256=delta.delta_sha256,
        inventory_delta_gate_status=delta.gate_status,
        inventory_delta_review_reasons=delta.review_reasons,
        new_associations=new,
        not_reobserved_associations=missing,
        reobserved_count=len(before & after),
        review_reasons=tuple(sorted(reasons)),
        gate_status="review_required"
        if new or delta.gate_status == "review_required"
        else "inconclusive",
    )


def verify_api_release_role_response_review(
    *,
    review: ApiReleaseRoleResponseReview | dict[str, Any],
    baseline: TrafficApiInventory,
    current: TrafficApiInventory,
    baseline_observations: tuple[SanitizedApiTrafficObservation, ...],
    current_observations: tuple[SanitizedApiTrafficObservation, ...],
    release_id: str,
    release_artifact_sha256: str,
    release_at: str,
) -> ApiReleaseRoleResponseReview:
    """Reject intact but substituted content against the complete original sources."""
    supplied = ApiReleaseRoleResponseReview.from_dict(
        review.to_dict() if type(review) is ApiReleaseRoleResponseReview else review
    )
    expected = compare_api_release_role_responses(
        baseline=baseline,
        current=current,
        baseline_observations=baseline_observations,
        current_observations=current_observations,
        release_id=release_id,
        release_artifact_sha256=release_artifact_sha256,
        release_at=release_at,
    )
    # Both documents contain only the exact, closed JSON primitive types above.
    if supplied.to_dict() != expected.to_dict():
        raise ApiReleaseRoleResponseReviewError("review does not match complete source replay")
    return expected


__all__ = [
    "ApiReleaseRoleResponseReview",
    "ApiReleaseRoleResponseReviewError",
    "ApiRoleStatusAssociation",
    "compare_api_release_role_responses",
    "verify_api_release_role_response_review",
]
