"""Offline, fail-closed API surface review across a supplied release boundary."""

from __future__ import annotations

from dataclasses import dataclass, fields

from .service_contract_extractor import ServiceContractEndpointBundle
from .traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    TrafficApiEndpoint,
    TrafficApiInventory,
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _plain_integer,
    _plain_string,
    _timestamp,
    _tuple_values,
    _verified_inventory,
    verify_traffic_api_inventory_from_sources,
)

AUTHORITY_EFFECT = "none"
RELEASE_APPROVAL_EFFECT = "none"
QUALIFICATION_EFFECT = "none"
NETWORK_CALL_PERFORMED = False


class ApiReleaseDeltaError(ValueError):
    """Two inventory snapshots cannot support a valid release comparison."""


def _key(endpoint: TrafficApiEndpoint) -> str:
    return f"{endpoint.method} {endpoint.origin}{endpoint.path_shape}"


def _payload(review: ApiReleaseDelta) -> dict[str, object]:
    return {
        "release_id": review.release_id,
        "release_artifact_sha256": review.release_artifact_sha256,
        "release_at": review.release_at,
        "tenant_id": review.tenant_id,
        "context_id": review.context_id,
        "context_sha256": review.context_sha256,
        "scope_id": review.scope_id,
        "scope_sha256": review.scope_sha256,
        "baseline_inventory_sha256": review.baseline_inventory_sha256,
        "current_inventory_sha256": review.current_inventory_sha256,
        "contract_bundle_changed": review.contract_bundle_changed,
        "new_endpoints": list(review.new_endpoints),
        "not_reobserved_endpoints": list(review.not_reobserved_endpoints),
        "expanded_roles": [
            {"endpoint": key, "new_role_refs": list(roles)}
            for key, roles in review.expanded_roles
        ],
        "new_status_codes": [
            {"endpoint": key, "status_codes": list(codes)}
            for key, codes in review.new_status_codes
        ],
        "changed_contract_mappings": list(review.changed_contract_mappings),
        "review_reasons": list(review.review_reasons),
        "gate_status": review.gate_status,
    }


@dataclass(frozen=True, slots=True)
class ApiReleaseDelta:
    release_id: str
    release_artifact_sha256: str
    release_at: str
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    baseline_inventory_sha256: str
    current_inventory_sha256: str
    contract_bundle_changed: bool
    new_endpoints: tuple[str, ...]
    not_reobserved_endpoints: tuple[str, ...]
    expanded_roles: tuple[tuple[str, tuple[str, ...]], ...]
    new_status_codes: tuple[tuple[str, tuple[int, ...]], ...]
    changed_contract_mappings: tuple[str, ...]
    review_reasons: tuple[str, ...]
    gate_status: str
    delta_sha256: str

    def __post_init__(self) -> None:
        try:
            for label in ("release_id", "tenant_id", "context_id", "scope_id"):
                _identifier(getattr(self, label), label)
            for label in (
                "release_artifact_sha256",
                "context_sha256",
                "scope_sha256",
                "baseline_inventory_sha256",
                "current_inventory_sha256",
            ):
                _digest(getattr(self, label), label)
            _timestamp(self.release_at, "release_at")
        except TrafficApiInventoryError as exc:
            raise ApiReleaseDeltaError("release delta metadata is invalid") from exc
        if not isinstance(self.contract_bundle_changed, bool):
            raise ApiReleaseDeltaError("contract_bundle_changed must be a boolean")
        for values in (
            self.new_endpoints,
            self.not_reobserved_endpoints,
            self.changed_contract_mappings,
            self.review_reasons,
        ):
            if (
                not isinstance(values, tuple)
                or not all(isinstance(value, str) and value for value in values)
                or tuple(sorted(set(values))) != values
            ):
                raise ApiReleaseDeltaError("release change list is not canonical")
        if set(self.new_endpoints).intersection(self.not_reobserved_endpoints):
            raise ApiReleaseDeltaError("endpoint cannot be both new and not reobserved")
        if not isinstance(self.expanded_roles, tuple) or not isinstance(
            self.new_status_codes, tuple
        ):
            raise ApiReleaseDeltaError("release expansion lists are invalid")
        if (
            not all(
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], tuple)
                for item in self.expanded_roles + self.new_status_codes
            )
            or tuple(sorted(self.expanded_roles)) != self.expanded_roles
            or tuple(sorted(self.new_status_codes)) != self.new_status_codes
        ):
            raise ApiReleaseDeltaError("release expansion lists are not canonical")
        for key, roles in self.expanded_roles:
            if (
                not key
                or not roles
                or not all(isinstance(role, str) and role for role in roles)
                or tuple(sorted(set(roles))) != roles
            ):
                raise ApiReleaseDeltaError("role expansion is invalid")
        for key, codes in self.new_status_codes:
            if (
                not key
                or not codes
                or not all(isinstance(code, int) and not isinstance(code, bool) for code in codes)
                or tuple(sorted(set(codes))) != codes
            ):
                raise ApiReleaseDeltaError("status expansion is invalid")
        changes_present = any(
            (
                self.new_endpoints,
                self.not_reobserved_endpoints,
                self.expanded_roles,
                self.new_status_codes,
                self.changed_contract_mappings,
                self.contract_bundle_changed,
            )
        )
        expected_status = "review_required" if changes_present else "inconclusive"
        if self.gate_status != expected_status:
            raise ApiReleaseDeltaError("gate_status overclaims the observed changes")
        expected_reasons = tuple(
            sorted(
                code
                for present, code in (
                    (self.new_endpoints, "new_endpoint_observed"),
                    (self.not_reobserved_endpoints, "prior_endpoint_not_reobserved"),
                    (self.expanded_roles, "new_role_observed"),
                    (self.new_status_codes, "new_status_observed"),
                    (self.changed_contract_mappings, "contract_mapping_changed"),
                    (self.contract_bundle_changed, "contract_bundle_changed"),
                )
                if present
            )
        ) or ("no_difference_observed_without_coverage_proof",)
        if self.review_reasons != expected_reasons:
            raise ApiReleaseDeltaError("review_reasons do not match observed changes")
        expected = _canonical_sha("sunderkey.api-release-delta.v1", _payload(self))
        if not self.delta_sha256:
            object.__setattr__(self, "delta_sha256", expected)
        elif self.delta_sha256 != expected:
            raise ApiReleaseDeltaError("delta_sha256 does not match content")

    def to_dict(self) -> dict[str, object]:
        return {
            **_payload(self),
            "delta_sha256": self.delta_sha256,
            "authority_effect": AUTHORITY_EFFECT,
            "release_approval_effect": RELEASE_APPROVAL_EFFECT,
            "qualification_effect": QUALIFICATION_EFFECT,
            "network_call_performed": NETWORK_CALL_PERFORMED,
        }


def compare_api_release_inventories(
    *,
    baseline: TrafficApiInventory,
    current: TrafficApiInventory,
    release_id: str,
    release_artifact_sha256: str,
    release_at: str,
) -> ApiReleaseDelta:
    """Flag observed changes, never infer a passing release gate."""

    if not isinstance(baseline, TrafficApiInventory) or not isinstance(
        current, TrafficApiInventory
    ):
        raise ApiReleaseDeltaError("typed inventories are required")
    try:
        baseline = _verified_inventory(baseline)
        current = _verified_inventory(current)
    except TrafficApiInventoryError as exc:
        raise ApiReleaseDeltaError("inventory integrity is invalid") from exc
    try:
        release_id = _plain_string(release_id, "release_id")
        release_artifact_sha256 = _plain_string(
            release_artifact_sha256, "release_artifact_sha256"
        )
        release_at = _plain_string(release_at, "release_at")
        _identifier(release_id, "release_id")
        _digest(release_artifact_sha256, "release_artifact_sha256")
        boundary = _timestamp(release_at, "release_at")
    except TrafficApiInventoryError as exc:
        raise ApiReleaseDeltaError("release metadata is invalid") from exc
    if (
        baseline.tenant_id,
        baseline.context_id,
        baseline.context_sha256,
        baseline.scope_id,
        baseline.scope_sha256,
    ) != (
        current.tenant_id,
        current.context_id,
        current.context_sha256,
        current.scope_id,
        current.scope_sha256,
    ):
        raise ApiReleaseDeltaError("inventory context or scope lineage differs")
    if not _timestamp(baseline.snapshot_at, "baseline snapshot") < boundary <= _timestamp(
        current.snapshot_at, "current snapshot"
    ):
        raise ApiReleaseDeltaError("release boundary is outside snapshot order")
    if any(
        _timestamp(item.last_observed_at, "baseline event") >= boundary
        for item in baseline.endpoints
    ):
        raise ApiReleaseDeltaError("baseline includes an event at or after release")
    if any(
        _timestamp(item.first_observed_at, "current event") < boundary
        for item in current.endpoints
    ):
        raise ApiReleaseDeltaError("current inventory includes a pre-release event")
    if set(baseline.observation_sha256).intersection(current.observation_sha256):
        raise ApiReleaseDeltaError("observation is replayed across the release boundary")

    before = {_key(item): item for item in baseline.endpoints}
    after = {_key(item): item for item in current.endpoints}
    new_endpoints = tuple(sorted(after.keys() - before.keys()))
    not_reobserved = tuple(sorted(before.keys() - after.keys()))
    expanded_roles: list[tuple[str, tuple[str, ...]]] = []
    new_status_codes: list[tuple[str, tuple[int, ...]]] = []
    changed_contract: list[str] = []
    for key in sorted(before.keys() & after.keys()):
        prior = before[key]
        latest = after[key]
        roles = tuple(sorted(set(latest.role_refs) - set(prior.role_refs)))
        codes = tuple(sorted(set(latest.status_codes) - set(prior.status_codes)))
        if roles:
            expanded_roles.append((key, roles))
        if codes:
            new_status_codes.append((key, codes))
        if (
            latest.contract_state != prior.contract_state
            or latest.matching_contract_endpoint_sha256
            != prior.matching_contract_endpoint_sha256
        ):
            changed_contract.append(key)
    contract_bundle_changed = (
        baseline.contract_bundle_sha256 != current.contract_bundle_sha256
    )
    reasons: list[str] = []
    for present, code in (
        (new_endpoints, "new_endpoint_observed"),
        (not_reobserved, "prior_endpoint_not_reobserved"),
        (expanded_roles, "new_role_observed"),
        (new_status_codes, "new_status_observed"),
        (changed_contract, "contract_mapping_changed"),
        (contract_bundle_changed, "contract_bundle_changed"),
    ):
        if present:
            reasons.append(code)
    if not reasons:
        reasons.append("no_difference_observed_without_coverage_proof")
    gate = "review_required" if any(
        (
            new_endpoints,
            not_reobserved,
            expanded_roles,
            new_status_codes,
            changed_contract,
            contract_bundle_changed,
        )
    ) else "inconclusive"
    values = {
        "release_id": release_id,
        "release_artifact_sha256": release_artifact_sha256,
        "release_at": release_at,
        "tenant_id": current.tenant_id,
        "context_id": current.context_id,
        "context_sha256": current.context_sha256,
        "scope_id": current.scope_id,
        "scope_sha256": current.scope_sha256,
        "baseline_inventory_sha256": baseline.inventory_sha256,
        "current_inventory_sha256": current.inventory_sha256,
        "contract_bundle_changed": contract_bundle_changed,
        "new_endpoints": new_endpoints,
        "not_reobserved_endpoints": not_reobserved,
        "expanded_roles": tuple(expanded_roles),
        "new_status_codes": tuple(new_status_codes),
        "changed_contract_mappings": tuple(changed_contract),
        "review_reasons": tuple(sorted(reasons)),
        "gate_status": gate,
    }
    return ApiReleaseDelta(**values, delta_sha256="")


def _verified_delta(value: ApiReleaseDelta) -> ApiReleaseDelta:
    """Capture declared base primitives and verify the supplied delta digest."""
    if not isinstance(value, ApiReleaseDelta):
        raise ApiReleaseDeltaError("typed release delta is required")
    tuple_names = {
        "new_endpoints", "not_reobserved_endpoints", "expanded_roles",
        "new_status_codes", "changed_contract_mappings", "review_reasons",
    }
    try:
        declared = {
            item.name: _plain_string(getattr(value, item.name), item.name)
            for item in fields(ApiReleaseDelta)
            if item.name not in tuple_names | {"contract_bundle_changed"}
        }
        _digest(declared["delta_sha256"], "delta_sha256")
        declared["contract_bundle_changed"] = value.contract_bundle_changed
        for name in tuple_names - {"expanded_roles", "new_status_codes"}:
            declared[name] = tuple(
                _plain_string(item, name)
                for item in _tuple_values(getattr(value, name), name)
            )
        for name in ("expanded_roles", "new_status_codes"):
            captured = []
            for supplied in _tuple_values(getattr(value, name), name):
                pair = _tuple_values(supplied, name)
                if len(pair) != 2:
                    raise TrafficApiInventoryError("release expansion pair is invalid")
                key = _plain_string(pair[0], "endpoint")
                values = _tuple_values(pair[1], name)
                captured.append((
                    key,
                    tuple(
                        _plain_string(item, "role_ref")
                        if name == "expanded_roles"
                        else _plain_integer(item, "status code")
                        for item in values
                    ),
                ))
            declared[name] = tuple(captured)
        return ApiReleaseDelta(**declared)
    except (TrafficApiInventoryError, AttributeError) as exc:
        raise ApiReleaseDeltaError("release delta integrity is invalid") from exc


def verify_api_release_delta_from_sources(
    review: ApiReleaseDelta,
    *,
    baseline: TrafficApiInventory,
    current: TrafficApiInventory,
    baseline_observations: tuple[SanitizedApiTrafficObservation, ...],
    current_observations: tuple[SanitizedApiTrafficObservation, ...],
    baseline_contract_bundle: ServiceContractEndpointBundle | None = None,
    current_contract_bundle: ServiceContractEndpointBundle | None = None,
) -> ApiReleaseDelta:
    """Replay both inventories and their release comparison from supplied evidence."""

    review = _verified_delta(review)
    try:
        baseline = verify_traffic_api_inventory_from_sources(
            baseline,
            observations=baseline_observations,
            contract_bundle=baseline_contract_bundle,
        )
        current = verify_traffic_api_inventory_from_sources(
            current,
            observations=current_observations,
            contract_bundle=current_contract_bundle,
        )
    except TrafficApiInventoryError as exc:
        raise ApiReleaseDeltaError("inventory source replay failed") from exc
    expected = compare_api_release_inventories(
        baseline=baseline,
        current=current,
        release_id=review.release_id,
        release_artifact_sha256=review.release_artifact_sha256,
        release_at=review.release_at,
    )
    if expected != review:
        raise ApiReleaseDeltaError("release delta does not match source replay")
    return expected
