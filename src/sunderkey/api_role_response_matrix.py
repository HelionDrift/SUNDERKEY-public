"""Offline role-to-endpoint response evidence from sanitized API observations."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any

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
    _plain_integer,
    _plain_string,
    _timestamp,
    _tuple_values,
    _verified_inventory,
    _verified_observation,
)

MAX_ROLE_ENDPOINT_ROWS = 10000
NO_EFFECTS = MappingProxyType({
    "authority": "none",
    "authorization_verdict": "none",
    "execution": "none",
    "network": "none",
    "qualification": "none",
    "scheduler": "none",
})


class ApiRoleResponseError(ValueError):
    """Role-to-endpoint evidence is inconsistent with the supplied inventory."""


@dataclass(frozen=True, slots=True)
class RoleEndpointResponse:
    role_ref: str
    origin: str
    method: str
    path_shape: str
    event_count: int
    status_codes: tuple[int, ...]
    first_observed_at: str
    last_observed_at: str
    source_sha256: tuple[str, ...]
    observation_sha256: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            if self.role_ref != "anonymous":
                if not isinstance(self.role_ref, str) or not self.role_ref.startswith("role:"):
                    raise TrafficApiInventoryError("role_ref is invalid")
                _identifier(self.role_ref, "role_ref")
            _origin(self.origin)
            _path_shape(self.path_shape)
            first = _timestamp(self.first_observed_at, "first_observed_at")
            last = _timestamp(self.last_observed_at, "last_observed_at")
            for value in (*self.source_sha256, *self.observation_sha256):
                _digest(value, "evidence digest")
        except TrafficApiInventoryError as exc:
            raise ApiRoleResponseError("row metadata is invalid") from exc
        if not isinstance(self.method, str) or self.method not in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        }:
            raise ApiRoleResponseError("method is invalid")
        if first > last:
            raise ApiRoleResponseError("row observation interval is invalid")
        if (
            isinstance(self.event_count, bool) or not isinstance(self.event_count, int)
            or not 1 <= self.event_count <= MAX_OBSERVATIONS
            or len(self.observation_sha256) != self.event_count
        ):
            raise ApiRoleResponseError("row event count is invalid")
        for values in (self.status_codes, self.source_sha256, self.observation_sha256):
            if not isinstance(values, tuple) or not values or values != tuple(sorted(set(values))):
                raise ApiRoleResponseError("row evidence list is not canonical")
        if any(
            isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599
            for code in self.status_codes
        ):
            raise ApiRoleResponseError("row status code is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_ref": self.role_ref, "origin": self.origin,
            "method": self.method, "path_shape": self.path_shape,
            "event_count": self.event_count, "status_codes": list(self.status_codes),
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
            "source_sha256": list(self.source_sha256),
            "observation_sha256": list(self.observation_sha256),
        }


@dataclass(frozen=True, slots=True)
class ApiRoleResponseMatrix:
    inventory_sha256: str
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    snapshot_at: str
    rows: tuple[RoleEndpointResponse, ...]
    matrix_sha256: str = ""

    def __post_init__(self) -> None:
        try:
            for name in ("inventory_sha256", "context_sha256", "scope_sha256"):
                _digest(getattr(self, name), name)
            for name in ("tenant_id", "context_id", "scope_id"):
                _identifier(getattr(self, name), name)
            _timestamp(self.snapshot_at, "snapshot_at")
        except TrafficApiInventoryError as exc:
            raise ApiRoleResponseError("matrix binding is invalid") from exc
        if (
            not isinstance(self.rows, tuple) or len(self.rows) > MAX_ROLE_ENDPOINT_ROWS
            or any(not isinstance(row, RoleEndpointResponse) for row in self.rows)
            or self.rows != tuple(sorted(self.rows, key=lambda row: (
                row.origin, row.method, row.path_shape, row.role_ref
            )))
        ):
            raise ApiRoleResponseError("rows are not bounded and canonical")
        keys = [(row.origin, row.method, row.path_shape, row.role_ref) for row in self.rows]
        if len(set(keys)) != len(keys):
            raise ApiRoleResponseError("role endpoint row is repeated")
        expected = _canonical_sha("sunderkey.api-role-response-matrix.v1", self._payload())
        if self.matrix_sha256 and self.matrix_sha256 != expected:
            raise ApiRoleResponseError("matrix_sha256 does not match content")
        object.__setattr__(self, "matrix_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "inventory_sha256": self.inventory_sha256,
            "tenant_id": self.tenant_id, "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "scope_id": self.scope_id, "scope_sha256": self.scope_sha256,
            "snapshot_at": self.snapshot_at,
            "rows": [row.to_dict() for row in self.rows], "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "matrix_sha256": self.matrix_sha256}


def build_api_role_response_matrix(
    *, inventory: TrafficApiInventory,
    observations: tuple[SanitizedApiTrafficObservation, ...],
) -> ApiRoleResponseMatrix:
    """Preserve exact role-response association, not an authorization verdict."""
    if not isinstance(inventory, TrafficApiInventory):
        raise ApiRoleResponseError("typed traffic inventory is required")
    try:
        inventory = _verified_inventory(inventory)
    except TrafficApiInventoryError as exc:
        raise ApiRoleResponseError("inventory integrity is invalid") from exc
    try:
        observations = _tuple_values(observations, "observations", MAX_OBSERVATIONS)
    except TrafficApiInventoryError as exc:
        raise ApiRoleResponseError("observations must be a bounded tuple") from exc
    by_event: dict[str, SanitizedApiTrafficObservation] = {}
    for supplied in observations:
        try:
            item = _verified_observation(supplied)
        except TrafficApiInventoryError as exc:
            raise ApiRoleResponseError("observation integrity is invalid") from exc
        if (
            item.tenant_id, item.context_id, item.context_sha256,
            item.scope_id, item.scope_sha256,
        ) != (
            inventory.tenant_id, inventory.context_id, inventory.context_sha256,
            inventory.scope_id, inventory.scope_sha256,
        ):
            raise ApiRoleResponseError("observation context or scope differs")
        if _timestamp(item.observed_at, "observed_at") > _timestamp(
            inventory.snapshot_at, "snapshot_at"
        ):
            raise ApiRoleResponseError("observation is after inventory snapshot")
        prior = by_event.setdefault(item.event_id, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise ApiRoleResponseError("event ID maps to conflicting observations")
    if tuple(sorted(item.observation_sha256 for item in by_event.values())) != (
        inventory.observation_sha256
    ):
        raise ApiRoleResponseError("observations do not exactly cover inventory")
    by_endpoint: dict[tuple[str, str, str], list[SanitizedApiTrafficObservation]] = (
        defaultdict(list)
    )
    by_row: dict[tuple[str, str, str, str], list[SanitizedApiTrafficObservation]] = (
        defaultdict(list)
    )
    for item in by_event.values():
        by_endpoint[item.origin, item.method, item.path_shape].append(item)
        by_row[item.origin, item.method, item.path_shape, item.role_ref].append(item)
    endpoints = {(item.origin, item.method, item.path_shape): item for item in inventory.endpoints}
    if set(by_endpoint) != set(endpoints):
        raise ApiRoleResponseError("observed endpoint set differs from inventory")
    for key, items in by_endpoint.items():
        endpoint = endpoints[key]
        if (
            endpoint.event_count != len(items)
            or endpoint.role_refs != tuple(sorted({item.role_ref for item in items}))
            or endpoint.status_codes != tuple(sorted({item.status_code for item in items}))
            or endpoint.source_sha256 != tuple(sorted({item.source_sha256 for item in items}))
            or endpoint.first_observed_at != min(item.observed_at for item in items)
            or endpoint.last_observed_at != max(item.observed_at for item in items)
        ):
            raise ApiRoleResponseError("endpoint aggregation differs from observations")
    if len(by_row) > MAX_ROLE_ENDPOINT_ROWS:
        raise ApiRoleResponseError("role endpoint row count exceeds hard limit")
    rows = tuple(
        RoleEndpointResponse(
            role_ref=key[3], origin=key[0], method=key[1], path_shape=key[2],
            event_count=len(items),
            status_codes=tuple(sorted({item.status_code for item in items})),
            first_observed_at=min(item.observed_at for item in items),
            last_observed_at=max(item.observed_at for item in items),
            source_sha256=tuple(sorted({item.source_sha256 for item in items})),
            observation_sha256=tuple(sorted(item.observation_sha256 for item in items)),
        )
        for key, items in sorted(by_row.items())
    )
    return ApiRoleResponseMatrix(
        inventory_sha256=inventory.inventory_sha256,
        tenant_id=inventory.tenant_id, context_id=inventory.context_id,
        context_sha256=inventory.context_sha256,
        scope_id=inventory.scope_id, scope_sha256=inventory.scope_sha256,
        snapshot_at=inventory.snapshot_at, rows=rows,
    )


def _verified_matrix(value: ApiRoleResponseMatrix) -> ApiRoleResponseMatrix:
    """Capture declared base primitives and verify the supplied matrix digest."""
    if not isinstance(value, ApiRoleResponseMatrix):
        raise ApiRoleResponseError("typed role-response matrix is required")
    try:
        declared = {
            item.name: _plain_string(getattr(value, item.name), item.name)
            for item in fields(ApiRoleResponseMatrix)
            if item.name != "rows"
        }
        _digest(declared["matrix_sha256"], "matrix_sha256")
        rows = []
        for supplied in _tuple_values(value.rows, "rows", MAX_ROLE_ENDPOINT_ROWS):
            if not isinstance(supplied, RoleEndpointResponse):
                raise TrafficApiInventoryError("typed role-response row is required")
            row = {
                item.name: _plain_string(getattr(supplied, item.name), item.name)
                for item in fields(RoleEndpointResponse)
                if item.name not in {
                    "event_count", "status_codes", "source_sha256", "observation_sha256"
                }
            }
            row["event_count"] = _plain_integer(supplied.event_count, "event_count")
            row["status_codes"] = tuple(
                _plain_integer(code, "status code")
                for code in _tuple_values(supplied.status_codes, "status_codes", 500)
            )
            for name in ("source_sha256", "observation_sha256"):
                row[name] = tuple(
                    _plain_string(digest, name)
                    for digest in _tuple_values(getattr(supplied, name), name, MAX_OBSERVATIONS)
                )
            rows.append(RoleEndpointResponse(**row))
        return ApiRoleResponseMatrix(**declared, rows=tuple(rows))
    except (TrafficApiInventoryError, AttributeError) as exc:
        raise ApiRoleResponseError("matrix integrity is invalid") from exc


def verify_api_role_response_matrix_from_sources(
    matrix: ApiRoleResponseMatrix,
    *,
    inventory: TrafficApiInventory,
    observations: tuple[SanitizedApiTrafficObservation, ...],
) -> ApiRoleResponseMatrix:
    """Replay the matrix from the supplied inventory and sanitized observations."""

    matrix = _verified_matrix(matrix)
    expected = build_api_role_response_matrix(
        inventory=inventory,
        observations=observations,
    )
    if expected != matrix:
        raise ApiRoleResponseError("role-response matrix does not match source replay")
    return expected
