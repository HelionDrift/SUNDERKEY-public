"""Offline API surface reconciliation from sanitized traffic metadata.

Observed traffic and supplied service contracts are evidence, not target
authority. This module performs no collection, network access, scheduling, or
release approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .assessment_transport_contracts import HttpMethod
from .service_contract_extractor import (
    HARD_MAX_ENDPOINTS,
    ServiceContractEndpointBundle,
    ServiceContractExtractionError,
)

AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"
NETWORK_CALL_PERFORMED = False
MAX_OBSERVATIONS = 10000
MAX_ENDPOINTS = 2000
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_INVENTORY_JSON_BYTES = 16_000_000
MAX_TOTAL_CONTRACT_MATCHES = 50_000
MAX_ORIGIN_LENGTH = 264

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9._~-]{1,64}\Z")
_PARAMETER = re.compile(r"\{[A-Za-z][A-Za-z0-9_]{0,63}\}\Z")


class TrafficApiInventoryError(ValueError):
    """Input metadata or reconciliation result violates the closed contract."""


def _plain_string(value: object, label: str) -> str:
    """Capture immutable text without invoking a caller conversion hook."""
    if not isinstance(value, str):
        raise TrafficApiInventoryError(f"{label} must be a string")
    return str.__str__(value)


def _plain_integer(value: object, label: str) -> int:
    """Capture the underlying integer while preserving boolean rejection."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrafficApiInventoryError(f"{label} must be an integer")
    return int.__int__(value)


def _tuple_values(
    value: object, label: str, maximum_items: int | None = None,
) -> tuple:
    if not isinstance(value, tuple):
        raise TrafficApiInventoryError(f"{label} must be a tuple")
    if maximum_items is not None and tuple.__len__(value) > maximum_items:
        raise TrafficApiInventoryError(f"{label} exceeds the hard limit")
    return tuple(tuple.__iter__(value))


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise TrafficApiInventoryError(f"{label} is invalid")
    return value


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise TrafficApiInventoryError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise TrafficApiInventoryError(f"{label} must be a UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TrafficApiInventoryError(f"{label} is invalid") from exc


def _origin(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_ORIGIN_LENGTH
        or not value.isascii()
    ):
        raise TrafficApiInventoryError("origin is invalid")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TrafficApiInventoryError("origin is invalid") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.netloc != parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or value != f"https://{parts.hostname}"
    ):
        raise TrafficApiInventoryError("origin must be canonical HTTPS port 443")
    return value


def _path_shape(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 2048:
        raise TrafficApiInventoryError("path_shape is invalid")
    if value == "/":
        return value
    segments = value[1:].split("/")
    if any(
        segment in {"", ".", ".."}
        or not (_SEGMENT.fullmatch(segment) or _PARAMETER.fullmatch(segment))
        for segment in segments
    ):
        raise TrafficApiInventoryError("path_shape must contain redacted safe segments")
    return value


def _canonical_sha(domain: str, payload: object) -> str:
    encoded = json.dumps(
        {"domain": domain, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise TrafficApiInventoryError(f"{label} fields are invalid")
    return value


def _bounded_list(value: object, maximum: int, label: str) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TrafficApiInventoryError(f"{label} must be a bounded list")
    return value


@dataclass(frozen=True, slots=True)
class SanitizedApiTrafficObservation:
    """One caller-supplied event with no URL query, headers, body, or identity."""

    event_id: str
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    collector_id: str
    source_sha256: str
    observed_at: str
    origin: str
    method: str
    path_shape: str
    role_ref: str
    status_code: int
    observation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for label in ("event_id", "tenant_id", "context_id", "scope_id", "collector_id"):
            _identifier(getattr(self, label), label)
        _digest(self.context_sha256, "context_sha256")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.source_sha256, "source_sha256")
        _timestamp(self.observed_at, "observed_at")
        _origin(self.origin)
        _path_shape(self.path_shape)
        if not isinstance(self.method, str) or self.method not in {
            method.value for method in HttpMethod
        }:
            raise TrafficApiInventoryError("method is unsupported")
        if self.role_ref != "anonymous":
            if not isinstance(self.role_ref, str) or not self.role_ref.startswith("role:"):
                raise TrafficApiInventoryError("role_ref must be an opaque role reference")
            _identifier(self.role_ref, "role_ref")
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise TrafficApiInventoryError("status_code is invalid")
        object.__setattr__(
            self,
            "observation_sha256",
            _canonical_sha("sunderkey.sanitized-api-traffic-observation.v1", self.body()),
        )

    def body(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "collector_id": self.collector_id,
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at,
            "origin": self.origin,
            "method": self.method,
            "path_shape": self.path_shape,
            "role_ref": self.role_ref,
            "status_code": self.status_code,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.body(), "observation_sha256": self.observation_sha256}

    @classmethod
    def from_dict(cls, value: object) -> SanitizedApiTrafficObservation:
        raw = _exact_object(
            value,
            {
                "event_id", "tenant_id", "context_id", "context_sha256",
                "scope_id", "scope_sha256", "collector_id", "source_sha256",
                "observed_at", "origin", "method", "path_shape", "role_ref",
                "status_code", "observation_sha256",
            },
            "traffic observation",
        )
        item = cls(**{key: data for key, data in raw.items() if key != "observation_sha256"})
        if item.observation_sha256 != raw["observation_sha256"]:
            raise TrafficApiInventoryError("observation_sha256 does not match content")
        return item


def _verified_observation(
    value: SanitizedApiTrafficObservation,
) -> SanitizedApiTrafficObservation:
    """Capture declared fields and verify their supplied content address."""
    if not isinstance(value, SanitizedApiTrafficObservation):
        raise TrafficApiInventoryError("observation must be typed")
    supplied_sha = getattr(value, "observation_sha256", None)
    if type(supplied_sha) is not str:
        raise TrafficApiInventoryError("observation_sha256 must be a plain digest")
    _digest(supplied_sha, "observation_sha256")
    try:
        declared = {
            item.name: (
                _plain_integer(getattr(value, item.name), item.name)
                if item.name == "status_code"
                else _plain_string(getattr(value, item.name), item.name)
            )
            for item in fields(SanitizedApiTrafficObservation)
            if item.init
        }
    except AttributeError as exc:
        raise TrafficApiInventoryError("observation declared fields are incomplete") from exc
    reconstructed = SanitizedApiTrafficObservation(**declared)
    if supplied_sha != reconstructed.observation_sha256:
        raise TrafficApiInventoryError("observation_sha256 does not match content")
    return reconstructed


@dataclass(frozen=True, slots=True)
class TrafficApiEndpoint:
    origin: str
    method: str
    path_shape: str
    event_count: int
    role_refs: tuple[str, ...]
    status_codes: tuple[int, ...]
    first_observed_at: str
    last_observed_at: str
    source_sha256: tuple[str, ...]
    contract_state: str
    matching_contract_endpoint_sha256: tuple[str, ...]

    def __post_init__(self) -> None:
        _origin(self.origin)
        if not isinstance(self.method, str) or self.method not in {
            method.value for method in HttpMethod
        }:
            raise TrafficApiInventoryError("endpoint method is invalid")
        _path_shape(self.path_shape)
        if (
            isinstance(self.event_count, bool)
            or not isinstance(self.event_count, int)
            or not 1 <= self.event_count <= MAX_OBSERVATIONS
        ):
            raise TrafficApiInventoryError("endpoint event_count is invalid")
        if (
            not isinstance(self.role_refs, tuple)
            or not self.role_refs
            or not all(
                isinstance(role, str)
                and (role == "anonymous" or role.startswith("role:"))
                and _ID.fullmatch(role)
                for role in self.role_refs
            )
            or tuple(sorted(set(self.role_refs))) != self.role_refs
        ):
            raise TrafficApiInventoryError("endpoint role_refs are invalid")
        if (
            not isinstance(self.status_codes, tuple)
            or not self.status_codes
            or not all(isinstance(code, int) for code in self.status_codes)
            or tuple(sorted(set(self.status_codes))) != self.status_codes
        ):
            raise TrafficApiInventoryError("endpoint status_codes are invalid")
        if any(
            isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599
            for code in self.status_codes
        ):
            raise TrafficApiInventoryError("endpoint status_codes are invalid")
        first = _timestamp(self.first_observed_at, "first_observed_at")
        last = _timestamp(self.last_observed_at, "last_observed_at")
        if first > last:
            raise TrafficApiInventoryError("endpoint observation interval is invalid")
        if (
            not isinstance(self.source_sha256, tuple)
            or not self.source_sha256
            or not all(isinstance(value, str) for value in self.source_sha256)
            or tuple(sorted(set(self.source_sha256))) != self.source_sha256
        ):
            raise TrafficApiInventoryError("endpoint source digests are invalid")
        for digest in self.source_sha256:
            _digest(digest, "endpoint source digest")
        if not isinstance(self.contract_state, str) or self.contract_state not in {
            "documented",
            "ambiguous_template",
            "not_in_supplied_contract",
            "not_compared",
        }:
            raise TrafficApiInventoryError("endpoint contract_state is invalid")
        if (
            not isinstance(self.matching_contract_endpoint_sha256, tuple)
            or len(self.matching_contract_endpoint_sha256) > HARD_MAX_ENDPOINTS
            or not all(
                isinstance(value, str)
                for value in self.matching_contract_endpoint_sha256
            )
            or tuple(sorted(set(self.matching_contract_endpoint_sha256)))
            != self.matching_contract_endpoint_sha256
        ):
            raise TrafficApiInventoryError("endpoint contract matches are invalid")
        for digest in self.matching_contract_endpoint_sha256:
            _digest(digest, "matching contract endpoint")
        if (self.contract_state == "documented") != bool(
            self.matching_contract_endpoint_sha256
        ):
            raise TrafficApiInventoryError("documented state requires exact contract matches")

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "method": self.method,
            "path_shape": self.path_shape,
            "event_count": self.event_count,
            "role_refs": list(self.role_refs),
            "status_codes": list(self.status_codes),
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
            "source_sha256": list(self.source_sha256),
            "contract_state": self.contract_state,
            "matching_contract_endpoint_sha256": list(
                self.matching_contract_endpoint_sha256
            ),
        }

    @classmethod
    def from_dict(cls, value: object) -> TrafficApiEndpoint:
        raw = _exact_object(
            value,
            {
                "origin", "method", "path_shape", "event_count", "role_refs",
                "status_codes", "first_observed_at", "last_observed_at",
                "source_sha256", "contract_state",
                "matching_contract_endpoint_sha256",
            },
            "traffic endpoint",
        )
        return cls(
            origin=raw["origin"],
            method=raw["method"],
            path_shape=raw["path_shape"],
            event_count=raw["event_count"],
            role_refs=tuple(_bounded_list(raw["role_refs"], MAX_OBSERVATIONS, "role_refs")),
            status_codes=tuple(_bounded_list(raw["status_codes"], 500, "status_codes")),
            first_observed_at=raw["first_observed_at"],
            last_observed_at=raw["last_observed_at"],
            source_sha256=tuple(
                _bounded_list(raw["source_sha256"], MAX_OBSERVATIONS, "source_sha256")
            ),
            contract_state=raw["contract_state"],
            matching_contract_endpoint_sha256=tuple(
                _bounded_list(
                    raw["matching_contract_endpoint_sha256"],
                    HARD_MAX_ENDPOINTS,
                    "matching_contract_endpoint_sha256",
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class TrafficApiInventory:
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    snapshot_at: str
    maximum_age_seconds: int
    contract_bundle_sha256: str | None
    observation_sha256: tuple[str, ...]
    endpoints: tuple[TrafficApiEndpoint, ...]
    not_definitively_observed_contract_endpoint_sha256: tuple[str, ...]
    inventory_sha256: str

    def __post_init__(self) -> None:
        for label in ("tenant_id", "context_id", "scope_id"):
            _identifier(getattr(self, label), label)
        _digest(self.context_sha256, "context_sha256")
        _digest(self.scope_sha256, "scope_sha256")
        _timestamp(self.snapshot_at, "snapshot_at")
        if (
            isinstance(self.maximum_age_seconds, bool)
            or not isinstance(self.maximum_age_seconds, int)
            or not 1 <= self.maximum_age_seconds <= MAX_AGE_SECONDS
        ):
            raise TrafficApiInventoryError("maximum_age_seconds is invalid")
        if self.contract_bundle_sha256 is not None:
            _digest(self.contract_bundle_sha256, "contract_bundle_sha256")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > MAX_OBSERVATIONS
            or not all(isinstance(value, str) for value in self.observation_sha256)
            or tuple(sorted(set(self.observation_sha256))) != self.observation_sha256
        ):
            raise TrafficApiInventoryError("observation digests are invalid")
        for digest in self.observation_sha256:
            _digest(digest, "observation digest")
        if (
            not isinstance(self.endpoints, tuple)
            or len(self.endpoints) > MAX_ENDPOINTS
            or not all(isinstance(item, TrafficApiEndpoint) for item in self.endpoints)
        ):
            raise TrafficApiInventoryError("endpoints are invalid")
        if sum(
            len(item.matching_contract_endpoint_sha256) for item in self.endpoints
        ) > MAX_TOTAL_CONTRACT_MATCHES:
            raise TrafficApiInventoryError("contract match count exceeds the hard limit")
        keys = tuple((item.origin, item.method, item.path_shape) for item in self.endpoints)
        if tuple(sorted(set(keys))) != keys:
            raise TrafficApiInventoryError("endpoint order or identity is invalid")
        if sum(item.event_count for item in self.endpoints) != len(self.observation_sha256):
            raise TrafficApiInventoryError("event coverage does not match endpoint counts")
        if self.contract_bundle_sha256 is None and any(
            item.contract_state != "not_compared" for item in self.endpoints
        ):
            raise TrafficApiInventoryError("contract comparison requires a bundle")
        unmatched = self.not_definitively_observed_contract_endpoint_sha256
        if (
            not isinstance(unmatched, tuple)
            or len(unmatched) > HARD_MAX_ENDPOINTS
            or not all(isinstance(value, str) for value in unmatched)
            or tuple(sorted(set(unmatched))) != unmatched
            or (self.contract_bundle_sha256 is None and unmatched)
        ):
            raise TrafficApiInventoryError("unmatched contract endpoints are invalid")
        for digest in unmatched:
            _digest(digest, "unmatched contract endpoint")
        matched = {
            digest
            for item in self.endpoints
            for digest in item.matching_contract_endpoint_sha256
        }
        if matched.intersection(unmatched):
            raise TrafficApiInventoryError("contract endpoint is both matched and unmatched")
        payload = {
            "tenant_id": self.tenant_id,
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "snapshot_at": self.snapshot_at,
            "maximum_age_seconds": self.maximum_age_seconds,
            "contract_bundle_sha256": self.contract_bundle_sha256,
            "observation_sha256": list(self.observation_sha256),
            "endpoints": [item.to_dict() for item in self.endpoints],
            "not_definitively_observed_contract_endpoint_sha256": list(unmatched),
        }
        expected = _canonical_sha("sunderkey.traffic-api-inventory.v1", payload)
        if self.inventory_sha256 != expected:
            raise TrafficApiInventoryError("inventory_sha256 does not match content")

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "snapshot_at": self.snapshot_at,
            "maximum_age_seconds": self.maximum_age_seconds,
            "contract_bundle_sha256": self.contract_bundle_sha256,
            "observation_sha256": list(self.observation_sha256),
            "endpoints": [item.to_dict() for item in self.endpoints],
            "not_definitively_observed_contract_endpoint_sha256": list(
                self.not_definitively_observed_contract_endpoint_sha256
            ),
            "inventory_sha256": self.inventory_sha256,
            "authority_effect": AUTHORITY_EFFECT,
            "qualification_effect": QUALIFICATION_EFFECT,
            "network_call_performed": NETWORK_CALL_PERFORMED,
        }

    @classmethod
    def from_dict(cls, value: object) -> TrafficApiInventory:
        raw = _exact_object(
            value,
            {
                "tenant_id", "context_id", "context_sha256", "scope_id",
                "scope_sha256", "snapshot_at", "maximum_age_seconds",
                "contract_bundle_sha256", "observation_sha256", "endpoints",
                "not_definitively_observed_contract_endpoint_sha256",
                "inventory_sha256", "authority_effect", "qualification_effect",
                "network_call_performed",
            },
            "traffic inventory",
        )
        if (
            raw["authority_effect"] != AUTHORITY_EFFECT
            or raw["qualification_effect"] != QUALIFICATION_EFFECT
            or raw["network_call_performed"] is not NETWORK_CALL_PERFORMED
        ):
            raise TrafficApiInventoryError("traffic inventory effects are invalid")
        return cls(
            tenant_id=raw["tenant_id"],
            context_id=raw["context_id"],
            context_sha256=raw["context_sha256"],
            scope_id=raw["scope_id"],
            scope_sha256=raw["scope_sha256"],
            snapshot_at=raw["snapshot_at"],
            maximum_age_seconds=raw["maximum_age_seconds"],
            contract_bundle_sha256=raw["contract_bundle_sha256"],
            observation_sha256=tuple(
                _bounded_list(raw["observation_sha256"], MAX_OBSERVATIONS, "observations")
            ),
            endpoints=tuple(
                TrafficApiEndpoint.from_dict(item)
                for item in _bounded_list(raw["endpoints"], MAX_ENDPOINTS, "endpoints")
            ),
            not_definitively_observed_contract_endpoint_sha256=tuple(
                _bounded_list(
                    raw["not_definitively_observed_contract_endpoint_sha256"],
                    HARD_MAX_ENDPOINTS,
                    "unobserved contract endpoints",
                )
            ),
            inventory_sha256=raw["inventory_sha256"],
        )


def load_traffic_api_inventory_json(raw: bytes) -> TrafficApiInventory:
    """Load a bounded UTF-8 archive with no duplicate keys or unknown fields."""

    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INVENTORY_JSON_BYTES:
        raise TrafficApiInventoryError("traffic inventory JSON exceeds the byte limit")

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise TrafficApiInventoryError("traffic inventory JSON repeats a key")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise TrafficApiInventoryError("traffic inventory JSON has a nonfinite value")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except TrafficApiInventoryError:
        raise
    except (ValueError, RecursionError) as exc:
        raise TrafficApiInventoryError("traffic inventory JSON is invalid") from exc
    return TrafficApiInventory.from_dict(value)


def _owned_endpoint(value: TrafficApiEndpoint) -> TrafficApiEndpoint:
    if not isinstance(value, TrafficApiEndpoint):
        raise TrafficApiInventoryError("endpoint must be typed")
    try:
        declared = {item.name: getattr(value, item.name) for item in fields(TrafficApiEndpoint)}
    except AttributeError as exc:
        raise TrafficApiInventoryError("endpoint declared fields are incomplete") from exc
    for name in (
        "origin", "method", "path_shape", "first_observed_at", "last_observed_at",
        "contract_state",
    ):
        declared[name] = _plain_string(declared[name], name)
    declared["event_count"] = _plain_integer(declared["event_count"], "event_count")
    for name in ("role_refs", "source_sha256", "matching_contract_endpoint_sha256"):
        declared[name] = tuple(
            _plain_string(item, name) for item in _tuple_values(declared[name], name)
        )
    declared["status_codes"] = tuple(
        _plain_integer(item, "status_codes")
        for item in _tuple_values(declared["status_codes"], "status_codes")
    )
    return TrafficApiEndpoint(**declared)


def _verified_inventory(value: TrafficApiInventory) -> TrafficApiInventory:
    """Own declared scalar metadata and validate the unchanged supplied digest."""
    if not isinstance(value, TrafficApiInventory):
        raise TrafficApiInventoryError("inventory must be typed")
    try:
        declared = {item.name: getattr(value, item.name) for item in fields(TrafficApiInventory)}
    except AttributeError as exc:
        raise TrafficApiInventoryError("inventory declared fields are incomplete") from exc
    for name in (
        "tenant_id", "context_id", "context_sha256", "scope_id", "scope_sha256",
        "snapshot_at", "inventory_sha256",
    ):
        declared[name] = _plain_string(declared[name], name)
    declared["maximum_age_seconds"] = _plain_integer(
        declared["maximum_age_seconds"], "maximum_age_seconds"
    )
    if declared["contract_bundle_sha256"] is not None:
        declared["contract_bundle_sha256"] = _plain_string(
            declared["contract_bundle_sha256"], "contract_bundle_sha256"
        )
    for name in (
        "observation_sha256", "not_definitively_observed_contract_endpoint_sha256",
    ):
        maximum = MAX_OBSERVATIONS if name == "observation_sha256" else None
        declared[name] = tuple(
            _plain_string(item, name)
            for item in _tuple_values(declared[name], name, maximum)
        )
    declared["endpoints"] = tuple(
        _owned_endpoint(item)
        for item in _tuple_values(declared["endpoints"], "endpoints", MAX_ENDPOINTS)
    )
    return TrafficApiInventory(**declared)


def _template_relation(observed: str, contract: str) -> str:
    observed_segments = observed.strip("/").split("/")
    contract_segments = contract.strip("/").split("/")
    if len(observed_segments) != len(contract_segments):
        return "no_match"
    ambiguous = False
    for left, right in zip(observed_segments, contract_segments, strict=True):
        if left == right or _PARAMETER.fullmatch(right):
            continue
        if "{" in right or "}" in right:
            ambiguous = True
            continue
        if _PARAMETER.fullmatch(left):
            ambiguous = True
        else:
            return "no_match"
    return "ambiguous" if ambiguous else "match"


def _contract_state(
    *,
    path_shape: str,
    contract_present: bool,
    candidates: tuple[tuple[str, str], ...],
) -> tuple[str, tuple[str, ...]]:
    if not contract_present:
        return "not_compared", ()
    matches: set[str] = set()
    ambiguous = False
    for contract_path, endpoint_sha256 in candidates:
        relation = _template_relation(path_shape, contract_path)
        if relation == "match":
            matches.add(endpoint_sha256)
        elif relation == "ambiguous":
            ambiguous = True
    if matches:
        return "documented", tuple(sorted(matches))
    if ambiguous:
        return "ambiguous_template", ()
    return "not_in_supplied_contract", ()


def build_traffic_api_inventory(
    *,
    observations: tuple[SanitizedApiTrafficObservation, ...],
    tenant_id: str,
    context_id: str,
    context_sha256: str,
    scope_id: str,
    scope_sha256: str,
    snapshot_at: str,
    contract_bundle: ServiceContractEndpointBundle | None = None,
    maximum_age_seconds: int = 7 * 24 * 60 * 60,
) -> TrafficApiInventory:
    """Reconcile exact metadata without granting a release or target action."""

    observations = _tuple_values(observations, "observations", MAX_OBSERVATIONS)
    tenant_id = _plain_string(tenant_id, "tenant_id")
    context_id = _plain_string(context_id, "context_id")
    context_sha256 = _plain_string(context_sha256, "context_sha256")
    scope_id = _plain_string(scope_id, "scope_id")
    scope_sha256 = _plain_string(scope_sha256, "scope_sha256")
    snapshot_at = _plain_string(snapshot_at, "snapshot_at")
    maximum_age_seconds = _plain_integer(maximum_age_seconds, "maximum_age_seconds")
    for label, value in (
        ("tenant_id", tenant_id),
        ("context_id", context_id),
        ("scope_id", scope_id),
    ):
        _identifier(value, label)
    _digest(context_sha256, "context_sha256")
    _digest(scope_sha256, "scope_sha256")
    snapshot_time = _timestamp(snapshot_at, "snapshot_at")
    if (
        not isinstance(observations, tuple)
        or len(observations) > MAX_OBSERVATIONS
        or not all(isinstance(item, SanitizedApiTrafficObservation) for item in observations)
    ):
        raise TrafficApiInventoryError("observations exceed the closed input contract")
    if (
        isinstance(maximum_age_seconds, bool)
        or not isinstance(maximum_age_seconds, int)
        or not 1 <= maximum_age_seconds <= MAX_AGE_SECONDS
    ):
        raise TrafficApiInventoryError("maximum_age_seconds is invalid")
    if contract_bundle is not None:
        if not isinstance(contract_bundle, ServiceContractEndpointBundle):
            raise TrafficApiInventoryError("contract_bundle is invalid")
        try:
            validated_bundle = ServiceContractEndpointBundle.from_dict(contract_bundle.to_dict())
        except (ServiceContractExtractionError, ValueError, TypeError) as exc:
            raise TrafficApiInventoryError("contract_bundle integrity is invalid") from exc
        if validated_bundle != contract_bundle:
            raise TrafficApiInventoryError("contract_bundle integrity is invalid")
        if contract_bundle.document_kind not in {"openapi", "swagger"}:
            raise TrafficApiInventoryError("only HTTP API contracts can be compared")

    by_event: dict[str, SanitizedApiTrafficObservation] = {}
    for supplied in observations:
        item = _verified_observation(supplied)
        if (
            item.tenant_id,
            item.context_id,
            item.context_sha256,
            item.scope_id,
            item.scope_sha256,
        ) != (
            tenant_id,
            context_id,
            context_sha256,
            scope_id,
            scope_sha256,
        ):
            raise TrafficApiInventoryError("cross-boundary traffic observation")
        age = (snapshot_time - _timestamp(item.observed_at, "observed_at")).total_seconds()
        if not 0 <= age <= maximum_age_seconds:
            raise TrafficApiInventoryError("traffic observation is future or stale")
        prior = by_event.get(item.event_id)
        if prior is not None and prior.observation_sha256 != item.observation_sha256:
            raise TrafficApiInventoryError("conflicting traffic event identity")
        by_event[item.event_id] = item

    by_endpoint: dict[tuple[str, str, str], list[SanitizedApiTrafficObservation]] = defaultdict(
        list
    )
    for item in by_event.values():
        by_endpoint[item.origin, item.method, item.path_shape].append(item)
    if len(by_endpoint) > MAX_ENDPOINTS:
        raise TrafficApiInventoryError("endpoint count exceeds the hard limit")
    contract_index: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    if contract_bundle is not None:
        for endpoint in contract_bundle.endpoints:
            address = urlsplit(endpoint.address)
            contract_origin = f"{address.scheme}://{address.netloc}"
            contract_index[contract_origin, endpoint.method].append(
                (address.path or "/", endpoint.endpoint_sha256)
            )
    endpoints: list[TrafficApiEndpoint] = []
    matched_contract: set[str] = set()
    match_count = 0
    for (origin, method, path_shape), items in sorted(by_endpoint.items()):
        state, matches = _contract_state(
            path_shape=path_shape,
            contract_present=contract_bundle is not None,
            candidates=tuple(contract_index.get((origin, method), ())),
        )
        match_count += len(matches)
        if match_count > MAX_TOTAL_CONTRACT_MATCHES:
            raise TrafficApiInventoryError("contract match count exceeds the hard limit")
        matched_contract.update(matches)
        endpoints.append(
            TrafficApiEndpoint(
                origin=origin,
                method=method,
                path_shape=path_shape,
                event_count=len(items),
                role_refs=tuple(sorted({item.role_ref for item in items})),
                status_codes=tuple(sorted({item.status_code for item in items})),
                first_observed_at=min(item.observed_at for item in items),
                last_observed_at=max(item.observed_at for item in items),
                source_sha256=tuple(sorted({item.source_sha256 for item in items})),
                contract_state=state,
                matching_contract_endpoint_sha256=matches,
            )
        )
    unobserved = (
        tuple(
            sorted(
                endpoint.endpoint_sha256
                for endpoint in contract_bundle.endpoints
                if endpoint.endpoint_sha256 not in matched_contract
            )
        )
        if contract_bundle is not None
        else ()
    )
    payload = {
        "tenant_id": tenant_id,
        "context_id": context_id,
        "context_sha256": context_sha256,
        "scope_id": scope_id,
        "scope_sha256": scope_sha256,
        "snapshot_at": snapshot_at,
        "maximum_age_seconds": maximum_age_seconds,
        "contract_bundle_sha256": (
            contract_bundle.bundle_sha256 if contract_bundle is not None else None
        ),
        "observation_sha256": sorted(
            item.observation_sha256 for item in by_event.values()
        ),
        "endpoints": [item.to_dict() for item in endpoints],
        "not_definitively_observed_contract_endpoint_sha256": list(unobserved),
    }
    return TrafficApiInventory(
        tenant_id=tenant_id,
        context_id=context_id,
        context_sha256=context_sha256,
        scope_id=scope_id,
        scope_sha256=scope_sha256,
        snapshot_at=snapshot_at,
        maximum_age_seconds=maximum_age_seconds,
        contract_bundle_sha256=payload["contract_bundle_sha256"],
        observation_sha256=tuple(payload["observation_sha256"]),
        endpoints=tuple(endpoints),
        not_definitively_observed_contract_endpoint_sha256=unobserved,
        inventory_sha256=_canonical_sha("sunderkey.traffic-api-inventory.v1", payload),
    )


def verify_traffic_api_inventory_from_sources(
    inventory: TrafficApiInventory,
    *,
    observations: tuple[SanitizedApiTrafficObservation, ...],
    contract_bundle: ServiceContractEndpointBundle | None = None,
) -> TrafficApiInventory:
    """Replay a stored inventory from supplied sanitized traffic and contract evidence."""

    inventory = _verified_inventory(inventory)
    expected = build_traffic_api_inventory(
        observations=observations,
        tenant_id=inventory.tenant_id,
        context_id=inventory.context_id,
        context_sha256=inventory.context_sha256,
        scope_id=inventory.scope_id,
        scope_sha256=inventory.scope_sha256,
        snapshot_at=inventory.snapshot_at,
        contract_bundle=contract_bundle,
        maximum_age_seconds=inventory.maximum_age_seconds,
    )
    if expected != inventory:
        raise TrafficApiInventoryError("traffic inventory does not match source replay")
    return inventory
