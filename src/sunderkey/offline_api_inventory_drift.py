"""Bounded offline comparison of supplied API inventory and route manifest."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S14"
CAPABILITY_ID = "army.gb.d06.s14"
VECTOR_ID = "AV-GB-D06-S14-01"
DOMAIN = "sunderkey.offline-api-inventory-drift.v1"
ANALYSIS_PROFILE = "supplied-canonical-route-inventory-v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_DEPTH = 24
MAX_NODES = 50_000
MAX_APIS = 64
MAX_ROUTES_PER_API = 64
MAX_INVENTORY_ROUTES = 1_024
MAX_MANIFEST_ROUTES = 1_024
MAX_DEPLOYMENTS = 128
_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_VERSION = re.compile(r"v[1-9][0-9]{0,5}\Z")
_PATH = re.compile(r"/[A-Za-z0-9._~/-]*\Z")
_METHODS = frozenset(("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
_LIFECYCLES = frozenset(("current", "legacy", "retired"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class ApiInventoryDriftError(ValueError):
    """Invalid, unsupported, or over-budget supplied inventory evidence."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ApiInventoryDriftError(f"{label} must have exact native fields")
    return value


def _match(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ApiInventoryDriftError(f"{label} must be canonical bounded text")
    return value


def _method(value: Any) -> str:
    if type(value) is not str or value not in _METHODS:
        raise ApiInventoryDriftError("Unsupported canonical method")
    return value


def _path(value: Any) -> str:
    if type(value) is not str or len(value) > 256 or _PATH.fullmatch(value) is None:
        raise ApiInventoryDriftError("Path must be a bounded literal ASCII path")
    if (
        "//" in value
        or "\\" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise ApiInventoryDriftError("Path normalization or traversal is unsupported")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ApiInventoryDriftError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ApiInventoryDriftError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise ApiInventoryDriftError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ApiInventoryDriftError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise ApiInventoryDriftError("Invalid Unicode scalar text") from exc
            if len(encoded) > MAX_MODEL_BYTES:
                raise ApiInventoryDriftError("Native string exceeds bound")
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise ApiInventoryDriftError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise ApiInventoryDriftError("Unsupported native primitive")
        if size > 12 * maximum:
            raise ApiInventoryDriftError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise ApiInventoryDriftError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ApiInventoryDriftError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise ApiInventoryDriftError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise ApiInventoryDriftError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise ApiInventoryDriftError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise ApiInventoryDriftError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ApiInventoryDriftError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise ApiInventoryDriftError(f"{label} exceeds byte limit")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ApiInventoryDriftError("JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ApiInventoryDriftError):
            raise
        raise ApiInventoryDriftError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _inventory(value: Any) -> tuple[str, str, bool, dict[tuple[str, str, str, str], str]]:
    inventory = _exact(value, {"source_id", "scope_id", "complete", "apis"}, "inventory")
    source_id = _match(inventory["source_id"], _ID, "inventory source_id")
    scope_id = _match(inventory["scope_id"], _ID, "inventory scope_id")
    complete = inventory["complete"]
    if type(complete) is not bool:
        raise ApiInventoryDriftError("Inventory completeness must be a native boolean")
    apis = inventory["apis"]
    if type(apis) is not list or len(apis) > MAX_APIS:
        raise ApiInventoryDriftError("Inventory APIs must be a bounded list")
    identities = set()
    route_map: dict[tuple[str, str, str, str], str] = {}
    total_routes = 0
    for raw in apis:
        api = _exact(raw, {"api_id", "version", "lifecycle", "routes"}, "inventory API")
        api_id = _match(api["api_id"], _ID, "api_id")
        version = _match(api["version"], _VERSION, "API version")
        if type(api["lifecycle"]) is not str or api["lifecycle"] not in _LIFECYCLES:
            raise ApiInventoryDriftError("Unsupported declared lifecycle")
        identity = (api_id, version)
        if identity in identities:
            raise ApiInventoryDriftError("Duplicate API identity")
        identities.add(identity)
        routes = api["routes"]
        if type(routes) is not list or len(routes) > MAX_ROUTES_PER_API:
            raise ApiInventoryDriftError("Inventory routes must be a bounded list")
        total_routes += len(routes)
        if total_routes > MAX_INVENTORY_ROUTES:
            raise ApiInventoryDriftError("Inventory route limit exceeded")
        for raw_route in routes:
            route = _exact(raw_route, {"method", "path"}, "inventory route")
            method = _method(route["method"])
            path = _path(route["path"])
            key = (api_id, version, method, path)
            if key in route_map:
                raise ApiInventoryDriftError("Duplicate canonical inventory route")
            route_map[key] = api["lifecycle"]
    return source_id, scope_id, complete, route_map


def _manifest(value: Any) -> tuple[str, str, bool, dict[str, bool], list[dict[str, Any]]]:
    manifest = _exact(
        value,
        {"source_id", "scope_id", "complete", "deployments", "routes"},
        "route manifest",
    )
    source_id = _match(manifest["source_id"], _ID, "manifest source_id")
    scope_id = _match(manifest["scope_id"], _ID, "manifest scope_id")
    complete = manifest["complete"]
    if type(complete) is not bool:
        raise ApiInventoryDriftError("Manifest completeness must be a native boolean")
    raw_deployments = manifest["deployments"]
    if type(raw_deployments) is not list or len(raw_deployments) > MAX_DEPLOYMENTS:
        raise ApiInventoryDriftError("Deployments must be a bounded list")
    deployments = {}
    for raw in raw_deployments:
        deployment = _exact(raw, {"deployment_id", "active"}, "deployment")
        deployment_id = _match(deployment["deployment_id"], _ID, "deployment_id")
        if deployment_id in deployments or type(deployment["active"]) is not bool:
            raise ApiInventoryDriftError("Duplicate deployment or invalid active flag")
        deployments[deployment_id] = deployment["active"]
    raw_routes = manifest["routes"]
    if type(raw_routes) is not list or len(raw_routes) > MAX_MANIFEST_ROUTES:
        raise ApiInventoryDriftError("Manifest routes must be a bounded list")
    route_ids = set()
    predicates = set()
    for raw in raw_routes:
        route = _exact(
            raw,
            {
                "route_id",
                "deployment_ref",
                "api_id",
                "version",
                "method",
                "path",
                "enabled",
            },
            "manifest route",
        )
        route_id = _match(route["route_id"], _ID, "route_id")
        deployment_ref = _match(route["deployment_ref"], _ID, "deployment_ref")
        if deployment_ref not in deployments:
            raise ApiInventoryDriftError("Route references unknown deployment")
        api_id = _match(route["api_id"], _ID, "route api_id")
        version = _match(route["version"], _VERSION, "route version")
        method = _method(route["method"])
        path = _path(route["path"])
        if type(route["enabled"]) is not bool:
            raise ApiInventoryDriftError("Route enabled flag must be a native boolean")
        predicate = (deployment_ref, api_id, version, method, path)
        if route_id in route_ids or predicate in predicates:
            raise ApiInventoryDriftError("Duplicate manifest route identity or predicate")
        route_ids.add(route_id)
        predicates.add(predicate)
    return source_id, scope_id, complete, deployments, raw_routes


def _projection(model: Any) -> dict[str, Any]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "approved_inventory", "route_manifest"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ApiInventoryDriftError("Unsupported schema version")
    source_id = _match(document["source_id"], _ID, "model source_id")
    inventory_id, inventory_scope, inventory_complete, inventory_routes = _inventory(
        document["approved_inventory"]
    )
    manifest_id, manifest_scope, manifest_complete, deployments, manifest_routes = _manifest(
        document["route_manifest"]
    )
    if len({source_id, inventory_id, manifest_id}) != 3:
        raise ApiInventoryDriftError("Source identifiers must be distinct")
    source_ready = inventory_complete and manifest_complete and inventory_scope == manifest_scope
    rows = []
    undeclared = []
    legacy = []
    unknowns = []
    for route in sorted(manifest_routes, key=lambda item: item["route_id"]):
        route_id = route["route_id"]
        active = route["enabled"] and deployments[route["deployment_ref"]]
        if not active:
            disposition = "excluded_by_supplied_inactive_state"
        elif not source_ready:
            disposition = "unknown_source_scope_or_completeness"
            reason = (
                "source_scope_mismatch"
                if inventory_scope != manifest_scope
                else "source_incomplete"
            )
            unknowns.append({"route_id": route_id, "reason": reason})
        else:
            key = (route["api_id"], route["version"], route["method"], route["path"])
            lifecycle = inventory_routes.get(key)
            if lifecycle is None:
                disposition = "undeclared_route_candidate"
                undeclared.append(
                    {
                        "route_id": route_id,
                        "deployment_ref": route["deployment_ref"],
                        "api_id": route["api_id"],
                        "version": route["version"],
                        "method": route["method"],
                        "path": route["path"],
                    }
                )
            elif lifecycle in {"legacy", "retired"}:
                disposition = "legacy_route_candidate"
                legacy.append(
                    {
                        "route_id": route_id,
                        "deployment_ref": route["deployment_ref"],
                        "api_id": route["api_id"],
                        "version": route["version"],
                        "method": route["method"],
                        "path": route["path"],
                        "declared_lifecycle": lifecycle,
                    }
                )
            else:
                disposition = "declared_current_route"
        rows.append({"route_id": route_id, "disposition": disposition})
    if not source_ready and not unknowns:
        reason = (
            "source_scope_mismatch" if inventory_scope != manifest_scope else "source_incomplete"
        )
        unknowns.append({"route_id": None, "reason": reason})
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": source_id,
            "model_sha256": _sha(model_text),
            "approved_inventory": {
                "source_id": inventory_id,
                "sha256": _sha(_canonical(document["approved_inventory"], maximum=MAX_MODEL_BYTES)),
            },
            "route_manifest": {
                "source_id": manifest_id,
                "sha256": _sha(_canonical(document["route_manifest"], maximum=MAX_MODEL_BYTES)),
            },
        },
        "supplied_model": model,
        "analysis_status": (
            "complete_matching_scope_projection" if source_ready else "unknown_source_premises"
        ),
        "route_outcomes": rows,
        "undeclared_route_candidates": undeclared,
        "legacy_route_candidates": legacy,
        "unknowns": unknowns,
        "uncertainty": [
            "Inventory, deployment state, completeness, and scope are caller declarations.",
            "Identifiers and versions are exact canonical strings, not discovered endpoints.",
            "No routing, exposure, reachability, or effective access is verified.",
            "Candidates are supplied-record discrepancies, not live shadow-API findings.",
        ],
        "offline_only": True,
        "live_shadow_api_verified": False,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "AID-" + digest[:32].upper()
    report["report_sha256"] = "sha256:" + digest
    _canonical(report, maximum=MAX_REPORT_BYTES)
    return report


_REPORT_FIELDS = {
    "schema_version",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "source",
    "supplied_model",
    "analysis_status",
    "route_outcomes",
    "undeclared_route_candidates",
    "legacy_route_candidates",
    "unknowns",
    "uncertainty",
    "offline_only",
    "live_shadow_api_verified",
    "effects",
    "report_id",
    "report_sha256",
}


def _replay(document: Any) -> str:
    _exact(document, _REPORT_FIELDS, "report")
    expected = _projection(document["supplied_model"])
    if document != expected:
        raise ApiInventoryDriftError("Report does not replay supplied model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> ApiInventoryDriftReport:
    report = object.__new__(ApiInventoryDriftReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class ApiInventoryDriftReport:
    """Detached unsigned inventory projection retaining its supplied model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ApiInventoryDriftReport:
            raise ApiInventoryDriftError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> ApiInventoryDriftReport:
        if cls is not ApiInventoryDriftReport:
            raise ApiInventoryDriftError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> ApiInventoryDriftReport:
        if cls is not ApiInventoryDriftReport or type(value) is not str:
            raise ApiInventoryDriftError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise ApiInventoryDriftError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ApiInventoryDriftReport or type(self.document_json) is not str:
            raise ApiInventoryDriftError("Exact native report wrapper required")
        return ApiInventoryDriftReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_api_inventory_drift(model: Any) -> ApiInventoryDriftReport:
    """Compare only supplied approved inventory and route manifest sources."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_api_inventory_drift_bytes(*, model_bytes: Any) -> ApiInventoryDriftReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ApiInventoryDriftError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiInventoryDriftError("Model bytes must be UTF-8") from exc
    return analyze_supplied_api_inventory_drift(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_api_inventory_drift(report: Any, *, model: Any) -> ApiInventoryDriftReport:
    if type(report) is not ApiInventoryDriftReport:
        raise ApiInventoryDriftError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise ApiInventoryDriftError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic inventory and route records without any URL."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-api-drift",
        "approved_inventory": {
            "source_id": "approved-inventory",
            "scope_id": "test-scope",
            "complete": True,
            "apis": [
                {
                    "api_id": "orders",
                    "version": "v2",
                    "lifecycle": "current",
                    "routes": [{"method": "GET", "path": "/orders"}],
                },
                {
                    "api_id": "orders",
                    "version": "v1",
                    "lifecycle": "legacy",
                    "routes": [{"method": "GET", "path": "/orders"}],
                },
            ],
        },
        "route_manifest": {
            "source_id": "deployment-routes",
            "scope_id": "test-scope",
            "complete": True,
            "deployments": [{"deployment_id": "synthetic-deployment", "active": True}],
            "routes": [
                {
                    "route_id": "orders-current",
                    "deployment_ref": "synthetic-deployment",
                    "api_id": "orders",
                    "version": "v2",
                    "method": "GET",
                    "path": "/orders",
                    "enabled": True,
                },
                {
                    "route_id": "orders-legacy",
                    "deployment_ref": "synthetic-deployment",
                    "api_id": "orders",
                    "version": "v1",
                    "method": "GET",
                    "path": "/orders",
                    "enabled": True,
                },
                {
                    "route_id": "orders-undeclared",
                    "deployment_ref": "synthetic-deployment",
                    "api_id": "orders",
                    "version": "v3",
                    "method": "GET",
                    "path": "/orders",
                    "enabled": True,
                },
            ],
        },
    }


__all__ = [
    "ApiInventoryDriftError",
    "ApiInventoryDriftReport",
    "analyze_supplied_api_inventory_drift",
    "analyze_supplied_api_inventory_drift_bytes",
    "verify_supplied_api_inventory_drift",
    "component_fixture",
]
