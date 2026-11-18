"""Finite offline projection of supplied API gateway route declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S07"
CAPABILITY_ID = "army.gb.d06.s07"
VECTOR_ID = "AV-GB-D06-S07-01"
DOMAIN = "sunderkey.offline-api-gateway-routes.v1"
ANALYSIS_PROFILE = "supplied-exact-literal-prefix-priority.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 1_048_576
MAX_DEPTH = 24
MAX_NODES = 50_000
MAX_ROUTES = 64
MAX_REQUESTS = 128
MAX_REFERENCES = 128
MAX_CANDIDATES = 2_016
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/[A-Za-z0-9._~/-]*\Z")
_METHODS = frozenset(("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class ApiGatewayRoutesError(ValueError):
    """Invalid, unsupported, or over-budget supplied route source or report."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ApiGatewayRoutesError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ApiGatewayRoutesError(f"{label} must be a bounded native identifier")
    return value


def _host(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 253:
        raise ApiGatewayRoutesError("Host must be a lower-case literal name without port")
    if any(_HOST_LABEL.fullmatch(label) is None for label in value.split(".")):
        raise ApiGatewayRoutesError("Host normalization is unsupported")
    return value


def _path(value: Any) -> str:
    if type(value) is not str or len(value) > 256 or _PATH.fullmatch(value) is None:
        raise ApiGatewayRoutesError("Path must be a bounded literal ASCII path")
    if (
        "//" in value
        or "\\" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise ApiGatewayRoutesError("Path normalization or traversal is unsupported")
    return value


def _method(value: Any) -> str:
    if type(value) is not str or value not in _METHODS:
        raise ApiGatewayRoutesError("Unsupported literal method")
    return value


def _integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ApiGatewayRoutesError(f"{label} must be a bounded native integer")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ApiGatewayRoutesError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ApiGatewayRoutesError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise ApiGatewayRoutesError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ApiGatewayRoutesError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise ApiGatewayRoutesError("Invalid Unicode scalar text") from exc
            if len(encoded) > MAX_MODEL_BYTES:
                raise ApiGatewayRoutesError("Native string exceeds bound")
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise ApiGatewayRoutesError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise ApiGatewayRoutesError("Unsupported native primitive")
        if size > 12 * maximum:
            raise ApiGatewayRoutesError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise ApiGatewayRoutesError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ApiGatewayRoutesError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise ApiGatewayRoutesError("JSON integer exceeds bound")
    value = int(text)
    if value.bit_length() > 63:
        raise ApiGatewayRoutesError("JSON integer exceeds bound")
    return value


def _unsupported_number(_text: str) -> None:
    raise ApiGatewayRoutesError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise ApiGatewayRoutesError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ApiGatewayRoutesError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise ApiGatewayRoutesError(f"{label} exceeds byte limit")
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
                raise ApiGatewayRoutesError("JSON depth limit exceeded")
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
        if isinstance(exc, ApiGatewayRoutesError):
            raise
        raise ApiGatewayRoutesError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _reference_list(value: Any, label: str) -> set[str]:
    if type(value) is not list or not value or len(value) > MAX_REFERENCES:
        raise ApiGatewayRoutesError(f"{label} must be a bounded nonempty list")
    result = set()
    for item in value:
        name = _identifier(item, label)
        if name in result:
            raise ApiGatewayRoutesError(f"Duplicate {label} identity")
        result.add(name)
    return result


def _route(value: Any, backends: set[str], policies: set[str]) -> dict[str, Any]:
    route = _exact(
        value,
        {
            "route_id",
            "host",
            "method",
            "path_kind",
            "path",
            "priority",
            "backend_ref",
            "auth_policy_ref",
        },
        "route",
    )
    _identifier(route["route_id"], "route_id")
    _host(route["host"])
    _method(route["method"])
    if type(route["path_kind"]) is not str or route["path_kind"] not in {"exact", "literal_prefix"}:
        raise ApiGatewayRoutesError("Unsupported route path kind")
    _path(route["path"])
    _integer(route["priority"], "priority", 10_000)
    if _identifier(route["backend_ref"], "backend_ref") not in backends:
        raise ApiGatewayRoutesError("Unknown backend reference")
    if _identifier(route["auth_policy_ref"], "auth_policy_ref") not in policies:
        raise ApiGatewayRoutesError("Unknown auth-policy reference")
    return route


def _request(value: Any) -> dict[str, Any]:
    request = _exact(value, {"request_id", "host", "method", "path"}, "request probe")
    _identifier(request["request_id"], "request_id")
    _host(request["host"])
    _method(request["method"])
    _path(request["path"])
    return request


def _model(value: Any) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    model = _exact(value, {"schema_version", "source_id", "route_table", "probes"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ApiGatewayRoutesError("Unsupported schema version")
    source_id = _identifier(model["source_id"], "model source_id")
    table = _exact(
        model["route_table"],
        {
            "source_id",
            "normalization",
            "rewrite",
            "order",
            "backends",
            "auth_policies",
            "routes",
        },
        "route table",
    )
    table_id = _identifier(table["source_id"], "route table source_id")
    if table["normalization"] != "none" or type(table["normalization"]) is not str:
        raise ApiGatewayRoutesError("Gateway normalization is unsupported")
    if table["rewrite"] != "none" or type(table["rewrite"]) is not str:
        raise ApiGatewayRoutesError("Gateway rewrite is unsupported")
    if table["order"] != "priority_desc_then_declaration" or type(table["order"]) is not str:
        raise ApiGatewayRoutesError("Unsupported route order")
    backends = _reference_list(table["backends"], "backend")
    policies = _reference_list(table["auth_policies"], "auth policy")
    raw_routes = table["routes"]
    if type(raw_routes) is not list or not raw_routes or len(raw_routes) > MAX_ROUTES:
        raise ApiGatewayRoutesError("Routes must be a bounded nonempty list")
    routes = []
    route_ids = set()
    predicates = set()
    for raw in raw_routes:
        route = _route(raw, backends, policies)
        route_id = route["route_id"]
        predicate = (route["host"], route["method"], route["path_kind"], route["path"])
        if route_id in route_ids or predicate in predicates:
            raise ApiGatewayRoutesError("Duplicate route identity or predicate")
        route_ids.add(route_id)
        predicates.add(predicate)
        routes.append(route)
    probes = _exact(model["probes"], {"source_id", "requests"}, "probes")
    probes_id = _identifier(probes["source_id"], "probes source_id")
    if len({source_id, table_id, probes_id}) != 3:
        raise ApiGatewayRoutesError("Source identifiers must be distinct")
    raw_requests = probes["requests"]
    if type(raw_requests) is not list or len(raw_requests) > MAX_REQUESTS:
        raise ApiGatewayRoutesError("Requests must be a bounded list")
    requests = []
    request_ids = set()
    for raw in raw_requests:
        request = _request(raw)
        if request["request_id"] in request_ids:
            raise ApiGatewayRoutesError("Duplicate request identity")
        request_ids.add(request["request_id"])
        requests.append(request)
    return source_id, table_id, routes, requests


def _matches(route: dict[str, Any], host: str, method: str, path: str) -> bool:
    return (
        route["host"] == host
        and route["method"] == method
        and (
            path == route["path"]
            if route["path_kind"] == "exact"
            else path.startswith(route["path"])
        )
    )


def _covers(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    if earlier["host"] != later["host"] or earlier["method"] != later["method"]:
        return False
    if earlier["path_kind"] == "exact":
        return later["path_kind"] == "exact" and earlier["path"] == later["path"]
    return later["path"].startswith(earlier["path"])


def _witness(left: dict[str, Any], right: dict[str, Any]) -> str | None:
    if left["host"] != right["host"] or left["method"] != right["method"]:
        return None
    if left["path_kind"] == "exact":
        return left["path"] if _matches(right, left["host"], left["method"], left["path"]) else None
    if right["path_kind"] == "exact":
        return (
            right["path"] if _matches(left, right["host"], right["method"], right["path"]) else None
        )
    if left["path"].startswith(right["path"]):
        return left["path"]
    if right["path"].startswith(left["path"]):
        return right["path"]
    return None


def _projection(model: Any) -> dict[str, Any]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    source_id, table_id, routes, requests = _model(model)
    ordered = sorted(enumerate(routes), key=lambda item: (-item[1]["priority"], item[0]))
    sorted_routes = [route for _, route in ordered]
    selections = []
    for request in requests:
        matches = [
            route
            for route in sorted_routes
            if _matches(route, request["host"], request["method"], request["path"])
        ]
        selected = matches[0] if matches else None
        selections.append(
            {
                "request_id": request["request_id"],
                "matched_route_ids": [route["route_id"] for route in matches],
                "selected_route_id": selected["route_id"] if selected is not None else None,
                "selected_backend_ref": selected["backend_ref"] if selected is not None else None,
                "selected_auth_policy_ref": (
                    selected["auth_policy_ref"] if selected is not None else None
                ),
            }
        )
    shadowed = []
    candidates = []
    for later_index, later in enumerate(sorted_routes):
        prior = sorted_routes[:later_index]
        covers = [route["route_id"] for route in prior if _covers(route, later)]
        if covers:
            shadowed.append({"route_id": later["route_id"], "prior_superset_route_ids": covers})
        for earlier in prior:
            if earlier["auth_policy_ref"] == later["auth_policy_ref"]:
                continue
            path = _witness(earlier, later)
            if path is None:
                continue
            selected = next(
                route
                for route in sorted_routes
                if _matches(route, earlier["host"], earlier["method"], path)
            )
            candidates.append(
                {
                    "earlier_route_id": earlier["route_id"],
                    "later_route_id": later["route_id"],
                    "earlier_auth_policy_ref": earlier["auth_policy_ref"],
                    "later_auth_policy_ref": later["auth_policy_ref"],
                    "witness": {
                        "host": earlier["host"],
                        "method": earlier["method"],
                        "path": path,
                    },
                    "witness_selected_route_id": selected["route_id"],
                }
            )
            if len(candidates) > MAX_CANDIDATES:
                raise ApiGatewayRoutesError("Candidate limit exceeded")
    table = model["route_table"]
    probes = model["probes"]
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": source_id,
            "model_sha256": _sha(model_text),
            "route_table": {
                "source_id": table_id,
                "sha256": _sha(_canonical(table, maximum=MAX_MODEL_BYTES)),
            },
            "probes": {
                "source_id": probes["source_id"],
                "sha256": _sha(_canonical(probes, maximum=MAX_MODEL_BYTES)),
            },
        },
        "supplied_model": model,
        "route_order": [route["route_id"] for route in sorted_routes],
        "selections": selections,
        "shadowed_routes": shadowed,
        "declared_policy_disparity_candidates": candidates,
        "uncertainty": [
            "The supplied route table and probes are not authenticated gateway state.",
            "Literal prefix is byte-prefix matching, not path-segment matching.",
            "Shadowing is reported only for a single earlier superset predicate.",
            "Different auth-policy references do not establish policy strength or bypass.",
            "No gateway behavior, authorization outcome, vulnerability, or impact is inferred.",
        ],
        "offline_only": True,
        "gateway_behavior_verified": False,
        "auth_bypass_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "AGR-" + digest[:32].upper()
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
    "route_order",
    "selections",
    "shadowed_routes",
    "declared_policy_disparity_candidates",
    "uncertainty",
    "offline_only",
    "gateway_behavior_verified",
    "auth_bypass_verdict",
    "effects",
    "report_id",
    "report_sha256",
}


def _replay(document: Any) -> str:
    _exact(document, _REPORT_FIELDS, "report")
    expected = _projection(document["supplied_model"])
    if document != expected:
        raise ApiGatewayRoutesError("Report does not replay supplied model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> ApiGatewayRoutesReport:
    report = object.__new__(ApiGatewayRoutesReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class ApiGatewayRoutesReport:
    """Detached unsigned projection retaining its complete supplied model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ApiGatewayRoutesReport:
            raise ApiGatewayRoutesError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> ApiGatewayRoutesReport:
        if cls is not ApiGatewayRoutesReport:
            raise ApiGatewayRoutesError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> ApiGatewayRoutesReport:
        if cls is not ApiGatewayRoutesReport or type(value) is not str:
            raise ApiGatewayRoutesError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise ApiGatewayRoutesError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ApiGatewayRoutesReport or type(self.document_json) is not str:
            raise ApiGatewayRoutesError("Exact native report wrapper required")
        return ApiGatewayRoutesReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_api_gateway_routes(model: Any) -> ApiGatewayRoutesReport:
    """Project only finite supplied route declarations and request probes."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_api_gateway_routes_bytes(*, model_bytes: Any) -> ApiGatewayRoutesReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ApiGatewayRoutesError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiGatewayRoutesError("Model bytes must be UTF-8") from exc
    return analyze_supplied_api_gateway_routes(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_api_gateway_routes(report: Any, *, model: Any) -> ApiGatewayRoutesReport:
    if type(report) is not ApiGatewayRoutesReport:
        raise ApiGatewayRoutesError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise ApiGatewayRoutesError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return a fresh synthetic route table with no gateway or destination."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-gateway-model",
        "route_table": {
            "source_id": "synthetic-route-table",
            "normalization": "none",
            "rewrite": "none",
            "order": "priority_desc_then_declaration",
            "backends": ["general-backend", "admin-backend"],
            "auth_policies": ["general-policy", "admin-policy"],
            "routes": [
                {
                    "route_id": "admin-route",
                    "host": "example.invalid",
                    "method": "GET",
                    "path_kind": "exact",
                    "path": "/api/admin",
                    "priority": 20,
                    "backend_ref": "admin-backend",
                    "auth_policy_ref": "admin-policy",
                },
                {
                    "route_id": "api-prefix",
                    "host": "example.invalid",
                    "method": "GET",
                    "path_kind": "literal_prefix",
                    "path": "/api",
                    "priority": 10,
                    "backend_ref": "general-backend",
                    "auth_policy_ref": "general-policy",
                },
                {
                    "route_id": "deep-prefix",
                    "host": "example.invalid",
                    "method": "GET",
                    "path_kind": "literal_prefix",
                    "path": "/api/deep",
                    "priority": 5,
                    "backend_ref": "admin-backend",
                    "auth_policy_ref": "admin-policy",
                },
            ],
        },
        "probes": {
            "source_id": "synthetic-probes",
            "requests": [
                {
                    "request_id": "admin",
                    "host": "example.invalid",
                    "method": "GET",
                    "path": "/api/admin",
                },
                {
                    "request_id": "deep",
                    "host": "example.invalid",
                    "method": "GET",
                    "path": "/api/deep/x",
                },
                {"request_id": "miss", "host": "example.invalid", "method": "POST", "path": "/api"},
            ],
        },
    }


__all__ = [
    "ApiGatewayRoutesError",
    "ApiGatewayRoutesReport",
    "analyze_supplied_api_gateway_routes",
    "analyze_supplied_api_gateway_routes_bytes",
    "verify_supplied_api_gateway_routes",
    "component_fixture",
]
