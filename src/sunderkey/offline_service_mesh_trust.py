"""Inert supplied service-route, sidecar and mTLS trust projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "api_supplied_service_mesh_trust_projection"
PROFILE_ID = "AOE-GB-D06-S08"
CAPABILITY_ID = "army.gb.d06.s08"
VECTOR_ID = "AV-GB-D06-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D06-S08"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GB-D06-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:25baf4de373d9ffc5c73aa0441254f73a476b309ae089eee154bba22d258a581"
DOMAIN = "sunderkey.offline-service-mesh-trust.v1"
MODEL_DOMAIN = "sunderkey.offline-service-mesh-trust-model.v1"
SEMANTICS_PROFILE = "declared-strict-mtls-exact-identity-route.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_WORKLOADS = 64
MAX_ROUTES = 64
MAX_POLICIES = 64
MAX_FLOWS = 128
MAX_IDENTITIES = 64
MAX_WORK = 2_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "service_discovery_verified",
        "route_deployment_verified",
        "sidecar_execution_verified",
        "mtls_handshake_verified",
        "identity_cryptographically_verified",
        "traffic_observed",
        "policy_enforcement_verified",
        "bypass_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "workloads": MAX_WORKLOADS,
    "routes": MAX_ROUTES,
    "policies": MAX_POLICIES,
    "flows": MAX_FLOWS,
    "allowed_identities_per_policy": MAX_IDENTITIES,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Workloads, identities, sidecar paths and routes are caller declarations.",
    "Policies and flow outcomes are caller declarations.",
    "Only strict mTLS with complete via-sidecar paths and exact identity rules is decisive.",
    "Permissive, disabled, bypassed, absent or incomplete mesh semantics remain unknown.",
    "A candidate is a supplied deny-versus-allow contradiction, not verified enforcement bypass.",
    "No Kubernetes, cloud, mesh, certificate, credential, network or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
)


class ServiceMeshTrustAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied mesh model/report."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise ServiceMeshTrustAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise ServiceMeshTrustAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(c) <= 126 for c in item):
                raise ServiceMeshTrustAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise ServiceMeshTrustAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise ServiceMeshTrustAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise ServiceMeshTrustAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise ServiceMeshTrustAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise ServiceMeshTrustAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise ServiceMeshTrustAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise ServiceMeshTrustAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ServiceMeshTrustAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise ServiceMeshTrustAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise ServiceMeshTrustAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise ServiceMeshTrustAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ServiceMeshTrustAnalysisError):
            raise
        raise ServiceMeshTrustAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise ServiceMeshTrustAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ServiceMeshTrustAnalysisError("Bounded exact identity required")
    return value


def _sorted_rows(rows: Any, field: str, limit: int, label: str) -> list:
    if type(rows) is not list or not 1 <= len(rows) <= limit:
        raise ServiceMeshTrustAnalysisError(f"Bounded nonempty {label} required")
    ids = [_identity(row[field]) for row in rows if type(row) is dict and field in row]
    if len(ids) != len(rows) or ids != sorted(set(ids)):
        raise ServiceMeshTrustAnalysisError(f"Sorted unique {label} identities required")
    return rows


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    _exact(owned, {"schema_version", "workloads", "routes", "policies", "flows"}, "model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise ServiceMeshTrustAnalysisError("Exact schema version 1 required")
    workloads = _sorted_rows(owned["workloads"], "workload_id", MAX_WORKLOADS, "workload")
    routes = _sorted_rows(owned["routes"], "route_id", MAX_ROUTES, "route")
    policies = _sorted_rows(owned["policies"], "policy_id", MAX_POLICIES, "policy")
    flows = _sorted_rows(owned["flows"], "flow_id", MAX_FLOWS, "flow")
    workload_by_id = {}
    for item in workloads:
        work.charge(16)
        _exact(
            item,
            {"workload_id", "service_id", "identity", "sidecar_present", "sidecar_complete"},
            "workload",
        )
        _identity(item["service_id"])
        _identity(item["identity"])
        if item["identity"] == "unknown":
            raise ServiceMeshTrustAnalysisError("Workload identity cannot be unknown")
        if type(item["sidecar_present"]) is not bool or type(item["sidecar_complete"]) is not bool:
            raise ServiceMeshTrustAnalysisError("Exact sidecar booleans required")
        workload_by_id[item["workload_id"]] = item
    policy_by_id = {}
    for item in policies:
        work.charge(16)
        _exact(
            item,
            {"policy_id", "mtls_mode", "identity_rule", "allowed_identities", "complete"},
            "policy",
        )
        if item["mtls_mode"] not in ("strict", "permissive", "disabled", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported mTLS mode required")
        if item["identity_rule"] not in ("exact_allowlist", "allow_any", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported identity rule required")
        allowed = item["allowed_identities"]
        if type(allowed) is not list or len(allowed) > MAX_IDENTITIES:
            raise ServiceMeshTrustAnalysisError("Bounded identity allowlist required")
        for identity in allowed:
            _identity(identity)
        if allowed != sorted(set(allowed)):
            raise ServiceMeshTrustAnalysisError("Sorted unique identity allowlist required")
        if item["identity_rule"] != "exact_allowlist" and allowed:
            raise ServiceMeshTrustAnalysisError("Only exact rule may list identities")
        if type(item["complete"]) is not bool:
            raise ServiceMeshTrustAnalysisError("Exact policy completeness required")
        policy_by_id[item["policy_id"]] = item
    route_by_id = {}
    for item in routes:
        work.charge(16)
        _exact(
            item,
            {"route_id", "service_id", "destination_id", "policy_id", "complete"},
            "route",
        )
        service_id = _identity(item["service_id"])
        destination_id = _identity(item["destination_id"])
        if destination_id not in workload_by_id:
            raise ServiceMeshTrustAnalysisError("Unknown route destination")
        if service_id != workload_by_id[destination_id]["service_id"]:
            raise ServiceMeshTrustAnalysisError("Route destination service mismatch")
        if _identity(item["policy_id"]) not in policy_by_id:
            raise ServiceMeshTrustAnalysisError("Unknown route policy")
        if type(item["complete"]) is not bool:
            raise ServiceMeshTrustAnalysisError("Exact route completeness required")
        route_by_id[item["route_id"]] = item
    for item in flows:
        work.charge(16)
        _exact(
            item,
            {
                "flow_id",
                "source_id",
                "route_id",
                "source_path",
                "destination_path",
                "transport",
                "presented_identity",
                "identity_binding_complete",
                "observed_outcome",
                "observation_complete",
            },
            "flow",
        )
        if _identity(item["source_id"]) not in workload_by_id:
            raise ServiceMeshTrustAnalysisError("Unknown flow source")
        if _identity(item["route_id"]) not in route_by_id:
            raise ServiceMeshTrustAnalysisError("Unknown flow route")
        if item["source_path"] not in ("via_sidecar", "bypass", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported source path required")
        if item["destination_path"] not in ("via_sidecar", "bypass", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported destination path required")
        if item["transport"] not in ("mtls", "plaintext", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported transport required")
        if item["presented_identity"] != "unknown":
            _identity(item["presented_identity"])
        if item["observed_outcome"] not in ("allowed", "denied", "unknown"):
            raise ServiceMeshTrustAnalysisError("Supported supplied outcome required")
        if (
            type(item["identity_binding_complete"]) is not bool
            or type(item["observation_complete"]) is not bool
        ):
            raise ServiceMeshTrustAnalysisError("Exact flow booleans required")
    return owned, source_text


def _observe(flow: dict, workloads: dict, routes: dict, policies: dict) -> dict:
    source = workloads[flow["source_id"]]
    route = routes[flow["route_id"]]
    destination = workloads[route["destination_id"]]
    policy = policies[route["policy_id"]]
    reasons: list[str] = []
    if not route["complete"]:
        reasons.append("route_incomplete")
    if not policy["complete"]:
        reasons.append("policy_incomplete")
    if not source["sidecar_present"] or not destination["sidecar_present"]:
        reasons.append("sidecar_absent")
    if not source["sidecar_complete"] or not destination["sidecar_complete"]:
        reasons.append("sidecar_semantics_incomplete")
    if flow["source_path"] != "via_sidecar" or flow["destination_path"] != "via_sidecar":
        reasons.append("sidecar_path_not_proven")
    if policy["mtls_mode"] != "strict":
        reasons.append("non_strict_or_unknown_mtls_mode")
    if flow["transport"] == "unknown":
        reasons.append("transport_unknown")
    if not flow["observation_complete"] or flow["observed_outcome"] == "unknown":
        reasons.append("observation_incomplete")
    expected = None
    if not reasons:
        if flow["transport"] == "plaintext":
            expected = "deny"
        elif flow["transport"] == "mtls":
            if not flow["identity_binding_complete"]:
                reasons.append("identity_binding_incomplete")
            elif flow["presented_identity"] == "unknown":
                reasons.append("presented_identity_unknown")
            elif flow["presented_identity"] != source["identity"]:
                reasons.append("presented_identity_mismatch")
            elif policy["identity_rule"] == "unknown":
                reasons.append("identity_rule_unknown")
            elif policy["identity_rule"] == "allow_any":
                expected = "allow"
            else:
                expected = (
                    "allow"
                    if flow["presented_identity"] in policy["allowed_identities"]
                    else "deny"
                )
    if reasons:
        outcome = "unknown"
    elif expected == "deny" and flow["observed_outcome"] == "allowed":
        outcome = "candidate_declared_deny_allowed_contradiction"
    elif expected == "allow" and flow["observed_outcome"] == "denied":
        outcome = "declared_allow_denied_contradiction"
    else:
        outcome = "matches_declared_policy"
    return {
        "flow_id": flow["flow_id"],
        "source_id": flow["source_id"],
        "route_id": flow["route_id"],
        "destination_id": route["destination_id"],
        "policy_id": route["policy_id"],
        "expected_outcome": expected,
        "supplied_outcome": flow["observed_outcome"],
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    workloads = {row["workload_id"]: row for row in owned["workloads"]}
    routes = {row["route_id"]: row for row in owned["routes"]}
    policies = {row["policy_id"]: row for row in owned["policies"]}
    observations = [_observe(row, workloads, routes, policies) for row in owned["flows"]]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _address(MODEL_DOMAIN, source_text),
        "flow_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_deny_allowed_contradiction"
            for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "flow_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "SMT-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise ServiceMeshTrustAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise ServiceMeshTrustAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class ServiceMeshTrustAnalysis:
    """Detached supplied-data comparison, not live mesh evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> ServiceMeshTrustAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> ServiceMeshTrustAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_service_mesh_trust(model: Any) -> ServiceMeshTrustAnalysis:
    """Compare finite supplied strict-mTLS route and sidecar premises."""
    return ServiceMeshTrustAnalysis(_derive(model))


def analyze_supplied_service_mesh_trust_bytes(*, model_bytes: Any) -> ServiceMeshTrustAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise ServiceMeshTrustAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ServiceMeshTrustAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_service_mesh_trust(_decode(text))


def verify_supplied_service_mesh_trust_analysis(
    report: Any, *, model: Any
) -> ServiceMeshTrustAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not ServiceMeshTrustAnalysis:
        raise ServiceMeshTrustAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise ServiceMeshTrustAnalysisError("Report differs from separately supplied originals")
    return ServiceMeshTrustAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic strict-deny contradictions, match and unknown bypass."""
    return {
        "schema_version": 1,
        "workloads": [
            {
                "workload_id": "client",
                "service_id": "caller",
                "identity": "spiffe://demo/client",
                "sidecar_present": True,
                "sidecar_complete": True,
            },
            {
                "workload_id": "server",
                "service_id": "orders",
                "identity": "spiffe://demo/server",
                "sidecar_present": True,
                "sidecar_complete": True,
            },
        ],
        "routes": [
            {
                "route_id": "orders-route",
                "service_id": "orders",
                "destination_id": "server",
                "policy_id": "orders-policy",
                "complete": True,
            }
        ],
        "policies": [
            {
                "policy_id": "orders-policy",
                "mtls_mode": "strict",
                "identity_rule": "exact_allowlist",
                "allowed_identities": ["spiffe://demo/server"],
                "complete": True,
            }
        ],
        "flows": [
            {
                "flow_id": "deny-allowed",
                "source_id": "client",
                "route_id": "orders-route",
                "source_path": "via_sidecar",
                "destination_path": "via_sidecar",
                "transport": "mtls",
                "presented_identity": "spiffe://demo/client",
                "identity_binding_complete": True,
                "observed_outcome": "allowed",
                "observation_complete": True,
            },
            {
                "flow_id": "plaintext-denied",
                "source_id": "client",
                "route_id": "orders-route",
                "source_path": "via_sidecar",
                "destination_path": "via_sidecar",
                "transport": "plaintext",
                "presented_identity": "unknown",
                "identity_binding_complete": False,
                "observed_outcome": "denied",
                "observation_complete": True,
            },
            {
                "flow_id": "unknown-bypass",
                "source_id": "client",
                "route_id": "orders-route",
                "source_path": "bypass",
                "destination_path": "via_sidecar",
                "transport": "mtls",
                "presented_identity": "spiffe://demo/client",
                "identity_binding_complete": True,
                "observed_outcome": "allowed",
                "observation_complete": True,
            },
        ],
    }


__all__ = [
    "ServiceMeshTrustAnalysisError",
    "ServiceMeshTrustAnalysis",
    "analyze_supplied_service_mesh_trust",
    "analyze_supplied_service_mesh_trust_bytes",
    "verify_supplied_service_mesh_trust_analysis",
    "component_fixture",
]
