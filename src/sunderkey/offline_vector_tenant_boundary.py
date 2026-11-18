"""Inert projection of supplied vector-result tenant and namespace labels."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "data_supplied_vector_tenant_boundary_projection"
PROFILE_ID = "AOE-GB-D07-S04"
CAPABILITY_ID = "army.gb.d07.s04"
VECTOR_ID = "AV-GB-D07-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GB-D07-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:8a36acf02a59df607617eb042cbec157c3d4b1270e7bb533497b10de1d992d60"
DOMAIN = "sunderkey.offline-vector-tenant-boundary.v1"
MODEL_DOMAIN = "sunderkey.offline-vector-tenant-boundary-model.v1"
SEMANTICS_PROFILE = "declared-exact-vector-namespace-tenant-result.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NODES = 16_384
MAX_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_NAMESPACES = 64
MAX_QUERIES = 128
MAX_RECORDS_PER_QUERY = 64
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "namespace_ownership_verified",
        "filter_execution_observed",
        "vector_search_executed",
        "result_provenance_verified",
        "record_tenant_verified",
        "exploitability_verified",
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
    "nodes": MAX_NODES,
    "depth": MAX_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "namespaces": MAX_NAMESPACES,
    "queries": MAX_QUERIES,
    "records_per_query": MAX_RECORDS_PER_QUERY,
}
_LIMITATIONS = [
    "Namespace ownership, filter policy, result lists and record labels are caller declarations.",
    "Only exact one-tenant namespace and result-label comparisons are modeled.",
    "Dynamic filters, aliases, sharing and delegated tenant access are not inferred.",
    "Complete no-exception sharing and delegation context is required for every result.",
    "Candidate records contradict supplied isolation requirements, not observed vector retrieval.",
    "Matching labels do not prove filter enforcement or safe retrieval.",
    "Incomplete mapping, query context, filter, result or record metadata yields unknown.",
    "No vector database, credential, network, process, provider or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
]


class VectorTenantBoundaryAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied vector model/report."""


def _measure(value: Any, depth: int = 1, active: set[int] | None = None) -> int:
    if active is None:
        active = set()
    if depth > MAX_DEPTH:
        raise VectorTenantBoundaryAnalysisError("Native depth bound exceeded")
    kind = type(value)
    if kind is str:
        if len(value.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or not all(
            32 <= ord(char) <= 126 for char in value
        ):
            raise VectorTenantBoundaryAnalysisError("Bounded printable ASCII text required")
        return 1
    if kind is int:
        if not -(2**63) <= value < 2**63:
            raise VectorTenantBoundaryAnalysisError("Signed 64-bit integer required")
        return 1
    if kind in (bool, type(None)):
        return 1
    if kind not in (dict, list) or id(value) in active:
        raise VectorTenantBoundaryAnalysisError("Exact acyclic JSON primitives required")
    active.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise VectorTenantBoundaryAnalysisError("Native text keys required")
            count = 1 + sum(
                _measure(key, depth + 1, active) + _measure(child, depth + 1, active)
                for key, child in value.items()
            )
        else:
            count = 1 + sum(_measure(child, depth + 1, active) for child in value)
    finally:
        active.remove(id(value))
    if count > MAX_NODES:
        raise VectorTenantBoundaryAnalysisError("Native node bound exceeded")
    return count


def _serialize(value: Any) -> str:
    _measure(value)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise VectorTenantBoundaryAnalysisError("Document byte bound exceeded")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise VectorTenantBoundaryAnalysisError("Bounded ASCII JSON required")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in rows:
            if key in result:
                raise VectorTenantBoundaryAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20:
            raise VectorTenantBoundaryAnalysisError("Integer bound exceeded")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise VectorTenantBoundaryAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_token: str) -> None:
        raise VectorTenantBoundaryAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, VectorTenantBoundaryAnalysisError):
            raise
        raise VectorTenantBoundaryAnalysisError("Malformed supplied JSON") from exc
    _serialize(value)
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise VectorTenantBoundaryAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or _ID.fullmatch(value) is None or value == "unknown":
        raise VectorTenantBoundaryAnalysisError("Bounded exact identity required")
    return value


def _rows(value: Any, field: str, limit: int, label: str, *, nonempty: bool = True) -> list:
    if type(value) is not list or len(value) > limit or (nonempty and not value):
        raise VectorTenantBoundaryAnalysisError(f"Bounded {label} list required")
    ids = [_identity(row[field]) for row in value if type(row) is dict and field in row]
    if len(ids) != len(value) or ids != sorted(set(ids)):
        raise VectorTenantBoundaryAnalysisError(f"Sorted unique {label} IDs required")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise VectorTenantBoundaryAnalysisError(f"Native {label} Boolean required")
    return value


def _validate_model(model: Any) -> dict:
    owned = _decode(_serialize(model))
    _exact(
        owned, {"schema_version", "namespace_inventory_complete", "namespaces", "queries"}, "model"
    )
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise VectorTenantBoundaryAnalysisError("Exact schema version 1 required")
    _boolean(owned["namespace_inventory_complete"], "namespace inventory completeness")
    namespaces = _rows(owned["namespaces"], "namespace_id", MAX_NAMESPACES, "namespace")
    queries = _rows(owned["queries"], "query_id", MAX_QUERIES, "query")
    namespace_ids = {row["namespace_id"] for row in namespaces}
    for namespace in namespaces:
        _exact(
            namespace,
            {
                "namespace_id",
                "owner_tenant_id",
                "mapping_complete",
                "policy_complete",
                "tenant_isolation_required",
            },
            "namespace",
        )
        _identity(namespace["owner_tenant_id"])
        for field in ("mapping_complete", "policy_complete", "tenant_isolation_required"):
            _boolean(namespace[field], field)
    for query in queries:
        _exact(
            query,
            {
                "query_id",
                "namespace_id",
                "requester_tenant_id",
                "filter_mode",
                "filter_tenant_id",
                "filter_complete",
                "context_complete",
                "result_complete",
                "sharing_delegation_policy_complete",
                "sharing_delegation_exception",
                "returned_records",
            },
            "query",
        )
        if _identity(query["namespace_id"]) not in namespace_ids:
            raise VectorTenantBoundaryAnalysisError("Unknown query namespace")
        _identity(query["requester_tenant_id"], nullable=True)
        _identity(query["filter_tenant_id"], nullable=True)
        if type(query["filter_mode"]) is not str or query["filter_mode"] not in (
            "exact_tenant",
            "dynamic_or_alias",
            "none",
        ):
            raise VectorTenantBoundaryAnalysisError("Supported filter mode required")
        for field in (
            "filter_complete",
            "context_complete",
            "result_complete",
            "sharing_delegation_policy_complete",
        ):
            _boolean(query[field], field)
        if type(query["sharing_delegation_exception"]) is not str or query[
            "sharing_delegation_exception"
        ] not in ("none", "applies", "unknown"):
            raise VectorTenantBoundaryAnalysisError("Supported sharing exception state required")
        records = _rows(
            query["returned_records"],
            "record_id",
            MAX_RECORDS_PER_QUERY,
            "returned record",
            nonempty=False,
        )
        for record in records:
            _exact(
                record,
                {"record_id", "namespace_id", "tenant_id", "metadata_complete"},
                "returned record",
            )
            namespace_id = _identity(record["namespace_id"], nullable=True)
            if namespace_id is not None and namespace_id not in namespace_ids:
                raise VectorTenantBoundaryAnalysisError("Unknown record namespace")
            _identity(record["tenant_id"], nullable=True)
            _boolean(record["metadata_complete"], "record metadata completeness")
    return owned


def _observe(query: dict, namespace: dict, model: dict, record: dict) -> dict:
    reasons = []
    if not model["namespace_inventory_complete"]:
        reasons.append("namespace_inventory_incomplete")
    if not namespace["mapping_complete"]:
        reasons.append("namespace_mapping_incomplete")
    if not namespace["policy_complete"]:
        reasons.append("namespace_policy_incomplete")
    if not query["filter_complete"] or query["filter_mode"] != "exact_tenant":
        reasons.append("filter_not_exact_or_incomplete")
    if not query["context_complete"]:
        reasons.append("query_context_incomplete")
    if not query["result_complete"]:
        reasons.append("result_snapshot_incomplete")
    if not query["sharing_delegation_policy_complete"]:
        reasons.append("sharing_delegation_policy_incomplete")
    if query["sharing_delegation_exception"] != "none":
        reasons.append("sharing_delegation_exception_not_ruled_out")
    if query["requester_tenant_id"] is None:
        reasons.append("requester_tenant_unknown")
    if query["filter_tenant_id"] is None:
        reasons.append("filter_tenant_unknown")
    if (
        query["requester_tenant_id"] is not None
        and query["requester_tenant_id"] != namespace["owner_tenant_id"]
    ):
        reasons.append("requester_namespace_owner_mismatch")
    if (
        query["requester_tenant_id"] is not None
        and query["filter_tenant_id"] is not None
        and query["filter_tenant_id"] != query["requester_tenant_id"]
    ):
        reasons.append("filter_requester_tenant_mismatch")
    if not record["metadata_complete"]:
        reasons.append("record_metadata_incomplete")
    if record["namespace_id"] is None:
        reasons.append("record_namespace_unknown")
    if record["tenant_id"] is None:
        reasons.append("record_tenant_unknown")
    violations = []
    if reasons:
        outcome = "unknown"
    elif not namespace["tenant_isolation_required"]:
        outcome = "isolation_not_required"
    else:
        if record["namespace_id"] != query["namespace_id"]:
            violations.append("record_namespace_mismatch")
        if record["tenant_id"] != query["requester_tenant_id"]:
            violations.append("record_tenant_mismatch")
        outcome = (
            "candidate_declared_tenant_boundary_contradiction"
            if violations
            else "matches_declared_tenant_boundary"
        )
    return {
        "query_id": query["query_id"],
        "record_id": record["record_id"],
        "namespace_id": query["namespace_id"],
        "record_namespace_id": record["namespace_id"],
        "requester_tenant_id": query["requester_tenant_id"],
        "record_tenant_id": record["tenant_id"],
        "outcome": outcome,
        "violated_declarations": violations,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    owned = _validate_model(model)
    namespaces = {row["namespace_id"]: row for row in owned["namespaces"]}
    observations = [
        _observe(query, namespaces[query["namespace_id"]], owned, record)
        for query in owned["queries"]
        for record in query["returned_records"]
    ]
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
        "source_model_sha256": _address(MODEL_DOMAIN, _serialize(owned)),
        "query_count": len(owned["queries"]),
        "record_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_tenant_boundary_contradiction"
            for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "record_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    digest = _address(DOMAIN, _serialize(body))
    body["analysis_id"] = "VTB-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body)
    return body


def _replay(document: Any) -> dict:
    owned = _decode(_serialize(document))
    if type(owned) is not dict or "source_model" not in owned:
        raise VectorTenantBoundaryAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if _serialize(owned) != _serialize(expected):
        raise VectorTenantBoundaryAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class VectorTenantBoundaryAnalysis:
    """Detached tenant-label comparison, not vector-retrieval evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> VectorTenantBoundaryAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> VectorTenantBoundaryAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())


def analyze_supplied_vector_tenant_boundary(model: Any) -> VectorTenantBoundaryAnalysis:
    """Compare only supplied exact tenant-filter and result-label declarations."""
    return VectorTenantBoundaryAnalysis(_derive(model))


def analyze_supplied_vector_tenant_boundary_bytes(
    *, model_bytes: Any
) -> VectorTenantBoundaryAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise VectorTenantBoundaryAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VectorTenantBoundaryAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_vector_tenant_boundary(_decode(text))


def verify_supplied_vector_tenant_boundary_analysis(
    report: Any, *, model: Any
) -> VectorTenantBoundaryAnalysis:
    if type(report) is not VectorTenantBoundaryAnalysis:
        raise VectorTenantBoundaryAnalysisError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != _serialize(expected):
        raise VectorTenantBoundaryAnalysisError("Report differs from separately supplied originals")
    return VectorTenantBoundaryAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic exact tenant match, contradiction and unknown label."""
    return {
        "schema_version": 1,
        "namespace_inventory_complete": True,
        "namespaces": [
            {
                "namespace_id": "tenant-a-index",
                "owner_tenant_id": "tenant-a",
                "mapping_complete": True,
                "policy_complete": True,
                "tenant_isolation_required": True,
            },
            {
                "namespace_id": "tenant-b-index",
                "owner_tenant_id": "tenant-b",
                "mapping_complete": True,
                "policy_complete": True,
                "tenant_isolation_required": True,
            },
        ],
        "queries": [
            {
                "query_id": "query-a",
                "namespace_id": "tenant-a-index",
                "requester_tenant_id": "tenant-a",
                "filter_mode": "exact_tenant",
                "filter_tenant_id": "tenant-a",
                "filter_complete": True,
                "context_complete": True,
                "result_complete": True,
                "sharing_delegation_policy_complete": True,
                "sharing_delegation_exception": "none",
                "returned_records": [
                    {
                        "record_id": "cross-tenant",
                        "namespace_id": "tenant-a-index",
                        "tenant_id": "tenant-b",
                        "metadata_complete": True,
                    },
                    {
                        "record_id": "exact-match",
                        "namespace_id": "tenant-a-index",
                        "tenant_id": "tenant-a",
                        "metadata_complete": True,
                    },
                    {
                        "record_id": "unknown-label",
                        "namespace_id": "tenant-a-index",
                        "tenant_id": None,
                        "metadata_complete": False,
                    },
                ],
            }
        ],
    }


__all__ = [
    "VectorTenantBoundaryAnalysisError",
    "VectorTenantBoundaryAnalysis",
    "analyze_supplied_vector_tenant_boundary",
    "analyze_supplied_vector_tenant_boundary_bytes",
    "verify_supplied_vector_tenant_boundary_analysis",
    "component_fixture",
]
