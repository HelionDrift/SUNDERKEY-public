"""Inert supplied Kubernetes validating admission and resource-context projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "kubernetes_supplied_admission_policy_projection"
PROFILE_ID = "AOE-GC-D15-S08"
CAPABILITY_ID = "army.gc.d15.s08"
VECTOR_ID = "AV-GC-D15-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S08"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:76b14df6228f98ca76bc907e10d2e7a9cef1a148d2775b981bdb490b84a5332b"
DOMAIN = "sunderkey.offline-kubernetes-admission-boundary.v1"
MODEL_DOMAIN = "sunderkey.offline-kubernetes-admission-boundary-model.v1"
SEMANTICS_PROFILE = "declared-post-mutation-validating-veto.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_POLICIES = 64
MAX_REQUESTS = 128
MAX_FIELDS = 32
MAX_WORK = 2_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "cluster_state_verified",
        "crd_schema_verified",
        "operator_reconciliation_verified",
        "mutating_admission_executed",
        "validating_admission_executed",
        "webhook_availability_verified",
        "request_observed",
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
    "policies": MAX_POLICIES,
    "requests": MAX_REQUESTS,
    "post_mutation_fields": MAX_FIELDS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Admission policies, request fields, operator provenance and outcomes are caller declarations.",
    "Only exact validating vetoes over declared post-mutation fields are modeled.",
    "Mutation effects, operator reconciliation and CRD schema validity are not computed.",
    "Incomplete inventory, mutation, operator or CRD premises produce unknown, not a candidate.",
    "A candidate is a supplied reject-versus-admitted contradiction, not a bypass finding.",
    "No Kubernetes API, webhook, operator, credential, network or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
)


class KubernetesAdmissionBoundaryAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied admission model/report."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise KubernetesAdmissionBoundaryAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise KubernetesAdmissionBoundaryAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(c) <= 126 for c in item):
                raise KubernetesAdmissionBoundaryAnalysisError(
                    "Bounded printable ASCII string required"
                )
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise KubernetesAdmissionBoundaryAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise KubernetesAdmissionBoundaryAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise KubernetesAdmissionBoundaryAnalysisError(
                                "Exact native string keys required"
                            )
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise KubernetesAdmissionBoundaryAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise KubernetesAdmissionBoundaryAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise KubernetesAdmissionBoundaryAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise KubernetesAdmissionBoundaryAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise KubernetesAdmissionBoundaryAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise KubernetesAdmissionBoundaryAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise KubernetesAdmissionBoundaryAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise KubernetesAdmissionBoundaryAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, KubernetesAdmissionBoundaryAnalysisError):
            raise
        raise KubernetesAdmissionBoundaryAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise KubernetesAdmissionBoundaryAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise KubernetesAdmissionBoundaryAnalysisError("Bounded exact identity required")
    return value


def _rows(rows: Any, field: str, limit: int, label: str) -> list:
    if type(rows) is not list or not 1 <= len(rows) <= limit:
        raise KubernetesAdmissionBoundaryAnalysisError(f"Bounded nonempty {label} required")
    names = [_identity(item[field]) for item in rows if type(item) is dict and field in item]
    if len(names) != len(rows) or names != sorted(set(names)):
        raise KubernetesAdmissionBoundaryAnalysisError(f"Sorted unique {label} identities required")
    return rows


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    _exact(owned, {"schema_version", "policy_set_complete", "policies", "requests"}, "model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise KubernetesAdmissionBoundaryAnalysisError("Exact schema version 1 required")
    if type(owned["policy_set_complete"]) is not bool:
        raise KubernetesAdmissionBoundaryAnalysisError("Exact policy-set completeness required")
    policies = _rows(owned["policies"], "policy_id", MAX_POLICIES, "policy")
    requests = _rows(owned["requests"], "request_id", MAX_REQUESTS, "request")
    policy_fields = {
        "policy_id",
        "policy_kind",
        "resource_kind",
        "namespace_id",
        "operation",
        "match_field",
        "match_value",
        "effect",
        "availability",
        "failure_policy",
        "semantics_complete",
    }
    request_fields = {
        "request_id",
        "resource_family",
        "resource_kind",
        "namespace_id",
        "operation",
        "post_mutation_fields",
        "mutation_complete",
        "operator_generated",
        "operator_reconcile_complete",
        "crd_schema_complete",
        "context_complete",
        "supplied_outcome",
        "observation_complete",
    }
    for item in policies:
        work.charge(16)
        _exact(item, policy_fields, "policy")
        if item["policy_kind"] not in ("validating_policy", "validating_webhook"):
            raise KubernetesAdmissionBoundaryAnalysisError(
                "Supported validating policy kind required"
            )
        for key in ("resource_kind", "namespace_id"):
            _identity(item[key])
        if item["operation"] not in ("create", "update"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported operation required")
        if (item["match_field"] is None) != (item["match_value"] is None):
            raise KubernetesAdmissionBoundaryAnalysisError("Field match pair required")
        if item["match_field"] is not None:
            _identity(item["match_field"])
            _identity(item["match_value"])
        if item["effect"] not in ("deny", "allow", "unknown"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported policy effect required")
        if item["availability"] not in ("available", "unavailable", "unknown"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported availability required")
        if item["failure_policy"] not in ("fail", "ignore"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported failure policy required")
        if item["policy_kind"] == "validating_policy" and (
            item["availability"] != "available" or item["failure_policy"] != "fail"
        ):
            raise KubernetesAdmissionBoundaryAnalysisError(
                "Native validating policy cannot use webhook availability semantics"
            )
        if type(item["semantics_complete"]) is not bool:
            raise KubernetesAdmissionBoundaryAnalysisError("Exact policy completeness required")
    for item in requests:
        work.charge(16)
        _exact(item, request_fields, "request")
        if item["resource_family"] not in ("builtin", "crd"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported resource family required")
        for key in ("resource_kind", "namespace_id"):
            _identity(item[key])
        if item["operation"] not in ("create", "update"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported operation required")
        fields = item["post_mutation_fields"]
        if type(fields) is not dict or len(fields) > MAX_FIELDS:
            raise KubernetesAdmissionBoundaryAnalysisError("Bounded post-mutation fields required")
        for key, value in fields.items():
            _identity(key)
            _identity(value)
        for key in (
            "mutation_complete",
            "operator_generated",
            "operator_reconcile_complete",
            "crd_schema_complete",
            "context_complete",
            "observation_complete",
        ):
            if type(item[key]) is not bool:
                raise KubernetesAdmissionBoundaryAnalysisError("Exact request booleans required")
        if item["supplied_outcome"] not in ("admitted", "rejected", "unknown"):
            raise KubernetesAdmissionBoundaryAnalysisError("Supported supplied outcome required")
    return owned, source_text


def _policy_matches(policy: dict, request: dict) -> bool:
    if (
        policy["resource_kind"] != request["resource_kind"]
        or policy["namespace_id"] != request["namespace_id"]
        or policy["operation"] != request["operation"]
    ):
        return False
    field = policy["match_field"]
    return field is None or request["post_mutation_fields"].get(field) == policy["match_value"]


def _observe(request: dict, policies: list[dict], policy_set_complete: bool) -> dict:
    reasons: list[str] = []
    if not policy_set_complete:
        reasons.append("policy_set_incomplete")
    if not request["context_complete"]:
        reasons.append("request_context_incomplete")
    if not request["mutation_complete"]:
        reasons.append("mutation_result_incomplete")
    if request["operator_generated"] and not request["operator_reconcile_complete"]:
        reasons.append("operator_reconciliation_incomplete")
    if request["resource_family"] == "crd" and not request["crd_schema_complete"]:
        reasons.append("crd_schema_incomplete")
    if not request["observation_complete"] or request["supplied_outcome"] == "unknown":
        reasons.append("request_observation_incomplete")
    matched: list[str] = []
    vetoes: list[str] = []
    uncertain: list[str] = []
    if not reasons:
        for policy in policies:
            if not policy["semantics_complete"]:
                uncertain.append(policy["policy_id"])
                continue
            if not _policy_matches(policy, request):
                continue
            matched.append(policy["policy_id"])
            if policy["availability"] == "unknown":
                uncertain.append(policy["policy_id"])
            elif policy["availability"] == "unavailable":
                if policy["failure_policy"] == "fail":
                    vetoes.append(policy["policy_id"])
            elif policy["effect"] == "deny":
                vetoes.append(policy["policy_id"])
            elif policy["effect"] == "unknown":
                uncertain.append(policy["policy_id"])
    if uncertain:
        reasons.append("matching_policy_uncertain")
    expected = None
    if not reasons:
        if vetoes:
            expected = "reject"
        else:
            reasons.append("unmodeled_admission_stages")
    if reasons:
        outcome = "unknown"
    elif expected == "reject" and request["supplied_outcome"] == "admitted":
        outcome = "candidate_declared_reject_admitted_contradiction"
    else:
        outcome = "matches_declared_admission"
    return {
        "request_id": request["request_id"],
        "resource_family": request["resource_family"],
        "expected_outcome": expected,
        "supplied_outcome": request["supplied_outcome"],
        "outcome": outcome,
        "matching_policy_ids": matched,
        "veto_policy_ids": vetoes,
        "uncertain_policy_ids": uncertain,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    observations = [
        _observe(row, owned["policies"], owned["policy_set_complete"]) for row in owned["requests"]
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
        "source_model_sha256": _address(MODEL_DOMAIN, source_text),
        "request_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_reject_admitted_contradiction"
            for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "request_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "KAB-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise KubernetesAdmissionBoundaryAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise KubernetesAdmissionBoundaryAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class KubernetesAdmissionBoundaryAnalysis:
    """Detached supplied-data comparison, not live admission evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> KubernetesAdmissionBoundaryAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> KubernetesAdmissionBoundaryAnalysis:
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


def analyze_supplied_kubernetes_admission_boundary(
    model: Any,
) -> KubernetesAdmissionBoundaryAnalysis:
    """Compare supplied validating admission vetoes and request outcomes."""
    return KubernetesAdmissionBoundaryAnalysis(_derive(model))


def analyze_supplied_kubernetes_admission_boundary_bytes(
    *, model_bytes: Any
) -> KubernetesAdmissionBoundaryAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise KubernetesAdmissionBoundaryAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise KubernetesAdmissionBoundaryAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_kubernetes_admission_boundary(_decode(text))


def verify_supplied_kubernetes_admission_boundary_analysis(
    report: Any, *, model: Any
) -> KubernetesAdmissionBoundaryAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not KubernetesAdmissionBoundaryAnalysis:
        raise KubernetesAdmissionBoundaryAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise KubernetesAdmissionBoundaryAnalysisError(
            "Report differs from separately supplied originals"
        )
    return KubernetesAdmissionBoundaryAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic validating veto, matching denial and uncertain operator case."""
    return {
        "schema_version": 1,
        "policy_set_complete": True,
        "policies": [
            {
                "policy_id": "block-privileged",
                "policy_kind": "validating_policy",
                "resource_kind": "pod",
                "namespace_id": "team-a",
                "operation": "create",
                "match_field": "privileged",
                "match_value": "true",
                "effect": "deny",
                "availability": "available",
                "failure_policy": "fail",
                "semantics_complete": True,
            }
        ],
        "requests": [
            {
                "request_id": "admitted-contradiction",
                "resource_family": "builtin",
                "resource_kind": "pod",
                "namespace_id": "team-a",
                "operation": "create",
                "post_mutation_fields": {"privileged": "true"},
                "mutation_complete": True,
                "operator_generated": False,
                "operator_reconcile_complete": False,
                "crd_schema_complete": False,
                "context_complete": True,
                "supplied_outcome": "admitted",
                "observation_complete": True,
            },
            {
                "request_id": "declared-reject",
                "resource_family": "builtin",
                "resource_kind": "pod",
                "namespace_id": "team-a",
                "operation": "create",
                "post_mutation_fields": {"privileged": "true"},
                "mutation_complete": True,
                "operator_generated": False,
                "operator_reconcile_complete": False,
                "crd_schema_complete": False,
                "context_complete": True,
                "supplied_outcome": "rejected",
                "observation_complete": True,
            },
            {
                "request_id": "unknown-operator",
                "resource_family": "crd",
                "resource_kind": "custom-widget",
                "namespace_id": "team-a",
                "operation": "create",
                "post_mutation_fields": {"privileged": "false"},
                "mutation_complete": True,
                "operator_generated": True,
                "operator_reconcile_complete": False,
                "crd_schema_complete": False,
                "context_complete": True,
                "supplied_outcome": "admitted",
                "observation_complete": True,
            },
        ],
    }


__all__ = [
    "KubernetesAdmissionBoundaryAnalysisError",
    "KubernetesAdmissionBoundaryAnalysis",
    "analyze_supplied_kubernetes_admission_boundary",
    "analyze_supplied_kubernetes_admission_boundary_bytes",
    "verify_supplied_kubernetes_admission_boundary_analysis",
    "component_fixture",
]
