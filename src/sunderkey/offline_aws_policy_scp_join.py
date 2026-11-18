"""Join two inert supplied AWS policy models without claiming AWS permission."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from sunderkey.aws_scp_analysis import AwsScpAnalysisError, analyze_aws_scp
from sunderkey.offline_aws_identity_policy_analysis import (
    AwsIdentityPolicyAnalysisError,
    analyze_aws_identity_policy_set,
)

COMPONENT_ID = "aws-supplied-identity-scp-pair-v1"
DOMAIN = "sunderkey.offline-aws-policy-scp-join.v1"
PROFILE_ID = "AOE-GC-D14-S01"
CAPABILITY_ID = "army.gc.d14.s01"
VECTOR_ID = "AV-GC-D14-S01-01"
WAVE_ID = "IW2-004"
MAX_MODEL_BYTES = 524_288
MAX_REPORT_BYTES = 4_194_304
MAX_NODES = 60_000
MAX_DEPTH = 16
MAX_TEXT = 4096
MAX_QUERIES = 64
_MODEL_FIELDS = {
    "schema_version",
    "principal_binding",
    "identity_model",
    "scp_snapshot",
    "scp_queries",
}
_BINDING_FIELDS = {"principal_ref", "principal_account_id", "principal_kind"}
_DECISIONS = (
    "identity_allow_and_scp_not_blocked",
    "explicit_deny_in_supplied_layer",
    "missing_allow_in_supplied_layer",
    "inconclusive",
    "not_applicable",
)
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider_requests",
        "credentials",
        "process",
    )
}
_LIMITATIONS = [
    "Principal, account, policy inventory, applicability and context are caller declarations.",
    "Identity Allow and SCP non-blocking concern only these two modeled layers.",
    "No effective AWS permission, request outcome, live source or policy currentness is proved.",
    "Resource, session, boundary, RCP, trust and cross-account policies are not composed.",
    "No credential, provider, target, routing, qualification or deployment authority exists.",
]
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class AwsPolicyScpJoinError(ValueError):
    """The supplied sources, join or exact report replay are unsupported."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(domain: str, value: Any) -> str:
    content = domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _capture(value: Any, *, maximum: int) -> Any:
    """Own exact native JSON after charging repeated containers and escaped text."""
    active: set[int] = set()
    nodes = size = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, size
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise AwsPolicyScpJoinError("Native node or depth budget exceeded")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT or any(not 32 <= ord(char) <= 126 for char in item):
                raise AwsPolicyScpJoinError("Text is outside bounded printable ASCII")
            size += 2 + len(item) + item.count('"') + item.count("\\")
            if size > maximum:
                raise AwsPolicyScpJoinError("Canonical byte budget exceeded")
            return item
        if kind is bool:
            size += 4 if item else 5
            return item
        if kind is int:
            if not -(2**63) <= item < 2**63:
                raise AwsPolicyScpJoinError("Integer is outside signed64")
            size += len(str(item))
            return item
        if item is None:
            size += 4
            return None
        if kind not in (dict, list) or id(item) in active:
            raise AwsPolicyScpJoinError("Only acyclic exact native JSON is accepted")
        size += 2
        if size > maximum or len(item) > MAX_NODES:
            raise AwsPolicyScpJoinError("Native container budget exceeded")
        active.add(id(item))
        try:
            if kind is list:
                result = []
                for index, child in enumerate(item):
                    if index:
                        size += 1
                    result.append(visit(child, depth + 1))
                return result
            result = {}
            for index, (key, child) in enumerate(item.items()):
                if type(key) is not str:
                    raise AwsPolicyScpJoinError("Object keys require native strings")
                if index:
                    size += 1
                owned_key = visit(key, depth + 1)
                size += 1
                result[owned_key] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    owned = visit(value, 1)
    if size > maximum:
        raise AwsPolicyScpJoinError("Canonical byte budget exceeded")
    return owned


def _parse_bytes(raw: bytes, *, maximum: int) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > maximum or not raw.isascii():
        raise AwsPolicyScpJoinError("JSON requires bounded exact ASCII bytes")
    text = raw.decode("ascii")
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
                raise AwsPolicyScpJoinError("Raw JSON depth budget exceeded")
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise AwsPolicyScpJoinError("Duplicate JSON object key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise AwsPolicyScpJoinError("Floats and nonfinite JSON are unsupported")

    def integer(token: str) -> int:
        if len(token) > 20:
            raise AwsPolicyScpJoinError("JSON integer is outside signed64")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise AwsPolicyScpJoinError("JSON integer is outside signed64")
        return value

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, RecursionError) as exc:
        raise AwsPolicyScpJoinError("Invalid bounded native JSON") from exc
    return _capture(value, maximum=maximum)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise AwsPolicyScpJoinError(f"{label} requires exactly its declared fields")
    return value


def _binding(value: Any) -> dict[str, str]:
    binding = _exact(value, _BINDING_FIELDS, "Principal binding")
    if type(binding["principal_ref"]) is not str or not binding["principal_ref"]:
        raise AwsPolicyScpJoinError("Principal reference requires native text")
    account = binding["principal_account_id"]
    if type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None:
        raise AwsPolicyScpJoinError("Principal account requires twelve native digits")
    if type(binding["principal_kind"]) is not str or binding["principal_kind"] not in (
        "iam_user",
        "iam_role",
    ):
        raise AwsPolicyScpJoinError("Only declared IAM user or role pairs are supported")
    return binding


def _joined_queries(model: dict[str, Any], binding: dict[str, str]) -> list[dict[str, Any]]:
    """Reject source substitutions before either child model is addressed."""
    identity = model["identity_model"]
    snapshot = model["scp_snapshot"]
    scp_queries = model["scp_queries"]
    if type(identity) is not dict or not {"principal_ref", "queries"} <= identity.keys():
        raise AwsPolicyScpJoinError("Identity source lacks principal or queries")
    if type(snapshot) is not dict or type(snapshot.get("path")) is not list:
        raise AwsPolicyScpJoinError("SCP source lacks a native member path")
    path = snapshot["path"]
    if not path or type(path[-1]) is not dict or "node_id" not in path[-1]:
        raise AwsPolicyScpJoinError("SCP member path is missing")
    if type(scp_queries) is not list:
        raise AwsPolicyScpJoinError("SCP queries require a native list")
    if binding["principal_ref"] != identity["principal_ref"]:
        raise AwsPolicyScpJoinError("Principal reference differs from identity source")
    if binding["principal_account_id"] != path[-1]["node_id"]:
        raise AwsPolicyScpJoinError("Principal account differs from selected member path")
    identity_queries = identity["queries"]
    if type(identity_queries) is not list:
        raise AwsPolicyScpJoinError("Identity queries require a native list")
    if len(identity_queries) > MAX_QUERIES or len(identity_queries) != len(scp_queries):
        raise AwsPolicyScpJoinError("Both policy models require one-to-one queries")
    by_id = {}
    for item in identity_queries:
        if type(item) is not dict or type(item.get("query_id")) is not str:
            raise AwsPolicyScpJoinError("Identity query requires a native ID")
        if not {"action", "resource", "context"} <= item.keys():
            raise AwsPolicyScpJoinError("Identity query lacks joined request fields")
        by_id[item["query_id"]] = item
    if len(by_id) != len(identity_queries):
        raise AwsPolicyScpJoinError("Identity query IDs repeat")
    joined = []
    seen_scp_ids = set()
    for scp_query in scp_queries:
        if (
            type(scp_query) is not dict
            or not {
                "query_id",
                "principal_account_id",
                "principal_kind",
                "action",
                "resource",
                "context",
            }
            <= scp_query.keys()
        ):
            raise AwsPolicyScpJoinError("SCP query lacks joined request fields")
        query_id = scp_query["query_id"]
        if type(query_id) is not str:
            raise AwsPolicyScpJoinError("SCP query ID requires native text")
        if query_id in seen_scp_ids:
            raise AwsPolicyScpJoinError("SCP query IDs repeat")
        seen_scp_ids.add(query_id)
        identity_query = by_id.get(query_id)
        if identity_query is None:
            raise AwsPolicyScpJoinError("SCP query ID differs from identity source")
        if (
            scp_query["principal_account_id"] != binding["principal_account_id"]
            or scp_query["principal_kind"] != binding["principal_kind"]
        ):
            raise AwsPolicyScpJoinError("SCP query differs from principal/account binding")
        for name in ("action", "resource", "context"):
            if _canonical(scp_query[name]) != _canonical(identity_query[name]):
                raise AwsPolicyScpJoinError(f"Query {name} differs across supplied policies")
        joined.append(identity_query)
    return sorted(joined, key=lambda item: item["query_id"])


def _pair_decision(identity: dict[str, Any], scp: dict[str, Any]) -> str:
    identity_state = identity["decision"]
    scp_state = scp["decision"]
    if identity_state == "explicit_denial_by_supplied_identity_policies" or (
        scp_state == "blocked" and scp["deny_witnesses"]
    ):
        return "explicit_deny_in_supplied_layer"
    if identity_state == "not_applicable" or scp_state == "not_applicable":
        return "not_applicable"
    if identity_state == "inconclusive" or scp_state == "inconclusive":
        return "inconclusive"
    if identity_state == "implicit_denial_by_supplied_identity_policies" or scp_state == "blocked":
        return "missing_allow_in_supplied_layer"
    if (
        identity_state == "allowed_by_supplied_identity_policies"
        and scp_state == "not_blocked_by_supplied_scps"
    ):
        return "identity_allow_and_scp_not_blocked"
    raise AwsPolicyScpJoinError("Supplied decisions cannot be composed in this subset")


def _derive(value: Any) -> dict[str, Any]:
    model = _exact(_capture(value, maximum=MAX_MODEL_BYTES), _MODEL_FIELDS, "Pair model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AwsPolicyScpJoinError("Pair schema_version requires native integer one")
    binding = _binding(model["principal_binding"])
    queries = _joined_queries(model, binding)
    try:
        identity_report = analyze_aws_identity_policy_set(model["identity_model"]).to_dict()
        scp_report = analyze_aws_scp(model["scp_snapshot"], model["scp_queries"]).to_dict()
    except (AwsIdentityPolicyAnalysisError, AwsScpAnalysisError) as exc:
        raise AwsPolicyScpJoinError("A supplied policy model is outside its own subset") from exc
    identity_results = {item["query_id"]: item for item in identity_report["results"]}
    scp_results = {item["query_id"]: item for item in scp_report["results"]}
    results = []
    for query in queries:
        query_id = query["query_id"]
        identity_result = identity_results[query_id]
        scp_result = scp_results[query_id]
        results.append(
            {
                "query_id": query_id,
                "identity_query_sha256": identity_result["query_sha256"],
                "scp_query_sha256": scp_result["query_sha256"],
                "identity_applicability": query["action_resource_applicability"],
                "scp_enabled": model["scp_snapshot"]["scp_enabled"],
                "identity_decision": identity_result["decision"],
                "scp_decision": scp_result["decision"],
                "pair_decision": _pair_decision(identity_result, scp_result),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "source_model": model,
        "source_model_sha256": _sha("sunderkey.offline-aws-policy-scp-model.v1", model),
        "identity_analysis": identity_report,
        "scp_analysis": scp_report,
        "results": results,
        "summary": {
            "query_count": len(results),
            **{name: sum(item["pair_decision"] == name for item in results) for name in _DECISIONS},
        },
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    _capture(
        {"analysis_id": "APJ-" + "0" * 32, "analysis_sha256": "sha256:" + "0" * 64, **body},
        maximum=MAX_REPORT_BYTES,
    )
    digest = _sha(DOMAIN, body)
    return _capture(
        {"analysis_id": "APJ-" + digest[7:39].upper(), "analysis_sha256": digest, **body},
        maximum=MAX_REPORT_BYTES,
    )


def _verified(value: Any) -> dict[str, Any]:
    document = _capture(value, maximum=MAX_REPORT_BYTES)
    if type(document) is not dict or "source_model" not in document:
        raise AwsPolicyScpJoinError("Pair report requires its complete original models")
    expected = _derive(document["source_model"])
    if _canonical(document) != _canonical(expected):
        raise AwsPolicyScpJoinError("Pair report does not replay exact supplied models")
    return expected


@dataclass(frozen=True, slots=True)
class AwsPolicyScpJoin:
    """Owned, source-replaying record of only the two supplied policy layers."""

    document_json: str

    def __post_init__(self) -> None:
        text = self.document_json
        if type(text) is not str or not text or len(text) > MAX_REPORT_BYTES:
            raise AwsPolicyScpJoinError("Pair wrapper requires bounded native text")
        if not text.isascii():
            raise AwsPolicyScpJoinError("Pair wrapper requires ASCII JSON")
        expected = _verified(_parse_bytes(text.encode("ascii"), maximum=MAX_REPORT_BYTES))
        if text != _canonical(expected):
            raise AwsPolicyScpJoinError("Pair wrapper requires exact canonical JSON")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AwsPolicyScpJoin:
        return cls(_canonical(_verified(value)))

    @classmethod
    def from_json(cls, raw: bytes) -> AwsPolicyScpJoin:
        return cls.from_dict(_parse_bytes(raw, maximum=MAX_REPORT_BYTES))

    def to_dict(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise AwsPolicyScpJoinError("Pair wrapper is incomplete") from exc
        if type(text) is not str or not text or len(text) > MAX_REPORT_BYTES or not text.isascii():
            raise AwsPolicyScpJoinError("Pair wrapper requires bounded native ASCII JSON")
        expected = _verified(_parse_bytes(text.encode("ascii"), maximum=MAX_REPORT_BYTES))
        if text != _canonical(expected):
            raise AwsPolicyScpJoinError("Pair wrapper is not canonical")
        return expected

    def to_json(self) -> str:
        return _canonical(self.to_dict())


def analyze_supplied_aws_policy_scp_pair(model: dict[str, Any]) -> AwsPolicyScpJoin:
    return AwsPolicyScpJoin(_canonical(_derive(model)))


def analyze_supplied_aws_policy_scp_pair_bytes(*, model_bytes: bytes) -> AwsPolicyScpJoin:
    return analyze_supplied_aws_policy_scp_pair(_parse_bytes(model_bytes, maximum=MAX_MODEL_BYTES))


def verify_supplied_aws_policy_scp_pair(
    report: AwsPolicyScpJoin | dict[str, Any], *, model: dict[str, Any]
) -> AwsPolicyScpJoin:
    if type(report) is AwsPolicyScpJoin:
        observed = report.to_dict()
    elif type(report) is dict:
        observed = _verified(report)
    else:
        raise AwsPolicyScpJoinError("Pair report requires its exact supported native family")
    expected = _derive(model)
    if _canonical(observed) != _canonical(expected):
        raise AwsPolicyScpJoinError("Pair report differs from separately supplied originals")
    return AwsPolicyScpJoin(_canonical(expected))


__all__ = [
    "AwsPolicyScpJoin",
    "AwsPolicyScpJoinError",
    "analyze_supplied_aws_policy_scp_pair",
    "analyze_supplied_aws_policy_scp_pair_bytes",
    "verify_supplied_aws_policy_scp_pair",
]
