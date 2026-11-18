"""Bounded resource-request reasoning over supplied Kubernetes RBAC objects."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D15-S04"
CAPABILITY_ID = "container.kubernetes.rbac-service-account"
VECTOR_ID = "AV-GC-D15-S04-01"
SEMANTICS_PROFILE = "kubernetes-v1.34.0-resource-rbac-subset-v1"
RBAC_GROUP = "rbac.authorization.k8s.io"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 24
MAX_NODES = 100_000
MAX_TEXT = 4096
MAX_OBJECTS = 256
MAX_QUERIES = 128
MAX_RULES = 2048
MAX_SUBJECTS = 4096
MAX_VALUES = 128
MAX_MATCH_WORK = 2_000_000
MAX_WITNESSES = 2048
_QUERY_FIELDS = {
    "query_id",
    "principal",
    "groups",
    "namespace",
    "resource_scope",
    "api_group",
    "resource",
    "subresource",
    "verb",
    "name",
    "field_selector",
}
_LIMITATIONS = (
    "Supplied objects, principal groups and resource scope are unauthenticated declarations.",
    "No matching allow in this model is not effective cluster denial.",
    "Other authorizers, admission, authentication and cluster completeness are not evaluated.",
    "Aggregation and field selectors are not evaluated; no policies are fetched.",
    "No containment, independent qualification, routing, deployment or target effect is granted.",
)


class KubernetesRbacAnalysisError(ValueError):
    """A supplied model is malformed, ambiguous, unbounded or falsely replayed."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture(value: Any) -> Any:
    """Copy only bounded native JSON, charging each occurrence of a shared tree."""
    active: set[int] = set()
    nodes = 0
    size = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, size
        nodes += 1
        size += 2
        if depth > MAX_DEPTH or nodes > MAX_NODES or size > MAX_JSON_BYTES:
            raise KubernetesRbacAnalysisError("JSON structural budget exceeded")
        if type(item) is str:
            if len(item) > MAX_TEXT:
                raise KubernetesRbacAnalysisError("JSON text budget exceeded")
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise KubernetesRbacAnalysisError("JSON text is not valid UTF-8") from exc
            # Twelve bytes covers an escaped non-BMP character before serialization.
            size += 12 * len(item)
            if size > MAX_JSON_BYTES:
                raise KubernetesRbacAnalysisError("JSON byte budget exceeded")
            return item
        if item is None or type(item) is bool:
            size += 5
            return item
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise KubernetesRbacAnalysisError("JSON integer is outside signed64")
            size += 20
            return item
        if type(item) not in (dict, list):
            raise KubernetesRbacAnalysisError("Only native JSON primitives are accepted")
        if len(item) > MAX_NODES or id(item) in active:
            raise KubernetesRbacAnalysisError("JSON collection is oversized or cyclic")
        active.add(id(item))
        try:
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise KubernetesRbacAnalysisError("JSON object keys must be native text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    result = visit(value, 0)
    if size > MAX_JSON_BYTES:
        raise KubernetesRbacAnalysisError("JSON byte budget exceeded")
    return result


def _parse_bytes(raw: bytes) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise KubernetesRbacAnalysisError("JSON requires bounded nonempty native bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KubernetesRbacAnalysisError("JSON is not UTF-8") from exc
    depth = 0
    quoted = False
    escaped = False
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
                raise KubernetesRbacAnalysisError("JSON structural budget exceeded")
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise KubernetesRbacAnalysisError("Duplicate JSON object key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise KubernetesRbacAnalysisError("JSON floats and nonfinite values are unsupported")

    def integer(value: str) -> int:
        if len(value) > 20:
            raise KubernetesRbacAnalysisError("JSON integer is outside signed64")
        return int(value)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, RecursionError) as exc:
        raise KubernetesRbacAnalysisError("Invalid bounded native JSON") from exc
    return _capture(value)


def _object(value: Any, required: set[str], allowed: set[str], label: str) -> dict:
    if type(value) is not dict or not required <= value.keys() or not value.keys() <= allowed:
        raise KubernetesRbacAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _text(value: Any, label: str, *, empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > 512
        or (not value and not empty)
        or not value.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise KubernetesRbacAnalysisError(f"{label} requires bounded native ASCII text")
    return value


def _texts(value: Any, label: str, *, empty_value: bool = False) -> list[str]:
    if type(value) is not list or len(value) > MAX_VALUES:
        raise KubernetesRbacAnalysisError(f"{label} requires a bounded native list")
    return [_text(item, label, empty=empty_value) for item in value]


def _namespace(value: Any, *, empty: bool = False) -> str:
    text = _text(value, "namespace", empty=empty)
    if text and (len(text) > 63 or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", text)):
        raise KubernetesRbacAnalysisError("namespace is outside the supported DNS-label form")
    return text


def _path_name(value: Any) -> str:
    text = _text(value, "object name")
    if text in (".", "..") or "/" in text or "%" in text:
        raise KubernetesRbacAnalysisError("object name is not a path segment")
    return text


def _key(item: dict) -> tuple[str, str, str]:
    return item["kind"], item["metadata"].get("namespace", ""), item["metadata"]["name"]


def _validate_objects(snapshot: Any) -> tuple[list[dict], dict, list[dict], int]:
    _object(snapshot, {"objects"}, {"objects"}, "snapshot")
    objects = snapshot["objects"]
    if type(objects) is not list or len(objects) > MAX_OBJECTS:
        raise KubernetesRbacAnalysisError("snapshot requires a bounded objects list")
    seen = set()
    roles = {}
    bindings = []
    rule_count = subject_count = work = 0
    for item in objects:
        _object(
            item,
            {"apiVersion", "kind", "metadata"},
            {
                "apiVersion",
                "kind",
                "metadata",
                "rules",
                "subjects",
                "roleRef",
                "aggregationRule",
            },
            "RBAC object",
        )
        if item["apiVersion"] != RBAC_GROUP + "/v1":
            raise KubernetesRbacAnalysisError("Only RBAC v1 objects are supported")
        kind = item["kind"]
        if kind not in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            raise KubernetesRbacAnalysisError("Unsupported RBAC object kind")
        metadata = _object(
            item["metadata"],
            {"name"},
            {
                "name",
                "namespace",
                "labels",
                "annotations",
                "uid",
                "resourceVersion",
                "generation",
                "creationTimestamp",
            },
            "metadata",
        )
        _path_name(metadata["name"])
        namespace = _namespace(metadata.get("namespace", ""), empty=kind.startswith("Cluster"))
        if kind.startswith("Cluster") and namespace:
            raise KubernetesRbacAnalysisError("Cluster objects cannot declare a namespace")
        for field in ("labels", "annotations"):
            if field in metadata:
                mapping = metadata[field]
                if type(mapping) is not dict:
                    raise KubernetesRbacAnalysisError("metadata maps must be native objects")
                for key, value in mapping.items():
                    _text(key, field)
                    _text(value, field, empty=True)
        for field in ("uid", "resourceVersion", "creationTimestamp"):
            if field in metadata and metadata[field] is not None:
                _text(metadata[field], field)
        if "generation" in metadata and (
            type(metadata["generation"]) is not int or metadata["generation"] < 0
        ):
            raise KubernetesRbacAnalysisError(
                "metadata generation must be a native nonnegative int"
            )
        key = _key(item)
        if key in seen:
            raise KubernetesRbacAnalysisError("Duplicate or conflicting RBAC object identity")
        seen.add(key)
        if kind in ("Role", "ClusterRole"):
            if "subjects" in item or "roleRef" in item:
                raise KubernetesRbacAnalysisError("A role cannot contain binding fields")
            rules = item.get("rules", [])
            if type(rules) is not list or len(rules) > MAX_VALUES:
                raise KubernetesRbacAnalysisError("rules must be a bounded native list")
            rule_count += len(rules)
            for rule in rules:
                _object(
                    rule,
                    {"verbs"},
                    {
                        "verbs",
                        "apiGroups",
                        "resources",
                        "resourceNames",
                        "nonResourceURLs",
                    },
                    "rule",
                )
                verbs = _texts(rule["verbs"], "verbs")
                if not verbs:
                    raise KubernetesRbacAnalysisError("A rule requires verbs")
                urls = _texts(rule.get("nonResourceURLs", []), "nonResourceURLs")
                groups = _texts(rule.get("apiGroups", []), "apiGroups", empty_value=True)
                resources = _texts(rule.get("resources", []), "resources")
                names = _texts(rule.get("resourceNames", []), "resourceNames")
                if urls:
                    if kind == "Role" or groups or resources or names:
                        raise KubernetesRbacAnalysisError("Invalid mixed or namespaced URL rule")
                elif not groups or not resources:
                    raise KubernetesRbacAnalysisError("Resource rules require groups and resources")
                work += 1 + len(verbs) + len(groups) + len(resources) + len(names)
            if "aggregationRule" in item:
                if kind != "ClusterRole" or type(item["aggregationRule"]) is not dict:
                    raise KubernetesRbacAnalysisError(
                        "Only ClusterRole aggregation is supported as uncertainty"
                    )
                _object(
                    item["aggregationRule"],
                    {"clusterRoleSelectors"},
                    {"clusterRoleSelectors"},
                    "aggregationRule",
                )
                selectors = item["aggregationRule"]["clusterRoleSelectors"]
                if type(selectors) is not list or not selectors or len(selectors) > MAX_VALUES:
                    raise KubernetesRbacAnalysisError("Aggregation requires bounded selectors")
                for selector in selectors:
                    _object(selector, set(), {"matchLabels", "matchExpressions"}, "selector")
            roles[key] = item
        else:
            if "rules" in item or "aggregationRule" in item:
                raise KubernetesRbacAnalysisError("A binding cannot contain role fields")
            if "subjects" not in item or "roleRef" not in item:
                raise KubernetesRbacAnalysisError("Binding subjects and roleRef are required")
            subjects = item["subjects"]
            if type(subjects) is not list or len(subjects) > MAX_VALUES:
                raise KubernetesRbacAnalysisError("subjects must be a bounded native list")
            subject_count += len(subjects)
            ref = _object(
                item["roleRef"],
                {"apiGroup", "kind", "name"},
                {"apiGroup", "kind", "name"},
                "roleRef",
            )
            if ref["apiGroup"] != RBAC_GROUP or ref["kind"] not in ("Role", "ClusterRole"):
                raise KubernetesRbacAnalysisError("Invalid roleRef API group or kind")
            if kind == "ClusterRoleBinding" and ref["kind"] != "ClusterRole":
                raise KubernetesRbacAnalysisError("ClusterRoleBinding must reference ClusterRole")
            _path_name(ref["name"])
            for subject in subjects:
                _object(
                    subject, {"kind", "name"}, {"kind", "name", "namespace", "apiGroup"}, "subject"
                )
                _text(subject["name"], "subject name")
                if "namespace" in subject:
                    _namespace(subject["namespace"], empty=True)
                subject_kind = subject["kind"]
                api_group = subject.get("apiGroup", "")
                if subject_kind == "ServiceAccount":
                    if api_group != "":
                        raise KubernetesRbacAnalysisError("ServiceAccount apiGroup must be empty")
                    labels = subject["name"].split(".")
                    if len(subject["name"]) > 253 or any(
                        len(label) > 63
                        or not re.fullmatch(
                            r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?",
                            label,
                        )
                        for label in labels
                    ):
                        raise KubernetesRbacAnalysisError("Unsupported service-account name")
                    _namespace(subject.get("namespace", ""), empty=kind == "RoleBinding")
                elif subject_kind in ("User", "Group"):
                    if api_group != RBAC_GROUP or subject.get("namespace", ""):
                        raise KubernetesRbacAnalysisError(
                            "User/Group apiGroup or namespace is invalid"
                        )
                else:
                    raise KubernetesRbacAnalysisError("Unsupported subject kind")
            bindings.append(item)
            work += 2 + len(subjects)
    if rule_count > MAX_RULES or subject_count > MAX_SUBJECTS:
        raise KubernetesRbacAnalysisError("RBAC rule or subject budget exceeded")
    return objects, roles, bindings, work


def _validate_queries(queries: Any) -> list[dict]:
    if type(queries) is not list or not 1 <= len(queries) <= MAX_QUERIES:
        raise KubernetesRbacAnalysisError("queries requires 1..128 native objects")
    seen = set()
    scopes = {}
    for query in queries:
        _object(query, _QUERY_FIELDS, _QUERY_FIELDS, "query")
        for field in _QUERY_FIELDS - {"groups"}:
            _text(
                query[field],
                field,
                empty=field
                in {
                    "namespace",
                    "api_group",
                    "subresource",
                    "name",
                    "field_selector",
                },
            )
        _texts(query["groups"], "query groups")
        if query["query_id"] in seen:
            raise KubernetesRbacAnalysisError("Duplicate query identity")
        seen.add(query["query_id"])
        scope = query["resource_scope"]
        if scope not in ("namespaced", "cluster", "unknown"):
            raise KubernetesRbacAnalysisError("Invalid declared resource scope")
        _namespace(query["namespace"], empty=scope != "namespaced")
        if scope == "cluster" and query["namespace"]:
            raise KubernetesRbacAnalysisError("Cluster queries cannot declare a namespace")
        if "*" in query["verb"] or "*" in query["api_group"]:
            raise KubernetesRbacAnalysisError("Query attributes must be explicit, not wildcards")
        for field in ("resource", "subresource"):
            if "/" in query[field] or "*" in query[field]:
                raise KubernetesRbacAnalysisError("Query resource attributes must be explicit")
        if query["verb"] in ("list", "watch", "deletecollection") or (
            query["verb"] == "create" and not query["subresource"]
        ):
            if query["name"]:
                raise KubernetesRbacAnalysisError(
                    "Collection and top-level create name must be empty"
                )
        if query["field_selector"] and query["verb"] not in ("list", "watch"):
            raise KubernetesRbacAnalysisError("Field selectors are only represented for list/watch")
        resource = (query["api_group"], query["resource"])
        if scope != "unknown":
            if resource in scopes and scopes[resource] != scope:
                raise KubernetesRbacAnalysisError("Conflicting declared resource scopes")
            scopes[resource] = scope
    return queries


def _subject_matches(subject: dict, binding: dict, query: dict) -> bool:
    if subject["kind"] == "User":
        return subject["name"] == query["principal"]
    if subject["kind"] == "Group":
        return subject["name"] in query["groups"]
    namespace = subject.get("namespace") or binding["metadata"].get("namespace", "")
    return query["principal"] == f"system:serviceaccount:{namespace}:{subject['name']}"


def _rule_matches(rule: dict, query: dict) -> bool:
    if rule.get("nonResourceURLs"):
        return False
    resource = query["resource"] + ("/" + query["subresource"] if query["subresource"] else "")
    return (
        ("*" in rule["verbs"] or query["verb"] in rule["verbs"])
        and ("*" in rule["apiGroups"] or query["api_group"] in rule["apiGroups"])
        and (
            "*" in rule["resources"]
            or resource in rule["resources"]
            or bool(query["subresource"] and "*/" + query["subresource"] in rule["resources"])
        )
        and (not rule.get("resourceNames") or query["name"] in rule["resourceNames"])
    )


def _build_document(snapshot: Any, queries: Any) -> dict:
    inputs = _capture({"snapshot": snapshot, "queries": queries})
    snapshot, queries = inputs["snapshot"], inputs["queries"]
    objects, roles, bindings, _ = _validate_objects(snapshot)
    _validate_queries(queries)
    source_issues = []
    resolved = {}
    work = 0
    for binding in bindings:
        ref = binding["roleRef"]
        role_key = (
            ref["kind"],
            binding["metadata"].get("namespace", "") if ref["kind"] == "Role" else "",
            ref["name"],
        )
        resolved[_key(binding)] = roles.get(role_key)
        work += 2 + len(binding["subjects"])
        role = roles.get(role_key)
        if role is not None and "aggregationRule" not in role:
            # Charge repeated references to the same role, not merely distinct role rows.
            work += sum(
                1
                + sum(
                    len(rule.get(field, []))
                    for field in (
                        "verbs",
                        "apiGroups",
                        "resources",
                        "resourceNames",
                    )
                )
                for rule in role.get("rules", [])
            )
        if role_key not in roles:
            source_issues.append(
                {"reason": "unresolved_role_reference", "object": list(_key(binding))}
            )
    if work * len(queries) > MAX_MATCH_WORK:
        raise KubernetesRbacAnalysisError("Matching work budget exceeded")
    for item in objects:
        if "aggregationRule" in item:
            source_issues.append({"reason": "unsupported_aggregation", "object": list(_key(item))})
    source_issues.sort(key=_canonical)
    results = []
    witness_count = 0
    for query in sorted(queries, key=lambda item: item["query_id"]):
        reasons = {item["reason"] for item in source_issues}
        witnesses = {}
        unsupported = query["resource_scope"] == "unknown" or bool(query["field_selector"])
        if query["resource_scope"] == "unknown":
            reasons.add("unknown_resource_scope")
        if query["field_selector"]:
            reasons.add("unsupported_field_selector")
        if not unsupported:
            for binding in bindings:
                if binding["kind"] == "RoleBinding" and (
                    query["resource_scope"] != "namespaced"
                    or query["namespace"] != binding["metadata"]["namespace"]
                ):
                    continue
                subjects = [s for s in binding["subjects"] if _subject_matches(s, binding, query)]
                role = resolved[_key(binding)]
                if not subjects or role is None or "aggregationRule" in role:
                    continue
                for rule in role.get("rules", []):
                    if _rule_matches(rule, query):
                        witness = {
                            "binding": list(_key(binding)),
                            "role": list(_key(role)),
                            "rule_sha256": _hash("sunderkey.kubernetes-rbac-rule.v1", rule),
                            # A single deterministic subject is sufficient for this grant.
                            "subjects": sorted(subjects, key=_canonical)[:1],
                        }
                        witness_key = _canonical(witness)
                        if (
                            witness_key not in witnesses
                            and witness_count + len(witnesses) >= MAX_WITNESSES
                        ):
                            raise KubernetesRbacAnalysisError(
                                "Witness budget exceeded; no truncated result is returned"
                            )
                        witnesses[witness_key] = witness
        ordered = [witnesses[key] for key in sorted(witnesses)]
        witness_count += len(ordered)
        if witness_count > MAX_WITNESSES:
            raise KubernetesRbacAnalysisError(
                "Witness budget exceeded; no truncated result is returned"
            )
        decision = (
            "allow_in_supplied_model"
            if ordered
            else ("inconclusive" if reasons else "no_matching_allow_in_supplied_model")
        )
        results.append(
            {
                "query_id": query["query_id"],
                "query_sha256": _hash("sunderkey.kubernetes-rbac-query.v1", query),
                "decision": decision,
                "witnesses": ordered,
                "uncertainties": sorted(reasons),
            }
        )
    body = {
        "schema_version": 1,
        "kind": "kubernetes_rbac_analysis",
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "snapshot": snapshot,
        "queries": queries,
        "snapshot_sha256": _hash("sunderkey.kubernetes-rbac-snapshot.v1", snapshot),
        "queries_sha256": _hash("sunderkey.kubernetes-rbac-queries.v1", queries),
        "source_issues": source_issues,
        "results": results,
        "limitations": list(_LIMITATIONS),
        "effects": {
            key: "none"
            for key in (
                "qualification",
                "routing",
                "execution",
                "deployment",
                "target_interaction",
            )
        },
    }
    digest = _hash("sunderkey.kubernetes-rbac-analysis.v1", body)
    body.update(analysis_id="KRA-" + digest[7:39].upper(), analysis_sha256=digest)
    _capture(body)
    return body


def _verified_document(value: Any) -> dict:
    document = _capture(value)
    if type(document) is not dict or "snapshot" not in document or "queries" not in document:
        raise KubernetesRbacAnalysisError("Analysis requires exact embedded source inputs")
    expected = _build_document(document["snapshot"], document["queries"])
    if _canonical(document) != _canonical(expected):
        raise KubernetesRbacAnalysisError("Analysis does not match exact source/query replay")
    return expected


@dataclass(frozen=True, slots=True)
class KubernetesRbacAnalysis:
    """Owned canonical document; every public export repeats exact algorithm replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self.document_json) is not str or len(self.document_json) > MAX_JSON_BYTES:
            raise KubernetesRbacAnalysisError("Analysis requires bounded native canonical text")
        try:
            raw = self.document_json.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise KubernetesRbacAnalysisError("Analysis text is not UTF-8") from exc
        expected = _verified_document(_parse_bytes(raw))
        if self.document_json != _canonical(expected):
            raise KubernetesRbacAnalysisError("Analysis text must be exact canonical JSON")

    @classmethod
    def from_dict(cls, document: dict) -> KubernetesRbacAnalysis:
        return cls(_canonical(_verified_document(document)))

    @classmethod
    def from_json(cls, raw: bytes) -> KubernetesRbacAnalysis:
        document = _parse_bytes(raw)
        return cls.from_dict(document)

    def to_dict(self) -> dict:
        text = getattr(self, "document_json", None)
        if type(text) is not str or len(text) > MAX_JSON_BYTES:
            raise KubernetesRbacAnalysisError("Analysis canonical text is missing or invalid")
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise KubernetesRbacAnalysisError("Analysis text is not UTF-8") from exc
        document = _verified_document(_parse_bytes(raw))
        if text != _canonical(document):
            raise KubernetesRbacAnalysisError("Analysis text is not canonical")
        return document

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_kubernetes_rbac(snapshot: dict, queries: list) -> KubernetesRbacAnalysis:
    """Return only declared-model resource grants, absent matches or explicit uncertainty."""
    return KubernetesRbacAnalysis(_canonical(_build_document(snapshot, queries)))


def analyze_kubernetes_rbac_bytes(
    *,
    snapshot_bytes: bytes,
    queries_bytes: bytes,
) -> KubernetesRbacAnalysis:
    return analyze_kubernetes_rbac(_parse_bytes(snapshot_bytes), _parse_bytes(queries_bytes))


def verify_kubernetes_rbac_analysis(
    analysis: KubernetesRbacAnalysis | dict,
    *,
    snapshot: dict,
    queries: list,
) -> KubernetesRbacAnalysis:
    """Bind a result to the exact separately supplied model, not live authorization."""
    if type(analysis) is KubernetesRbacAnalysis:
        document = analysis.to_dict()
    elif type(analysis) is dict:
        document = _verified_document(analysis)
    else:
        raise KubernetesRbacAnalysisError("Expected a native analysis document or exact record")
    expected = _build_document(snapshot, queries)
    if _canonical(document) != _canonical(expected):
        raise KubernetesRbacAnalysisError("Analysis is bound to different source/query inputs")
    return KubernetesRbacAnalysis(_canonical(expected))
