"""Pure, bounded NetworkPolicy mathematics over an unauthenticated supplied model."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "kubernetes_supplied_network_policy_flows"
PROFILE_ID = "AOE-GC-D15-S07"
CAPABILITY_ID = "army.gc.d15.s07"
VECTOR_ID = "AV-GC-D15-S07-01"
WAVE_ID = "IW2-009"
BLUEPRINT_SHA256 = "sha256:ae690f9ea176aeee2f7cc66d6a5f7d1837a81ebac3c8cdaed7421c470745d875"
SEMANTICS_PROFILE = "kubernetes-v1.34.1-pod-network-policy-subset-v1"
DOMAIN = "sunderkey.kubernetes-network-policy-analysis.v1"
MODEL_DOMAIN = "sunderkey.kubernetes-network-policy-model.v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NATIVE_DEPTH = 16
MAX_NATIVE_NODES = 32768
MAX_STRING_BYTES = 512
MAX_NAMESPACES = 64
MAX_PODS = 256
MAX_POLICIES = 128
MAX_FLOWS = 64
MAX_LABELS = 64
MAX_EXPRESSIONS = 64
MAX_VALUES = 64
MAX_RULES = 512
MAX_PEERS = 64
MAX_PORTS = 64
MAX_MATCH_WORK = 1_000_000
MAX_WITNESSES = 2048
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LABEL_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?\Z")
_FLOW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MODEL_FIELDS = {"schema_version", "namespaces", "pods", "network_policies", "flows"}
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_depth": MAX_NATIVE_DEPTH,
    "native_nodes": MAX_NATIVE_NODES,
    "string_bytes": MAX_STRING_BYTES,
    "namespaces": MAX_NAMESPACES,
    "pods": MAX_PODS,
    "policies": MAX_POLICIES,
    "flows": MAX_FLOWS,
    "labels_per_object": MAX_LABELS,
    "expressions_per_selector": MAX_EXPRESSIONS,
    "values_per_expression": MAX_VALUES,
    "total_rules": MAX_RULES,
    "peers_per_rule": MAX_PEERS,
    "ports_per_rule": MAX_PORTS,
    "match_work": MAX_MATCH_WORK,
    "total_witnesses": MAX_WITNESSES,
}
_FLAGS = {
    "snapshot_authenticated": False,
    "snapshot_complete": False,
    "cni_enforcement_proven": False,
    "reachability_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider",
        "credential",
        "process",
    ),
    "none",
)
_LIMITATIONS = (
    "Sources and flow attributes are caller assertions, not authenticated cluster evidence.",
    "Only supplied distinct pod-to-pod TCP, UDP and SCTP policy declarations are evaluated.",
    "No CNI enforcement, snapshot completeness, actual reachability or vulnerability is proven.",
    "Named ports, IP blocks, host networking and same-pod flows are outside this subset.",
    (
        "Node traffic, Services, address translation, existing connections "
        "and service meshes are not evaluated."
    ),
    (
        "No source acquisition, runtime invocation, credentials, signing "
        "or current authority is involved."
    ),
)


class KubernetesNetworkPolicyAnalysisError(ValueError):
    """The supplied projection is malformed, unbounded or does not replay exactly."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture(value: Any) -> Any:
    """Charge repeated native nodes and escaped canonical bytes before copying them."""
    nodes = size = 0
    active: set[int] = set()

    def charge(count: int) -> None:
        nonlocal size
        size += count
        if size > MAX_DOCUMENT_BYTES:
            raise KubernetesNetworkPolicyAnalysisError("Document exceeds its aggregate byte bound")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise KubernetesNetworkPolicyAnalysisError("Document exceeds node or depth bounds")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise KubernetesNetworkPolicyAnalysisError("String exceeds its byte bound")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise KubernetesNetworkPolicyAnalysisError("Strings must be printable ASCII")
                if char in '\\"':
                    charge(1)
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if item.bit_length() > 63:
                raise KubernetesNetworkPolicyAnalysisError("Integer exceeds signed63 magnitude")
            charge(len(str(item)))
            return item
        if kind not in {dict, list}:
            raise KubernetesNetworkPolicyAnalysisError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise KubernetesNetworkPolicyAnalysisError("Cyclic native inputs are refused")
        if len(item) > MAX_NATIVE_NODES - nodes:
            raise KubernetesNetworkPolicyAnalysisError("Collection exceeds remaining node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise KubernetesNetworkPolicyAnalysisError("Object keys must be native strings")
                owned_key = visit(key, depth + 1)
                result[owned_key] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1)


def _decode(text: Any) -> Any:
    """Bound raw lexical costs before JSON decoding or integer conversion."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise KubernetesNetworkPolicyAnalysisError("JSON must be bounded native ASCII text")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise KubernetesNetworkPolicyAnalysisError(
                    "JSON scalar exceeds pre-decoder depth bound"
                )
            nodes += 1
            length = 0
            index += 1
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise KubernetesNetworkPolicyAnalysisError("Incomplete JSON escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise KubernetesNetworkPolicyAnalysisError(
                                "Invalid JSON Unicode escape"
                            )
                        if not 32 <= int(digits, 16) <= 126:
                            raise KubernetesNetworkPolicyAnalysisError(
                                "JSON is outside printable ASCII"
                            )
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise KubernetesNetworkPolicyAnalysisError("Unsupported JSON string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise KubernetesNetworkPolicyAnalysisError(
                            "JSON is outside printable ASCII"
                        )
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise KubernetesNetworkPolicyAnalysisError("JSON string exceeds its bound")
            if not closed:
                raise KubernetesNetworkPolicyAnalysisError("Incomplete JSON string")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise KubernetesNetworkPolicyAnalysisError(
                    "JSON scalar exceeds pre-decoder depth bound"
                )
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            token = text[start:index]
            nodes += 1
            if token not in {"true", "false", "null"}:
                if _INTEGER.fullmatch(token) is None or int(token).bit_length() > 63:
                    raise KubernetesNetworkPolicyAnalysisError(
                        "JSON number is outside the integer subset"
                    )
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise KubernetesNetworkPolicyAnalysisError(
                "JSON exceeds pre-decoder node or depth bounds"
            )
    if depth:
        raise KubernetesNetworkPolicyAnalysisError("Incomplete JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise KubernetesNetworkPolicyAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise KubernetesNetworkPolicyAnalysisError(
            "Fractional or nonfinite numbers are unsupported"
        )

    try:
        document = json.loads(
            text, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, KubernetesNetworkPolicyAnalysisError):
            raise
        raise KubernetesNetworkPolicyAnalysisError("Malformed JSON document") from exc
    return _capture(document)


def _fields(value: Any, required: set[str], allowed: set[str], label: str) -> dict:
    if type(value) is not dict or not required <= value.keys() or not value.keys() <= allowed:
        raise KubernetesNetworkPolicyAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _list(value: Any, maximum: int, label: str) -> list:
    if type(value) is not list or len(value) > maximum:
        raise KubernetesNetworkPolicyAnalysisError(f"{label} exceeds its native collection bound")
    return value


def _name(value: Any, *, namespace: bool = False) -> str:
    if type(value) is not str or not value or len(value) > (63 if namespace else 253):
        raise KubernetesNetworkPolicyAnalysisError("Name exceeds the supported DNS spelling")
    if any(_DNS_LABEL.fullmatch(part) is None for part in value.split(".")) or (
        namespace and "." in value
    ):
        raise KubernetesNetworkPolicyAnalysisError("Name is outside the supported DNS spelling")
    return value


def _label_key(value: Any) -> str:
    if type(value) is not str:
        raise KubernetesNetworkPolicyAnalysisError("Label key must be a native string")
    parts = value.split("/")
    if len(parts) > 2 or _LABEL_NAME.fullmatch(parts[-1]) is None:
        raise KubernetesNetworkPolicyAnalysisError("Label key is outside the supported spelling")
    if len(parts) == 2:
        _name(parts[0])
    return value


def _label_value(value: Any) -> str:
    if type(value) is not str or (value and _LABEL_NAME.fullmatch(value) is None):
        raise KubernetesNetworkPolicyAnalysisError("Label value is outside the supported spelling")
    return value


def _labels(value: Any) -> dict[str, str]:
    if type(value) is not dict or len(value) > MAX_LABELS:
        raise KubernetesNetworkPolicyAnalysisError("Label map exceeds its native bound")
    for key, label in value.items():
        _label_key(key)
        _label_value(label)
    return value


def _port_number(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise KubernetesNetworkPolicyAnalysisError(
            "Port must be a native integer from 1 through 65535"
        )
    return value


@dataclass(frozen=True, slots=True)
class _Selector:
    index: int
    labels: tuple[tuple[str, str], ...]
    expressions: tuple[tuple[str, str, frozenset[str]], ...]


@dataclass(frozen=True, slots=True)
class _Peer:
    pod: _Selector | None
    namespace: _Selector | None


@dataclass(frozen=True, slots=True)
class _Port:
    protocol: str
    first: int | None
    last: int | None


@dataclass(frozen=True, slots=True)
class _Rule:
    peers: tuple[_Peer, ...]
    ports: tuple[_Port, ...]


@dataclass(frozen=True, slots=True)
class _Policy:
    document: dict
    selector: _Selector
    directions: frozenset[str]
    ingress: tuple[_Rule, ...]
    egress: tuple[_Rule, ...]


class _Preparation:
    def __init__(self) -> None:
        self.selectors = 0
        self.rules = 0
        self.issues: list[dict[str, str]] = []

    def issue(self, path: str, code: str) -> None:
        self.issues.append({"source_path": path, "code": code})

    def selector(self, value: Any) -> _Selector:
        obj = _fields(value, set(), {"matchLabels", "matchExpressions"}, "Label selector")
        labels = _labels(obj.get("matchLabels", {}))
        expressions = []
        for requirement in _list(
            obj.get("matchExpressions", []), MAX_EXPRESSIONS, "Selector expressions"
        ):
            _fields(
                requirement,
                {"key", "operator"},
                {"key", "operator", "values"},
                "Selector requirement",
            )
            key = _label_key(requirement["key"])
            operator = requirement["operator"]
            if type(operator) is not str or operator not in {
                "In",
                "NotIn",
                "Exists",
                "DoesNotExist",
            }:
                raise KubernetesNetworkPolicyAnalysisError("Selector operator is unsupported")
            values = _list(requirement.get("values", []), MAX_VALUES, "Selector values")
            for item in values:
                _label_value(item)
            if bool(values) != (operator in {"In", "NotIn"}):
                raise KubernetesNetworkPolicyAnalysisError(
                    "Selector values contradict its operator"
                )
            expressions.append((key, operator, frozenset(values)))
        index = self.selectors
        self.selectors += 1
        return _Selector(index, tuple(sorted(labels.items())), tuple(expressions))

    def rule(self, value: Any, direction: str, path: str) -> _Rule:
        peer_field = "from" if direction == "Ingress" else "to"
        obj = _fields(value, set(), {peer_field, "ports"}, "NetworkPolicy rule")
        self.rules += 1
        if self.rules > MAX_RULES:
            raise KubernetesNetworkPolicyAnalysisError("Total rule count exceeds its bound")
        peers = []
        for index, peer in enumerate(_list(obj.get(peer_field, []), MAX_PEERS, "Rule peers")):
            _fields(
                peer, set(), {"podSelector", "namespaceSelector", "ipBlock"}, "NetworkPolicy peer"
            )
            if not peer:
                raise KubernetesNetworkPolicyAnalysisError(
                    "A peer must specify a selector or IP block"
                )
            if "ipBlock" in peer:
                if len(peer) != 1:
                    raise KubernetesNetworkPolicyAnalysisError(
                        "IP block cannot be combined with selectors"
                    )
                block = _fields(
                    peer["ipBlock"], {"cidr"}, {"cidr", "except"}, "IP block projection"
                )
                if type(block["cidr"]) is not str or not block["cidr"]:
                    raise KubernetesNetworkPolicyAnalysisError(
                        "IP block CIDR requires a native nonempty string"
                    )
                for excluded in _list(block.get("except", []), MAX_VALUES, "IP block exclusions"):
                    if type(excluded) is not str or not excluded:
                        raise KubernetesNetworkPolicyAnalysisError(
                            "IP block exclusions require native strings"
                        )
                self.issue(f"{path}.{peer_field}[{index}]", "ip_block_outside_subset")
                peers.append(_Peer(None, None))
            else:
                pod = self.selector(peer["podSelector"]) if "podSelector" in peer else None
                namespace = (
                    self.selector(peer["namespaceSelector"])
                    if "namespaceSelector" in peer
                    else None
                )
                peers.append(_Peer(pod, namespace))
        ports = []
        for index, port in enumerate(_list(obj.get("ports", []), MAX_PORTS, "Rule ports")):
            _fields(port, set(), {"protocol", "port", "endPort"}, "NetworkPolicy port")
            protocol = port.get("protocol", "TCP")
            if type(protocol) is not str or protocol not in {"TCP", "UDP", "SCTP"}:
                raise KubernetesNetworkPolicyAnalysisError("Port protocol is unsupported")
            first = last = None
            if "endPort" in port and ("port" not in port or type(port["port"]) is not int):
                raise KubernetesNetworkPolicyAnalysisError(
                    "endPort requires an explicitly numeric port"
                )
            if "port" in port:
                if type(port["port"]) is str:
                    if not port["port"]:
                        raise KubernetesNetworkPolicyAnalysisError(
                            "Named port requires a nonempty string"
                        )
                    self.issue(f"{path}.ports[{index}]", "named_port_outside_subset")
                else:
                    first = _port_number(port["port"])
                    last = _port_number(port.get("endPort", first))
                    if last < first:
                        raise KubernetesNetworkPolicyAnalysisError("endPort precedes port")
            ports.append(_Port(protocol, first, last))
        return _Rule(tuple(peers), tuple(ports))

    def policy(self, value: Any, index: int, namespaces: dict) -> _Policy:
        obj = _fields(
            value,
            {"apiVersion", "kind", "metadata", "spec"},
            {"apiVersion", "kind", "metadata", "spec"},
            "NetworkPolicy",
        )
        if obj["apiVersion"] != "networking.k8s.io/v1" or obj["kind"] != "NetworkPolicy":
            raise KubernetesNetworkPolicyAnalysisError(
                "NetworkPolicy version or kind is unsupported"
            )
        meta = _fields(
            obj["metadata"], {"namespace", "name"}, {"namespace", "name"}, "Policy metadata"
        )
        _name(meta["name"])
        if _name(meta["namespace"], namespace=True) not in namespaces:
            raise KubernetesNetworkPolicyAnalysisError(
                "Policy namespace is absent from the supplied model"
            )
        spec = _fields(
            obj["spec"], set(), {"podSelector", "policyTypes", "ingress", "egress"}, "Policy spec"
        )
        selector = self.selector(spec.get("podSelector", {}))
        ingress = tuple(
            self.rule(rule, "Ingress", f"network_policies[{index}].spec.ingress[{i}]")
            for i, rule in enumerate(_list(spec.get("ingress", []), MAX_RULES, "Ingress rules"))
        )
        egress = tuple(
            self.rule(rule, "Egress", f"network_policies[{index}].spec.egress[{i}]")
            for i, rule in enumerate(_list(spec.get("egress", []), MAX_RULES, "Egress rules"))
        )
        types = _list(spec.get("policyTypes", []), 2, "Policy types")
        for item in types:
            if type(item) is not str or item not in {"Ingress", "Egress"}:
                raise KubernetesNetworkPolicyAnalysisError("Policy direction is unsupported")
        directions = (
            frozenset(types)
            if types
            else frozenset({"Ingress", "Egress"} if egress else {"Ingress"})
        )
        return _Policy(obj, selector, directions, ingress, egress)


def _prepare(value: Any) -> tuple[dict, dict, dict, list[_Policy], list[dict]]:
    model = _fields(_capture(value), _MODEL_FIELDS, _MODEL_FIELDS, "NetworkPolicy model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesNetworkPolicyAnalysisError(
            "Model schema version must be native integer one"
        )
    prep = _Preparation()
    namespaces = {}
    for item in _list(model["namespaces"], MAX_NAMESPACES, "Namespaces"):
        _fields(item, {"name", "labels"}, {"name", "labels"}, "Namespace projection")
        name = _name(item["name"], namespace=True)
        labels = _labels(item["labels"])
        if name in namespaces:
            raise KubernetesNetworkPolicyAnalysisError("Duplicate namespace identity")
        if (
            "kubernetes.io/metadata.name" in labels
            and labels["kubernetes.io/metadata.name"] != name
        ):
            raise KubernetesNetworkPolicyAnalysisError(
                "Supplied namespace name label contradicts its name"
            )
        namespaces[name] = item
    pods = {}
    for index, item in enumerate(_list(model["pods"], MAX_PODS, "Pods")):
        _fields(
            item,
            {"namespace", "name", "labels", "host_network"},
            {"namespace", "name", "labels", "host_network"},
            "Pod projection",
        )
        namespace = _name(item["namespace"], namespace=True)
        name = _name(item["name"])
        _labels(item["labels"])
        if namespace not in namespaces or (namespace, name) in pods:
            raise KubernetesNetworkPolicyAnalysisError(
                "Pod namespace is missing or its identity is duplicated"
            )
        if type(item["host_network"]) is not bool:
            raise KubernetesNetworkPolicyAnalysisError("host_network must be a native boolean")
        if item["host_network"]:
            prep.issue(f"pods[{index}]", "host_network_outside_subset")
        pods[(namespace, name)] = item
    policies = []
    seen = set()
    for index, item in enumerate(
        _list(model["network_policies"], MAX_POLICIES, "Network policies")
    ):
        policy = prep.policy(item, index, namespaces)
        identity = (policy.document["metadata"]["namespace"], policy.document["metadata"]["name"])
        if identity in seen:
            raise KubernetesNetworkPolicyAnalysisError("Duplicate policy identity")
        seen.add(identity)
        policies.append(policy)
    flow_ids = set()
    for flow in _list(model["flows"], MAX_FLOWS, "Flows"):
        fields = {"flow_id", "source_pod", "destination_pod", "protocol", "destination_port"}
        _fields(flow, fields, fields, "Flow projection")
        identifier = flow["flow_id"]
        if (
            type(identifier) is not str
            or _FLOW_ID.fullmatch(identifier) is None
            or identifier in flow_ids
        ):
            raise KubernetesNetworkPolicyAnalysisError("Flow identity is malformed or duplicated")
        flow_ids.add(identifier)
        for field in ("source_pod", "destination_pod"):
            endpoint = _fields(
                flow[field], {"namespace", "name"}, {"namespace", "name"}, "Pod reference"
            )
            key = (_name(endpoint["namespace"], namespace=True), _name(endpoint["name"]))
            if key not in pods:
                raise KubernetesNetworkPolicyAnalysisError("Flow references an absent supplied pod")
        if type(flow["protocol"]) is not str or flow["protocol"] not in {"TCP", "UDP", "SCTP"}:
            raise KubernetesNetworkPolicyAnalysisError("Flow protocol is unsupported")
        _port_number(flow["destination_port"])
    policies.sort(
        key=lambda policy: (
            policy.document["metadata"]["namespace"],
            policy.document["metadata"]["name"],
        )
    )
    return model, namespaces, pods, policies, prep.issues


class _Matching:
    def __init__(self, namespaces: dict, pods: dict) -> None:
        self.namespaces = namespaces
        self.pods = pods
        self.work = 0
        self.witnesses = 0
        self.cache: dict[tuple, bool] = {}

    def charge(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > MAX_MATCH_WORK:
            raise KubernetesNetworkPolicyAnalysisError(
                "Selector/rule matching exceeds its work bound"
            )

    def selector(
        self, selector: _Selector, kind: str, identity: tuple[str, ...], labels: dict
    ) -> bool:
        key = (selector.index, kind, identity)
        if key in self.cache:
            return self.cache[key]
        self.charge(1 + len(selector.labels) + len(selector.expressions))
        matches = all(labels.get(key) == value for key, value in selector.labels)
        for key, operator, values in selector.expressions:
            if operator == "In":
                matches = matches and key in labels and labels[key] in values
            elif operator == "NotIn":
                matches = matches and (key not in labels or labels[key] not in values)
            elif operator == "Exists":
                matches = matches and key in labels
            else:
                matches = matches and key not in labels
        self.cache[(selector.index, kind, identity)] = matches
        return matches

    def peer(self, peer: _Peer, policy_namespace: str, identity: tuple[str, str]) -> bool:
        namespace, _ = identity
        if peer.namespace is None:
            if namespace != policy_namespace:
                return False
        elif not self.selector(
            peer.namespace, "namespace", (namespace,), self.namespaces[namespace]["labels"]
        ):
            return False
        return peer.pod is None or self.selector(
            peer.pod, "pod", identity, self.pods[identity]["labels"]
        )

    def direction(
        self,
        policies: list[_Policy],
        refs: dict,
        focal: tuple[str, str],
        peer: tuple[str, str],
        flow: dict,
        direction: str,
    ) -> dict:
        applicable = []
        matches = []
        for policy in policies:
            self.charge()
            namespace = policy.document["metadata"]["namespace"]
            if namespace != focal[0] or direction not in policy.directions:
                continue
            if not self.selector(policy.selector, "pod", focal, self.pods[focal]["labels"]):
                continue
            ref = refs[(namespace, policy.document["metadata"]["name"])]
            applicable.append(ref)
            rules = policy.ingress if direction == "Ingress" else policy.egress
            for index, rule in enumerate(rules):
                self.charge()
                peer_index = None
                peer_ok = not rule.peers
                for candidate, selected in enumerate(rule.peers):
                    self.charge()
                    if self.peer(selected, namespace, peer):
                        peer_ok = True
                        peer_index = candidate
                        break
                if not peer_ok:
                    continue
                port_index = None
                port_ok = not rule.ports
                for candidate, port in enumerate(rule.ports):
                    self.charge()
                    if port.protocol == flow["protocol"] and (
                        port.first is None or port.first <= flow["destination_port"] <= port.last
                    ):
                        port_ok = True
                        port_index = candidate
                        break
                if port_ok:
                    self.witnesses += 1
                    if self.witnesses > MAX_WITNESSES:
                        raise KubernetesNetworkPolicyAnalysisError(
                            "Matching witnesses exceed their bound"
                        )
                    matches.append(
                        {
                            "policy": ref,
                            "rule_index": index,
                            "peer_index": peer_index,
                            "port_index": port_index,
                        }
                    )
        isolated = bool(applicable)
        return {
            "isolated": isolated,
            "allowed": not isolated or bool(matches),
            "applicable_policies": applicable,
            "matching_rules": matches,
            "reason": "not_isolated_by_supplied_policies"
            if not isolated
            else "matched_allow_rule"
            if matches
            else "no_matching_allow_rule",
        }


def _unassessed(reason: str) -> dict:
    return {
        "isolated": None,
        "allowed": None,
        "applicable_policies": [],
        "matching_rules": [],
        "reason": reason,
    }


def _derive(prepared: tuple[dict, dict, dict, list[_Policy], list[dict]]) -> dict:
    model, namespaces, pods, policies, issues = prepared
    matching = _Matching(namespaces, pods)
    refs = {}
    placeholder = "sha256:" + "0" * 64
    for policy in policies:
        meta = policy.document["metadata"]
        refs[(meta["namespace"], meta["name"])] = {**meta, "policy_sha256": placeholder}
    rows = []
    for flow in sorted(model["flows"], key=lambda value: value["flow_id"]):
        source = (flow["source_pod"]["namespace"], flow["source_pod"]["name"])
        destination = (flow["destination_pod"]["namespace"], flow["destination_pod"]["name"])
        reason = (
            "unsupported_snapshot"
            if issues
            else "same_pod_exception_outside_subset"
            if source == destination
            else None
        )
        if reason:
            egress = _unassessed(reason)
            ingress = _unassessed(reason)
            outcome = "unassessed"
        else:
            egress = matching.direction(policies, refs, source, destination, flow, "Egress")
            ingress = matching.direction(policies, refs, destination, source, flow, "Ingress")
            outcome = (
                "allowed_in_supplied_policy_model"
                if egress["allowed"] and ingress["allowed"]
                else "blocked_in_supplied_policy_model"
            )
        rows.append({**flow, "egress": egress, "ingress": ingress, "outcome": outcome})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GC-D15-CMD",
        "group_commander_profile_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": model,
        "source_model_sha256": placeholder,
        "bounds": dict(_BOUNDS),
        "analysis_status": "incomplete"
        if issues or any(row["outcome"] == "unassessed" for row in rows)
        else "complete_declared_subset",
        "flow_results": rows,
        "incomplete_reasons": issues,
        "input_provenance": "operator_supplied_unverified",
        **_FLAGS,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    # The fixed-length address placeholders charge the complete output before hashes.
    report = _capture({"analysis_id": "KNP-" + "0" * 32, "analysis_sha256": placeholder, **body})
    del report["analysis_id"]
    del report["analysis_sha256"]
    hashes = {}
    for policy in policies:
        meta = policy.document["metadata"]
        hashes[(meta["namespace"], meta["name"])] = _hash(
            "sunderkey.kubernetes-network-policy-object.v1", policy.document
        )
    for row in report["flow_results"]:
        for field in ("ingress", "egress"):
            direction = row[field]
            for ref in direction["applicable_policies"]:
                ref["policy_sha256"] = hashes[(ref["namespace"], ref["name"])]
            for witness in direction["matching_rules"]:
                ref = witness["policy"]
                ref["policy_sha256"] = hashes[(ref["namespace"], ref["name"])]
    report["source_model_sha256"] = _hash(MODEL_DOMAIN, model)
    digest = _hash(DOMAIN, report)
    return {"analysis_id": "KNP-" + digest[7:39].upper(), "analysis_sha256": digest, **report}


def _report(value: Any) -> dict:
    actual = _capture(value)
    if type(actual) is not dict or "source_model" not in actual:
        raise KubernetesNetworkPolicyAnalysisError(
            "Analysis requires its exact supplied source model"
        )
    expected = _derive(_prepare(actual["source_model"]))
    if _canonical(actual) != _canonical(expected):
        raise KubernetesNetworkPolicyAnalysisError(
            "Analysis does not exactly replay its declared model"
        )
    return expected


@dataclass(frozen=True, slots=True)
class KubernetesNetworkPolicyAnalysis:
    """Detached unsigned model replay, never effective cluster access or live permission."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not KubernetesNetworkPolicyAnalysis:
            raise KubernetesNetworkPolicyAnalysisError(
                "Analysis must be the exact native wrapper family"
            )
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise KubernetesNetworkPolicyAnalysisError(
                "Analysis native slots are incomplete"
            ) from exc
        return _report(_decode(text))

    def to_dict(self) -> dict:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> KubernetesNetworkPolicyAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> KubernetesNetworkPolicyAnalysis:
        return cls(document)


def analyze_supplied_kubernetes_network_policy(model: dict) -> KubernetesNetworkPolicyAnalysis:
    """Evaluate only declared supported traffic rules over captured supplied inputs."""
    return KubernetesNetworkPolicyAnalysis.from_dict(_derive(_prepare(model)))


def verify_supplied_kubernetes_network_policy_analysis(
    report: KubernetesNetworkPolicyAnalysis, *, model: dict
) -> KubernetesNetworkPolicyAnalysis:
    """Require the separate exact original model, without authenticating its origin."""
    if type(report) is not KubernetesNetworkPolicyAnalysis:
        raise KubernetesNetworkPolicyAnalysisError(
            "Report must be the exact native analysis family"
        )
    actual = report.to_json()
    expected = analyze_supplied_kubernetes_network_policy(model)
    if actual != expected.to_json():
        raise KubernetesNetworkPolicyAnalysisError("Analysis differs from the exact original model")
    return KubernetesNetworkPolicyAnalysis.from_json(expected.to_json())


__all__ = [
    "CAPABILITY_ID",
    "COMPONENT_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "WAVE_ID",
    "KubernetesNetworkPolicyAnalysis",
    "KubernetesNetworkPolicyAnalysisError",
    "analyze_supplied_kubernetes_network_policy",
    "verify_supplied_kubernetes_network_policy_analysis",
]
