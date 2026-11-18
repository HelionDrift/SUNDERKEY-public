"""Supplied single-family Service/EndpointSlice relational consistency, without IO."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "kubernetes_supplied_service_endpoint_consistency"
PROFILE_ID = "AOE-GC-D15-S07"
CAPABILITY_ID = "army.gc.d15.s07"
VECTOR_ID = "AV-GC-D15-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S07"
WAVE_ID = "IW2-009"
BLUEPRINT_SHA256 = "sha256:ae690f9ea176aeee2f7cc66d6a5f7d1837a81ebac3c8cdaed7421c470745d875"
SEMANTICS_PROFILE = "kubernetes-v1.34.1-single-family-controller-supplied-subset.v1"
DOMAIN = "sunderkey.offline-kubernetes-service-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-kubernetes-service-model.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 32_768
MAX_REPORT_NODES = 65_536
MAX_MODEL_DEPTH = 20
MAX_REPORT_DEPTH = 24
MAX_STRING_BYTES = 512
MAX_PODS = 128
MAX_SLICES = 64
MAX_PORTS = 32
MAX_CONTAINER_PORTS = 64
MAX_LABELS = 32
MAX_ENDPOINTS = 256
MAX_TUPLES = 4096
MAX_ISSUES = 2048
MAX_WORK = 33_554_432
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "KSE-" + "0" * 32
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LABEL_PART = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?\Z")
_PROTOCOLS = {"TCP", "UDP", "SCTP"}
_MODEL_FIELDS = {
    "schema_version",
    "service",
    "pods",
    "endpoint_slices",
    "coverage",
    "unsupported_features",
}
_UNSUPPORTED = {
    "sidecars",
    "topology",
    "dual_stack",
    "service_mesh",
    "host_networking",
    "nondefault_controller_configuration",
    "additional_unprojected_semantics",
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "network",
        "provider",
        "credential",
        "process",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "inventory_completeness_proven",
        "controller_behavior_proven",
        "current_readiness_proven",
        "connectivity_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "model_depth": MAX_MODEL_DEPTH,
    "report_depth": MAX_REPORT_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "pods": MAX_PODS,
    "slices": MAX_SLICES,
    "service_and_slice_ports": MAX_PORTS,
    "ordinary_container_ports_per_pod": MAX_CONTAINER_PORTS,
    "labels_per_map": MAX_LABELS,
    "total_endpoints": MAX_ENDPOINTS,
    "expected_or_expanded_observed_tuples": MAX_TUPLES,
    "issues_per_kind": MAX_ISSUES,
    "cumulative_work_per_public_operation": MAX_WORK,
}
_LIMITATIONS = (
    "All sources, readiness, controller ownership and completeness are caller declarations.",
    "Only one ordinary ClusterIP Service, a nonempty equality selector and one IP family are used.",
    (
        "Pods must be declared Running and nonterminating; "
        "only ordinary container ports are projected."
    ),
    "Missing or ambiguous named ports do not predict controller omissions or routing behavior.",
    "Conflicting duplicates, unjoined identities and incomplete inventories withhold consistency.",
    (
        "Selectorless, manual, headless, ExternalName, sidecar, topology "
        "and dual-stack cases are excluded."
    ),
    (
        "No kube-proxy, network policy, address translation, connectivity "
        "or current readiness is proven."
    ),
    "The source address binds parsed canonical projections, not raw JSON byte provenance.",
    "No cluster, provider, credential, process, current authority or qualification is involved.",
    "Simultaneous software ceilings are finite and their maximum combinations need not fit.",
)


class KubernetesServiceAnalysisError(ValueError):
    """The exact supplied subset, cost ceiling or source replay was rejected."""


@dataclass
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_WORK - self.used:
            raise KubernetesServiceAnalysisError("Cumulative operation work budget exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    """Bound every repeated occurrence before copying, including escaped punctuation."""
    size = nodes = 0
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    active: set[int] = set()

    def charge_bytes(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise KubernetesServiceAnalysisError("Escaped document byte budget exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > depth_limit:
            raise KubernetesServiceAnalysisError("Native document node/depth budget exceeded")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise KubernetesServiceAnalysisError("Native string budget exceeded")
            charge_bytes(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise KubernetesServiceAnalysisError("Printable ASCII strings are required")
                if char in '\\"':
                    charge_bytes(1)
            return item
        if kind is bool:
            charge_bytes(4 if item else 5)
            return item
        if item is None:
            charge_bytes(4)
            return None
        if kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise KubernetesServiceAnalysisError("Signed 64-bit native integers are required")
            budget.charge(20)
            charge_bytes(len(str(item)))
            return item
        if kind not in (dict, list):
            raise KubernetesServiceAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise KubernetesServiceAnalysisError("Cyclic native inputs are rejected")
        count = len(item)
        children = count * (2 if kind is dict else 1)
        if children > node_limit - nodes:
            raise KubernetesServiceAnalysisError("Collection exceeds remaining native node budget")
        charge_bytes(2 + max(0, count - 1) + (count if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise KubernetesServiceAnalysisError("Exact native string keys are required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise KubernetesServiceAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise KubernetesServiceAnalysisError("Raw signed 64-bit integer budget exceeded")
    return int(text)


def _raw_string(text: str, start: int) -> int:
    index = start + 1
    count = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise KubernetesServiceAnalysisError("Incomplete JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise KubernetesServiceAnalysisError("Malformed Unicode escape")
                if not 32 <= int(digits, 16) <= 126:
                    raise KubernetesServiceAnalysisError("Raw strings exceed printable ASCII")
                index += 4
            elif escape not in '\\"/':
                raise KubernetesServiceAnalysisError("Unsupported JSON string escape")
        elif not 32 <= ord(char) <= 126:
            raise KubernetesServiceAnalysisError("Raw strings exceed printable ASCII")
        count += 1
        if count > MAX_STRING_BYTES:
            raise KubernetesServiceAnalysisError("Raw string budget exceeded")
        index += 1
    raise KubernetesServiceAnalysisError("Unterminated JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    if type(text) is not str or not text or len(text) > byte_limit or not text.isascii():
        raise KubernetesServiceAnalysisError("Bounded exact native ASCII JSON text required")
    budget.charge(len(text))
    index = nodes = 0
    stack = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise KubernetesServiceAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > depth_limit:
            raise KubernetesServiceAnalysisError("Pre-decoder node/depth budget exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise KubernetesServiceAnalysisError("Raw integer lexical budget exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise KubernetesServiceAnalysisError("Unterminated JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in rows:
            if key in result:
                raise KubernetesServiceAnalysisError("Duplicate JSON member")
            result[key] = child
        return result

    try:
        document = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise KubernetesServiceAnalysisError("Invalid bounded JSON document") from exc
    return _capture(document, budget, report=report)


def _fields(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise KubernetesServiceAnalysisError(f"{label} requires exact closed fields")
    return value


def _rows(value: Any, maximum: int, label: str) -> list:
    if type(value) is not list or len(value) > maximum:
        raise KubernetesServiceAnalysisError(f"{label} exceeds its native array bound")
    return value


def _boolean(value: Any, *, nullable: bool = False) -> None:
    if type(value) is not bool and not (nullable and value is None):
        raise KubernetesServiceAnalysisError("Exact native booleans are required")


def _name(value: Any, *, namespace: bool = False, service: bool = False) -> str:
    if type(value) is not str or not 1 <= len(value) <= (63 if namespace or service else 253):
        raise KubernetesServiceAnalysisError("Bounded DNS names are required")
    if any(_DNS_LABEL.fullmatch(part) is None for part in value.split(".")):
        raise KubernetesServiceAnalysisError("Unsupported DNS name spelling")
    if (namespace or service) and "." in value:
        raise KubernetesServiceAnalysisError("Namespace and Service names must be DNS labels")
    if service and not "a" <= value[0] <= "z":
        raise KubernetesServiceAnalysisError("Relaxed Service name feature is outside this subset")
    return value


def _uid(value: Any) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128 or any(c == " " for c in value):
        raise KubernetesServiceAnalysisError("Bounded nonempty opaque UID declarations required")
    return value


def _labels(value: Any) -> dict:
    if type(value) is not dict or len(value) > MAX_LABELS:
        raise KubernetesServiceAnalysisError("Label map exceeds its native bound")
    for key, label in value.items():
        parts = key.split("/")
        if len(parts) > 2 or _LABEL_PART.fullmatch(parts[-1]) is None:
            raise KubernetesServiceAnalysisError("Label key spelling is unsupported")
        if len(parts) == 2:
            _name(parts[0])
        if type(label) is not str or (label and _LABEL_PART.fullmatch(label) is None):
            raise KubernetesServiceAnalysisError("Label value spelling is unsupported")
    return value


def _port_name(value: Any, *, empty: bool = False, container: bool = False) -> str:
    if empty and value == "" and type(value) is str:
        return value
    if type(value) is not str or _DNS_LABEL.fullmatch(value) is None:
        raise KubernetesServiceAnalysisError("Unsupported port name spelling")
    if container and (len(value) > 15 or "--" in value or not any("a" <= c <= "z" for c in value)):
        raise KubernetesServiceAnalysisError("Named target port exceeds the IANA subset")
    return value


def _port_number(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise KubernetesServiceAnalysisError("Native ports from 1 through 65535 are required")
    return value


def _protocol(value: Any) -> str:
    if type(value) is not str or value not in _PROTOCOLS:
        raise KubernetesServiceAnalysisError("Explicit TCP, UDP or SCTP protocol required")
    return value


def _ip(value: Any, family: str) -> str:
    if type(value) is not str or not value or "%" in value:
        raise KubernetesServiceAnalysisError("Explicit canonical single-family IP required")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise KubernetesServiceAnalysisError("Malformed supplied IP address") from exc
    if str(address) != value or address.version != (4 if family == "IPv4" else 6):
        raise KubernetesServiceAnalysisError("IP spelling or family is outside this subset")
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise KubernetesServiceAnalysisError(
            "IP address is outside the declared Pod/Service subset"
        )
    return value


def _identity(row: dict) -> tuple[str, str, str]:
    return row["namespace"], row["name"], row["uid"]


def _identity_fields(row: Any, fields: set[str], label: str) -> dict:
    _fields(row, fields, label)
    _name(row["namespace"], namespace=True)
    _name(row["name"])
    _uid(row["uid"])
    return row


def _port_rows(rows: Any, *, service: bool = False, container: bool = False) -> list:
    ports = _rows(rows, MAX_CONTAINER_PORTS if container else MAX_PORTS, "Ports")
    if service and not ports:
        raise KubernetesServiceAnalysisError("Ordinary Service requires at least one port")
    names = set()
    sockets = set()
    for row in ports:
        fields = (
            {"name", "protocol", "port", "target_port"} if service else {"name", "protocol", "port"}
        )
        _fields(row, fields, "Port")
        _port_name(row["name"], empty=not service or len(ports) == 1, container=container)
        _protocol(row["protocol"])
        _port_number(row["port"])
        name_key = (row["name"], row["protocol"]) if container else row["name"]
        socket = (row["protocol"], row["port"])
        # Container ambiguity is retained, not arbitrarily resolved by iteration order.
        if not container and (name_key in names or (service and socket in sockets)):
            raise KubernetesServiceAnalysisError("Duplicate Service/slice port declarations")
        names.add(name_key)
        sockets.add(socket)
        if service:
            target = row["target_port"]
            if type(target) is int:
                _port_number(target)
            else:
                _port_name(target, container=True)
    return ports


def _validate(model: Any, budget: _Budget) -> None:
    _fields(model, _MODEL_FIELDS, "Model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesServiceAnalysisError("Native schema version 1 required")
    _fields(model["coverage"], {"pods_complete", "endpoint_slices_complete"}, "Coverage")
    for value in model["coverage"].values():
        _boolean(value)
    features = _rows(model["unsupported_features"], len(_UNSUPPORTED), "Unsupported features")
    for feature in features:
        if type(feature) is not str or feature not in _UNSUPPORTED:
            raise KubernetesServiceAnalysisError("Unknown unsupported-feature declaration")
    if len(set(features)) != len(features):
        raise KubernetesServiceAnalysisError("Duplicate unsupported-feature declaration")
    service = _identity_fields(
        model["service"],
        {
            "namespace",
            "name",
            "uid",
            "type",
            "cluster_ip",
            "ip_family",
            "selector",
            "ports",
            "publish_not_ready_addresses",
        },
        "Service",
    )
    _name(service["name"], service=True)
    if type(service["type"]) is not str or service["type"] != "ClusterIP":
        raise KubernetesServiceAnalysisError("Only an ordinary ClusterIP Service is supported")
    if type(service["ip_family"]) is not str or service["ip_family"] not in {"IPv4", "IPv6"}:
        raise KubernetesServiceAnalysisError("An explicit single IP family is required")
    _ip(service["cluster_ip"], service["ip_family"])
    if not _labels(service["selector"]):
        raise KubernetesServiceAnalysisError("Selectorless Services are outside this subset")
    _boolean(service["publish_not_ready_addresses"])
    budget.charge(
        len(_rows(service["ports"], MAX_PORTS, "Service ports")) + len(service["selector"])
    )
    _port_rows(service["ports"], service=True)
    identities = set()
    uids = {service["uid"]}
    for pod in _rows(model["pods"], MAX_PODS, "Pods"):
        budget.charge(8)
        _identity_fields(
            pod,
            {
                "namespace",
                "name",
                "uid",
                "labels",
                "phase",
                "terminating",
                "ip",
                "ready",
                "container_ports",
            },
            "Pod",
        )
        if (pod["namespace"], pod["name"]) in identities or pod["uid"] in uids:
            raise KubernetesServiceAnalysisError("Duplicate or conflicting Pod identity")
        identities.add((pod["namespace"], pod["name"]))
        uids.add(pod["uid"])
        _labels(pod["labels"])
        if type(pod["phase"]) is not str or pod["phase"] != "Running":
            raise KubernetesServiceAnalysisError("Only declared Running Pods are supported")
        _boolean(pod["terminating"])
        if pod["terminating"]:
            raise KubernetesServiceAnalysisError("Terminating Pods are outside this subset")
        _boolean(pod["ready"], nullable=True)
        if pod["ip"] is not None:
            _ip(pod["ip"], service["ip_family"])
        budget.charge(
            len(_rows(pod["container_ports"], MAX_CONTAINER_PORTS, "Container ports"))
            + len(pod["labels"])
        )
        _port_rows(pod["container_ports"], container=True)
    slice_names = set()
    endpoints = expanded = 0
    for slice_ in _rows(model["endpoint_slices"], MAX_SLICES, "EndpointSlices"):
        budget.charge(8)
        _identity_fields(
            slice_,
            {
                "namespace",
                "name",
                "uid",
                "address_type",
                "service_name",
                "managed_by",
                "owner",
                "ports",
                "endpoints",
            },
            "EndpointSlice",
        )
        if (slice_["namespace"], slice_["name"]) in slice_names or slice_["uid"] in uids:
            raise KubernetesServiceAnalysisError("Duplicate or conflicting EndpointSlice identity")
        slice_names.add((slice_["namespace"], slice_["name"]))
        uids.add(slice_["uid"])
        if type(slice_["address_type"]) is not str or slice_["address_type"] not in {
            "IPv4",
            "IPv6",
        }:
            raise KubernetesServiceAnalysisError("Only explicit IPv4/IPv6 slices are supported")
        _name(slice_["service_name"], service=True)
        if type(slice_["managed_by"]) is not str or not slice_["managed_by"]:
            raise KubernetesServiceAnalysisError("Explicit managed-by declaration required")
        owner = _fields(
            slice_["owner"], {"api_version", "kind", "name", "uid", "controller"}, "Owner"
        )
        _name(owner["name"])
        _uid(owner["uid"])
        if type(owner["api_version"]) is not str or type(owner["kind"]) is not str:
            raise KubernetesServiceAnalysisError("Owner kind and API version must be native text")
        _boolean(owner["controller"])
        budget.charge(len(_rows(slice_["ports"], MAX_PORTS, "Slice ports")))
        _port_rows(slice_["ports"])
        rows = _rows(slice_["endpoints"], MAX_ENDPOINTS, "Slice endpoints")
        endpoints += len(rows)
        expanded += len(rows) * len(slice_["ports"])
        budget.charge(len(rows) + len(rows) * len(slice_["ports"]))
        if endpoints > MAX_ENDPOINTS or expanded > MAX_TUPLES:
            raise KubernetesServiceAnalysisError(
                "Aggregate endpoint/tuple expansion budget exceeded"
            )
        for endpoint in rows:
            _fields(endpoint, {"addresses", "target_ref", "conditions"}, "Endpoint")
            addresses = _rows(endpoint["addresses"], 1, "Single-family endpoint addresses")
            if len(addresses) != 1:
                raise KubernetesServiceAnalysisError(
                    "Exactly one projected endpoint address required"
                )
            _ip(addresses[0], slice_["address_type"])
            ref = _identity_fields(
                endpoint["target_ref"], {"kind", "namespace", "name", "uid"}, "Target reference"
            )
            if type(ref["kind"]) is not str:
                raise KubernetesServiceAnalysisError("Target reference kind must be native text")
            _fields(endpoint["conditions"], {"ready", "serving", "terminating"}, "Conditions")
            for value in endpoint["conditions"].values():
                _boolean(value, nullable=True)


class _Retained:
    def __init__(self, size: int, nodes: int, budget: _Budget) -> None:
        self.size = size
        self.nodes = nodes
        self.budget = budget

    def row(self, value: dict) -> dict:
        owned, size, nodes = _capture(value, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise KubernetesServiceAnalysisError("Cumulative retained result budget exceeded")
        self.size += size + 1
        self.nodes += nodes
        return owned


def _tuple(pod: dict, address: str, port: dict, conditions: dict) -> dict:
    return {
        "pod_namespace": pod["namespace"],
        "pod_name": pod["name"],
        "pod_uid": pod["uid"],
        "address": address,
        "port_name": port["name"],
        "protocol": port["protocol"],
        "port": port["port"],
        "ready": conditions["ready"],
        "serving": conditions["serving"],
        "terminating": conditions["terminating"],
    }


def _key(row: dict) -> tuple:
    return (
        row["pod_namespace"],
        row["pod_name"],
        row["pod_uid"],
        row["address"],
        row["port_name"],
        row["protocol"],
        row["port"],
    )


def _conditions(row: dict) -> tuple:
    return row["ready"], row["serving"], row["terminating"]


def _logic(model: dict, model_size: int, model_nodes: int, budget: _Budget) -> dict:
    service = model["service"]
    retained = _Retained(model_size, model_nodes, budget)
    issues: dict[str, list[dict]] = {"uncertainties": [], "contradictions": []}

    def issue(kind: str, code: str, path: str) -> None:
        if len(issues[kind]) >= MAX_ISSUES:
            raise KubernetesServiceAnalysisError("Retained issue count budget exceeded")
        issues[kind].append(retained.row({"code": code, "source_path": path}))

    for key, complete in model["coverage"].items():
        if not complete:
            issue("uncertainties", "inventory_not_declared_complete", f"coverage.{key}")
    for feature in sorted(model["unsupported_features"]):
        issue("uncertainties", "unsupported_declared_feature", f"unsupported_features.{feature}")
    pods = {_identity(pod): pod for pod in model["pods"]}
    selected = []
    expected = {}
    resolutions = {}
    for index, pod in enumerate(model["pods"]):
        budget.charge(len(service["selector"]) + 1)
        if pod["namespace"] != service["namespace"] or not all(
            pod["labels"].get(key) == value for key, value in service["selector"].items()
        ):
            continue
        selected.append(retained.row({key: pod[key] for key in ("namespace", "name", "uid")}))
        path = f"pods[{index}]"
        if pod["ready"] is None:
            issue("uncertainties", "pod_ready_not_declared", path)
        if pod["ip"] is None:
            issue("uncertainties", "pod_address_not_declared", path)
        conditions = {
            "ready": True if service["publish_not_ready_addresses"] else pod["ready"],
            "serving": pod["ready"],
            "terminating": False,
        }
        for port in service["ports"]:
            target = port["target_port"]
            budget.charge(1)
            if type(target) is str:
                matches = []
                for candidate in pod["container_ports"]:
                    budget.charge(1)
                    if candidate["name"] == target and candidate["protocol"] == port["protocol"]:
                        matches.append(candidate["port"])
                if len(matches) != 1:
                    issue(
                        "uncertainties",
                        "named_target_port_missing"
                        if not matches
                        else "named_target_port_ambiguous",
                        f"{path}.container_ports:{port['name']}",
                    )
                    continue
                target = matches[0]
            resolutions[(_identity(pod), port["name"], port["protocol"])] = target
            if pod["ip"] is None:
                continue
            if len(expected) >= MAX_TUPLES:
                raise KubernetesServiceAnalysisError("Expected tuple count budget exceeded")
            row = retained.row(
                _tuple(
                    pod,
                    pod["ip"],
                    {"name": port["name"], "protocol": port["protocol"], "port": target},
                    conditions,
                )
            )
            expected[_key(row)] = row
    selected_ids = {_identity(row) for row in selected}
    address_identities: dict[str, set[tuple]] = {}
    for pod in model["pods"]:
        budget.charge(1)
        if pod["ip"] is not None:
            address_identities.setdefault(pod["ip"], set()).add(_identity(pod))
    for address, identities in address_identities.items():
        budget.charge(len(identities))
        if len(identities) > 1 and identities & selected_ids:
            issue("uncertainties", "pod_address_identity_is_ambiguous", f"pods.ip:{address}")
    observed: dict[tuple, dict] = {}
    observations_by_network: dict[tuple, set[tuple]] = {}
    duplicates = 0
    for index, slice_ in enumerate(model["endpoint_slices"]):
        path = f"endpoint_slices[{index}]"
        owner = slice_["owner"]
        joined = (
            slice_["namespace"] == service["namespace"]
            and slice_["service_name"] == service["name"]
            and slice_["managed_by"] == "endpointslice-controller.k8s.io"
            and owner["api_version"] == "v1"
            and owner["kind"] == "Service"
            and owner["name"] == service["name"]
            and owner["uid"] == service["uid"]
            and owner["controller"]
            and slice_["address_type"] == service["ip_family"]
        )
        budget.charge(9)
        if not joined:
            issue("uncertainties", "slice_service_ownership_or_family_not_joined", path)
            continue
        for endpoint_index, endpoint in enumerate(slice_["endpoints"]):
            endpoint_path = f"{path}.endpoints[{endpoint_index}]"
            ref = endpoint["target_ref"]
            pod = pods.get(_identity(ref)) if ref["kind"] == "Pod" else None
            budget.charge(1)
            if pod is None:
                issue("uncertainties", "endpoint_pod_identity_not_joined", endpoint_path)
            elif _identity(pod) not in selected_ids:
                issue("contradictions", "endpoint_pod_not_selected", endpoint_path)
            elif pod["ip"] is not None and endpoint["addresses"][0] != pod["ip"]:
                issue("contradictions", "endpoint_address_differs_from_pod", endpoint_path)
            conditions = endpoint["conditions"]
            if any(value is None for value in conditions.values()):
                issue("uncertainties", "endpoint_conditions_not_fully_declared", endpoint_path)
            if pod is not None and _identity(pod) in selected_ids:
                wanted = {
                    "ready": True if service["publish_not_ready_addresses"] else pod["ready"],
                    "serving": pod["ready"],
                    "terminating": False,
                }
                for name, value in wanted.items():
                    budget.charge(1)
                    if (
                        value is not None
                        and conditions[name] is not None
                        and value != conditions[name]
                    ):
                        issue(
                            "contradictions",
                            f"endpoint_{name}_differs_from_pod_projection",
                            endpoint_path,
                        )
            if not slice_["ports"]:
                issue("uncertainties", "endpoint_has_no_projected_ports", endpoint_path)
            for port in slice_["ports"]:
                budget.charge(1)
                row = _tuple(ref, endpoint["addresses"][0], port, conditions)
                key = _key(row)
                observation_key = key + _conditions(row)
                # Repeated observations consume work even when the retained row is deduplicated.
                budget.charge(10)
                if observation_key in observed:
                    duplicates += 1
                else:
                    if len(observed) >= MAX_TUPLES:
                        raise KubernetesServiceAnalysisError("Observed tuple count budget exceeded")
                    observed[observation_key] = retained.row(row)
                network_key = (row["address"], row["port_name"], row["protocol"], row["port"])
                known = observations_by_network.setdefault(network_key, set())
                if observation_key not in known and known:
                    issue(
                        "uncertainties",
                        "conflicting_duplicate_endpoint_observations",
                        endpoint_path,
                    )
                known.add(observation_key)
                resolution = resolutions.get((_identity(ref), port["name"], port["protocol"]))
                if resolution is not None and resolution != port["port"]:
                    issue(
                        "contradictions",
                        "endpoint_port_differs_from_named_or_numeric_target",
                        endpoint_path,
                    )
    # Coverage-dependent absence/extra claims are withheld if any source remains unresolved.
    missing = []
    unexpected = []
    if not issues["uncertainties"]:
        budget.charge(len(observed) + len(expected))
        observed_by_key = {_key(row): row for row in observed.values()}
        observed_keys = observed_by_key.keys()
        for key in sorted(expected.keys() - observed_keys):
            missing.append(retained.row(expected[key]))
        for key in sorted(observed_keys - expected.keys()):
            unexpected.append(retained.row(observed_by_key[key]))
    if issues["uncertainties"]:
        status = "inconclusive"
    elif issues["contradictions"] or missing or unexpected:
        status = "inconsistent_supplied_subset"
    else:
        status = "consistent_supplied_subset"
    budget.charge(
        4 * (len(expected) + len(observed) + len(selected) + len(missing) + len(unexpected))
    )
    return {
        "summary": {
            "status": status,
            "selected_pod_count": len(selected),
            "expected_tuple_count": len(expected),
            "observed_tuple_count": len(observed),
            "identical_duplicate_tuple_count": duplicates,
        },
        "selected_pods": sorted(selected, key=_identity),
        "expected_endpoint_tuples": [expected[key] for key in sorted(expected)],
        "observed_endpoint_tuples": sorted(
            observed.values(), key=lambda row: _key(row) + tuple(str(v) for v in _conditions(row))
        ),
        "missing_endpoint_tuples": missing,
        "unexpected_endpoint_tuples": unexpected,
        "uncertainties": sorted(
            issues["uncertainties"], key=lambda row: (row["code"], row["source_path"])
        ),
        "contradictions": sorted(
            issues["contradictions"], key=lambda row: (row["code"], row["source_path"])
        ),
    }


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


@dataclass
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    """Own and fund all semantic/result construction without computing any address."""
    owned, model_size, model_nodes = _capture(model, budget)
    _validate(owned, budget)
    logic = _logic(owned, model_size, model_nodes, budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
        "effects": _EFFECTS,
        "claims": _FLAGS,
        "bounds": _BOUNDS,
        "limitations": list(_LIMITATIONS),
        **logic,
    }
    # Charge the complete retained report, including address fields, before any digest.
    document, size, _ = _capture(document, budget, report=True)
    budget.charge(4 * size + 2 * model_size + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, size)


def _materialize(plan: _Plan) -> str:
    """Materialize fixed-width addresses only after the caller funds every required pass."""
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "KSE-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan, int]:
    document, size, _ = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise KubernetesServiceAnalysisError("Report requires its original embedded source model")
    plan = _plan(document["source_model"], budget)
    budget.charge(2 * size + plan.size)
    return document, plan, size


def _compare_replay(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if actual != expected or text != actual:
        raise KubernetesServiceAnalysisError("Canonical report does not replay its complete source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan, _ = _replay_plan(text, budget)
    _compare_replay(text, document, _materialize(plan))
    return document


@dataclass(frozen=True, slots=True)
class KubernetesServiceAnalysis:
    document_json: str

    def __post_init__(self) -> None:
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> KubernetesServiceAnalysis:
        if cls is not KubernetesServiceAnalysis:
            raise KubernetesServiceAnalysisError("Exact native report family is required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> KubernetesServiceAnalysis:
        if cls is not KubernetesServiceAnalysis:
            raise KubernetesServiceAnalysisError("Exact native report family is required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        if type(self) is not KubernetesServiceAnalysis or not hasattr(self, "document_json"):
            raise KubernetesServiceAnalysisError("Exact complete report wrapper is required")
        return _replay(self.document_json, _Budget())

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def _owned(text: str) -> KubernetesServiceAnalysis:
    result = object.__new__(KubernetesServiceAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_kubernetes_service_endpoints(model: Any) -> KubernetesServiceAnalysis:
    """Derive relational observations over an owned, unauthenticated supplied projection."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_kubernetes_service_endpoints_bytes(
    *, model_bytes: Any
) -> KubernetesServiceAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise KubernetesServiceAnalysisError("Bounded exact native model bytes required")
    if not model_bytes.isascii():
        raise KubernetesServiceAnalysisError("Printable-ASCII JSON subset required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    model, _, _ = _decode(model_bytes.decode("ascii"), budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_kubernetes_service_analysis(
    report: Any, *, model: Any
) -> KubernetesServiceAnalysis:
    if type(report) is not KubernetesServiceAnalysis or not hasattr(report, "document_json"):
        raise KubernetesServiceAnalysisError("Exact complete report wrapper required")
    budget = _Budget()
    actual, embedded_plan, size = _replay_plan(report.document_json, budget)
    original_plan = _plan(model, budget)
    budget.charge(size + original_plan.size)
    # Both complete derivations and all comparisons are funded before the first digest.
    embedded_expected = _materialize(embedded_plan)
    original_expected = _materialize(original_plan)
    _compare_replay(report.document_json, actual, embedded_expected)
    if _canonical(actual) != original_expected:
        raise KubernetesServiceAnalysisError(
            "Report does not match separately supplied original model"
        )
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh inert supplied projection, not an acquired or authenticated cluster snapshot."""
    service = {
        "namespace": "demo",
        "name": "api",
        "uid": "service-api-uid",
        "type": "ClusterIP",
        "cluster_ip": "10.96.0.10",
        "ip_family": "IPv4",
        "selector": {"app": "api"},
        "ports": [{"name": "http", "protocol": "TCP", "port": 80, "target_port": "web"}],
        "publish_not_ready_addresses": False,
    }
    pods = []
    for name, address, namespace, ready, target in (
        ("api-a", "10.0.0.1", "demo", True, 8080),
        ("api-b", "10.0.0.2", "demo", False, 9090),
        ("api-c", "10.0.0.3", "other", True, 8080),
    ):
        pods.append(
            {
                "namespace": namespace,
                "name": name,
                "uid": f"uid-{namespace}-{name}",
                "labels": {"app": "api"},
                "phase": "Running",
                "terminating": False,
                "ip": address,
                "ready": ready,
                "container_ports": [{"name": "web", "protocol": "TCP", "port": target}],
            }
        )
    slices = []
    for index in range(2):
        pod = pods[index]
        name = "slice-a" if index == 0 else "slice-b"
        slices.append(
            {
                "namespace": "demo",
                "name": name,
                "uid": f"uid-{name}",
                "address_type": "IPv4",
                "service_name": "api",
                "managed_by": "endpointslice-controller.k8s.io",
                "owner": {
                    "api_version": "v1",
                    "kind": "Service",
                    "name": "api",
                    "uid": "service-api-uid",
                    "controller": True,
                },
                "ports": [
                    {"name": "http", "protocol": "TCP", "port": 8080 if index == 0 else 9090}
                ],
                "endpoints": [
                    {
                        "addresses": [pod["ip"]],
                        "target_ref": {
                            "kind": "Pod",
                            "namespace": "demo",
                            "name": pod["name"],
                            "uid": pod["uid"],
                        },
                        "conditions": {
                            "ready": pod["ready"],
                            "serving": pod["ready"],
                            "terminating": False,
                        },
                    }
                ],
            }
        )
    return {
        "schema_version": 1,
        "service": service,
        "pods": pods,
        "endpoint_slices": slices,
        "coverage": {"pods_complete": True, "endpoint_slices_complete": True},
        "unsupported_features": [],
    }
