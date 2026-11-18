"""Finite SG/NACL predicates over explicit, unauthenticated same-VPC declarations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "aws_supplied_vpc_flow_predicates"
PROFILE_ID = "AOE-GC-D14-S03"
CAPABILITY_ID = "army.gc.d14.s03"
VECTOR_ID = "AV-GC-D14-S03-01"
WAVE_ID = "IW2-006"
BLUEPRINT_SHA256 = "sha256:8c5b708f933616e92a8f22e5b46063b8299db660fac1f31b4aa92df983bf9a23"
DOMAIN = "sunderkey.aws-vpc-flow-analysis.v1"
MODEL_DOMAIN = "sunderkey.aws-vpc-flow-model.v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NATIVE_DEPTH = 16
MAX_NATIVE_NODES = 32768
MAX_STRING_BYTES = 512
MAX_SUBNETS = 32
MAX_ENDPOINTS = 64
MAX_SECURITY_GROUPS = 64
MAX_NETWORK_ACLS = 32
MAX_FLOWS = 64
MAX_GROUP_REFS = 16
MAX_DIRECTION_RULES = 64
MAX_TOTAL_RULES = 2048
MAX_WORK = 1_000_000
MAX_WITNESSES = 1024
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {
    "schema_version",
    "vpc",
    "subnets",
    "endpoints",
    "security_groups",
    "network_acls",
    "flows",
}
_FLOW_FIELDS = {
    "flow_id",
    "source_endpoint_id",
    "destination_endpoint_id",
    "protocol",
    "source_port",
    "destination_port",
    "traffic_class",
    "return_mode",
}
_PACKET_FIELDS = {
    "source_endpoint_id",
    "destination_endpoint_id",
    "protocol",
    "source_port",
    "destination_port",
}
_GATE_NAMES = (
    "source_security_group_egress",
    "destination_security_group_ingress",
    "source_network_acl_egress",
    "destination_network_acl_ingress",
)
_BASES = {
    "known_security_group_allow",
    "complete_security_group_no_allow",
    "incomplete_security_group_membership_or_rules",
    "network_acl_first_match",
    "complete_network_acl_default_deny",
    "incomplete_network_acl_rules",
    "not_applied_same_subnet",
    "conditional_stateful_response",
    "return_mode_unknown",
    "forward_premise_not_satisfied",
    "traffic_class_outside_subset",
    "endpoint_address_outside_subset",
    "same_endpoint_outside_subset",
}
_OUTCOMES = {
    "allowed_in_supplied_policy_model",
    "blocked_in_supplied_policy_model",
    "unknown_in_supplied_policy_model",
    "conditionally_allowed_in_supplied_policy_model",
    "unassessed",
}
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_depth": MAX_NATIVE_DEPTH,
    "native_nodes": MAX_NATIVE_NODES,
    "string_bytes": MAX_STRING_BYTES,
    "subnets": MAX_SUBNETS,
    "endpoints": MAX_ENDPOINTS,
    "security_groups": MAX_SECURITY_GROUPS,
    "network_acls": MAX_NETWORK_ACLS,
    "flows": MAX_FLOWS,
    "groups_per_endpoint": MAX_GROUP_REFS,
    "rules_per_direction": MAX_DIRECTION_RULES,
    "total_rules": MAX_TOTAL_RULES,
    "matching_work": MAX_WORK,
    "witnesses": MAX_WITNESSES,
}
_FLAGS = dict.fromkeys(
    (
        "snapshot_authenticated",
        "snapshot_complete",
        "routing_verified",
        "conntrack_verified",
        "provider_exemptions_verified",
        "reachability_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
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
    "All sources, completeness flags and response assumptions are caller declarations.",
    "Only one supplied VPC CIDR and address family with one address per ENI is modeled.",
    "Only distinct direct ENI TCP/UDP tuples and CIDR-only rules are evaluated.",
    "Conditional SG response allowance does not prove a connection was established or tracked.",
    "No routes, NAT, middleboxes, peering, SG references or prefix lists are evaluated.",
    "Provider-exempt, unknown, reserved and special endpoint traffic remains unassessed.",
    "No acquisition, clock, credentials, transport, deployment or live authorization is involved.",
)


class AwsVpcFlowAnalysisError(ValueError):
    """The supplied projection is malformed, unbounded or fails exact replay."""


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
    nodes = size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise AwsVpcFlowAnalysisError("Document exceeds its aggregate byte bound")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AwsVpcFlowAnalysisError("Document exceeds node or depth bounds")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise AwsVpcFlowAnalysisError("String exceeds its byte bound")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise AwsVpcFlowAnalysisError("Strings must be printable ASCII")
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
                raise AwsVpcFlowAnalysisError("Integer exceeds signed63 magnitude")
            charge(len(str(item)))
            return item
        if kind not in {dict, list}:
            raise AwsVpcFlowAnalysisError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise AwsVpcFlowAnalysisError("Cyclic native inputs are refused")
        if len(item) > MAX_NATIVE_NODES - nodes:
            raise AwsVpcFlowAnalysisError("Collection exceeds remaining node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise AwsVpcFlowAnalysisError("Object keys must be native strings")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1)


def _json(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise AwsVpcFlowAnalysisError("JSON must be bounded native ASCII text")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise AwsVpcFlowAnalysisError("JSON scalar exceeds depth bound")
            index += 1
            nodes += 1
            length = 0
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
                        raise AwsVpcFlowAnalysisError("Incomplete JSON escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise AwsVpcFlowAnalysisError("Malformed Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise AwsVpcFlowAnalysisError("JSON is outside printable ASCII")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise AwsVpcFlowAnalysisError("Unsupported JSON escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise AwsVpcFlowAnalysisError("JSON is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise AwsVpcFlowAnalysisError("JSON string exceeds its bound")
            if not closed:
                raise AwsVpcFlowAnalysisError("Incomplete JSON string")
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
                raise AwsVpcFlowAnalysisError("JSON scalar exceeds depth bound")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            token = text[start:index]
            nodes += 1
            if token not in {"true", "false", "null"} and (
                _INTEGER.fullmatch(token) is None or int(token).bit_length() > 63
            ):
                raise AwsVpcFlowAnalysisError("JSON number is outside integer subset")
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise AwsVpcFlowAnalysisError("JSON exceeds node or depth bounds")
    if depth:
        raise AwsVpcFlowAnalysisError("Incomplete JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise AwsVpcFlowAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def number(_: str) -> None:
        raise AwsVpcFlowAnalysisError("Fractional and nonfinite numbers are unsupported")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_float=number, parse_constant=number)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, AwsVpcFlowAnalysisError):
            raise
        raise AwsVpcFlowAnalysisError("Malformed JSON document") from exc
    return _capture(value)


def _fields(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise AwsVpcFlowAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _list(value: Any, maximum: int, label: str) -> list:
    if type(value) is not list or len(value) > maximum:
        raise AwsVpcFlowAnalysisError(f"{label} exceeds its collection bound")
    return value


def _id(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AwsVpcFlowAnalysisError("Resource identity is outside the supported spelling")
    return value


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise AwsVpcFlowAnalysisError("Completeness and flags require native booleans")
    return value


def _port(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise AwsVpcFlowAnalysisError("Port must be a native integer from 0 through 65535")
    return value


def _network(value: Any, family: int | None = None) -> Any:
    if type(value) is not str or len(value) > 64 or "%" in value:
        raise AwsVpcFlowAnalysisError("CIDR must have bounded canonical spelling")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise AwsVpcFlowAnalysisError("CIDR is malformed or has host bits") from exc
    if str(network) != value or (family is not None and network.version != family):
        raise AwsVpcFlowAnalysisError("CIDR must be canonical and use the supplied family")
    return network


def _address(value: Any, family: int) -> Any:
    if type(value) is not str or len(value) > 45 or "%" in value:
        raise AwsVpcFlowAnalysisError("Address must have bounded canonical spelling")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AwsVpcFlowAnalysisError("Endpoint address is malformed") from exc
    if str(address) != value or address.version != family:
        raise AwsVpcFlowAnalysisError("Address must be canonical and use the supplied family")
    return address


@dataclass(frozen=True, slots=True)
class _Rule:
    document: dict
    network: Any
    index: int


@dataclass(frozen=True, slots=True)
class _Policy:
    document: dict
    ingress: tuple[_Rule, ...]
    egress: tuple[_Rule, ...]


def _flow(value: Any) -> dict:
    obj = _fields(value, _FLOW_FIELDS, "Flow")
    for field in ("flow_id", "source_endpoint_id", "destination_endpoint_id"):
        _id(obj[field])
    if type(obj["protocol"]) is not str or obj["protocol"] not in {"TCP", "UDP"}:
        raise AwsVpcFlowAnalysisError("Flow protocol must be TCP or UDP")
    _port(obj["source_port"])
    _port(obj["destination_port"])
    if type(obj["traffic_class"]) is not str or obj["traffic_class"] not in {
        "ordinary_eni_to_eni",
        "provider_exempt",
        "unknown",
    }:
        raise AwsVpcFlowAnalysisError("Traffic class is unsupported")
    if type(obj["return_mode"]) is not str or obj["return_mode"] not in {
        "assumed_tracked_response",
        "independent_reverse_packet",
        "unknown",
    }:
        raise AwsVpcFlowAnalysisError("Return mode is unsupported")
    return obj


def _prepare(value: Any) -> tuple:
    model = _fields(_capture(value), _MODEL_FIELDS, "VPC model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AwsVpcFlowAnalysisError("Model schema must be native integer one")
    vpc = _fields(model["vpc"], {"vpc_id", "cidr"}, "VPC")
    _id(vpc["vpc_id"])
    network = _network(vpc["cidr"])
    issues = []
    total_rules = 0

    def policies(field: str, limit: int, kind: str) -> dict:
        nonlocal total_rules
        result = {}
        identity_field = "security_group_id" if kind == "security_group" else "network_acl_id"
        for source_index, obj in enumerate(_list(model[field], limit, field)):
            _fields(
                obj,
                {identity_field, "ingress_complete", "egress_complete", "ingress", "egress"},
                field,
            )
            identifier = _id(obj[identity_field])
            if identifier in result:
                raise AwsVpcFlowAnalysisError("Duplicate policy identity")
            directions = {}
            group_rule_ids = set()
            for direction in ("ingress", "egress"):
                complete = _bool(obj[direction + "_complete"])
                if not complete:
                    issues.append(
                        {
                            "source_path": f"{field}[{source_index}].{direction}",
                            "code": "incomplete_rule_declaration",
                        }
                    )
                rules = []
                numbers = set()
                for index, entry in enumerate(
                    _list(obj[direction], MAX_DIRECTION_RULES, "Policy rules")
                ):
                    total_rules += 1
                    if total_rules > MAX_TOTAL_RULES:
                        raise AwsVpcFlowAnalysisError("Total rule count exceeds its bound")
                    fields = {"protocol", "cidr", "from_port", "to_port"}
                    fields |= {"rule_id"} if kind == "security_group" else {"rule_number", "action"}
                    _fields(entry, fields, "Policy rule")
                    protocol = entry["protocol"]
                    if type(protocol) is not str or protocol not in {"TCP", "UDP", "ALL"}:
                        raise AwsVpcFlowAnalysisError("Rule protocol is unsupported")
                    if protocol == "ALL":
                        if entry["from_port"] is not None or entry["to_port"] is not None:
                            raise AwsVpcFlowAnalysisError("ALL rules must have null port bounds")
                    elif _port(entry["from_port"]) > _port(entry["to_port"]):
                        raise AwsVpcFlowAnalysisError("Rule range is reversed")
                    if kind == "security_group":
                        rule_id = _id(entry["rule_id"])
                        if rule_id in group_rule_ids:
                            raise AwsVpcFlowAnalysisError("Duplicate SG rule identity")
                        group_rule_ids.add(rule_id)
                    else:
                        number = entry["rule_number"]
                        if type(number) is not int or not 1 <= number <= 32766 or number in numbers:
                            raise AwsVpcFlowAnalysisError(
                                "ACL rule number is malformed or duplicated"
                            )
                        numbers.add(number)
                        if type(entry["action"]) is not str or entry["action"] not in {
                            "allow",
                            "deny",
                        }:
                            raise AwsVpcFlowAnalysisError("ACL action must be allow or deny")
                    rules.append(_Rule(entry, _network(entry["cidr"], network.version), index))
                if kind == "network_acl":
                    rules.sort(key=lambda rule: rule.document["rule_number"])
                directions[direction] = tuple(rules)
            result[identifier] = _Policy(obj, directions["ingress"], directions["egress"])
        return result

    groups = policies("security_groups", MAX_SECURITY_GROUPS, "security_group")
    acls = policies("network_acls", MAX_NETWORK_ACLS, "network_acl")
    subnets = {}
    for obj in _list(model["subnets"], MAX_SUBNETS, "Subnets"):
        _fields(obj, {"subnet_id", "cidr", "network_acl_id"}, "Subnet")
        identifier = _id(obj["subnet_id"])
        subnet = _network(obj["cidr"], network.version)
        if identifier in subnets or not subnet.subnet_of(network):
            raise AwsVpcFlowAnalysisError("Subnet identity is duplicated or outside VPC CIDR")
        if _id(obj["network_acl_id"]) not in acls:
            raise AwsVpcFlowAnalysisError("Subnet ACL is absent from the supplied model")
        if any(subnet.overlaps(existing[1]) for existing in subnets.values()):
            raise AwsVpcFlowAnalysisError("Distinct supplied subnets overlap")
        subnets[identifier] = (obj, subnet)
    endpoints = {}
    eni_ids = set()
    addresses = set()
    for index, obj in enumerate(_list(model["endpoints"], MAX_ENDPOINTS, "Endpoints")):
        _fields(
            obj,
            {
                "endpoint_id",
                "eni_id",
                "subnet_id",
                "address",
                "security_group_ids",
                "security_groups_complete",
            },
            "Endpoint",
        )
        identifier = _id(obj["endpoint_id"])
        eni = _id(obj["eni_id"])
        subnet_id = _id(obj["subnet_id"])
        if identifier in endpoints or eni in eni_ids or subnet_id not in subnets:
            raise AwsVpcFlowAnalysisError("Endpoint/ENI is duplicated or its subnet is absent")
        address = _address(obj["address"], network.version)
        subnet = subnets[subnet_id][1]
        if address not in subnet or address in addresses:
            raise AwsVpcFlowAnalysisError("Endpoint address is duplicated or outside its subnet")
        refs = _list(obj["security_group_ids"], MAX_GROUP_REFS, "Endpoint SG references")
        if not refs or len(refs) != len(set(_id(ref) for ref in refs)):
            raise AwsVpcFlowAnalysisError("Endpoint needs unique explicit SG references")
        if any(ref not in groups for ref in refs):
            raise AwsVpcFlowAnalysisError("Endpoint references an absent SG")
        if not _bool(obj["security_groups_complete"]):
            issues.append(
                {
                    "source_path": f"endpoints[{index}].security_group_ids",
                    "code": "incomplete_group_membership",
                }
            )
        numeric = int(address)
        special = (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or getattr(address, "ipv4_mapped", None) is not None
            or numeric - int(subnet.network_address) < 4
            or address == subnet.broadcast_address
            or str(address) in {"fd00:ec2::123", "fd00:ec2::253", "fd00:ec2::254"}
        )
        if special:
            issues.append(
                {
                    "source_path": f"endpoints[{index}].address",
                    "code": "reserved_or_special_address_outside_subset",
                }
            )
        endpoints[identifier] = (obj, address, special)
        eni_ids.add(eni)
        addresses.add(address)
    flow_ids = set()
    for obj in _list(model["flows"], MAX_FLOWS, "Flows"):
        flow = _flow(obj)
        if flow["flow_id"] in flow_ids:
            raise AwsVpcFlowAnalysisError("Duplicate flow identity")
        flow_ids.add(flow["flow_id"])
        if (
            flow["source_endpoint_id"] not in endpoints
            or flow["destination_endpoint_id"] not in endpoints
        ):
            raise AwsVpcFlowAnalysisError("Flow endpoint is absent from the supplied model")
    return model, subnets, endpoints, groups, acls, issues


class _Matching:
    def __init__(self, subnets: dict, endpoints: dict, groups: dict, acls: dict) -> None:
        self.subnets = subnets
        self.endpoints = endpoints
        self.groups = groups
        self.acls = acls
        self.work = self.witnesses = 0

    def charge(self) -> None:
        self.work += 1
        if self.work > MAX_WORK:
            raise AwsVpcFlowAnalysisError("Matching work exceeds its bound")

    def witness(self, kind: str, identifier: str, direction: str, rule: _Rule) -> dict:
        self.witnesses += 1
        if self.witnesses > MAX_WITNESSES:
            raise AwsVpcFlowAnalysisError("Witness count exceeds its bound")
        return {
            "policy_kind": kind,
            "policy_id": identifier,
            "policy_sha256": _PLACEHOLDER,
            "direction": direction,
            "source_rule_index": rule.index,
            "rule_id": rule.document.get("rule_id"),
            "rule_number": rule.document.get("rule_number"),
            "action": rule.document.get("action", "allow"),
        }

    def matches(self, rule: _Rule, peer: Any, protocol: str, destination_port: int) -> bool:
        self.charge()
        obj = rule.document
        return peer in rule.network and (
            obj["protocol"] == "ALL"
            or (
                obj["protocol"] == protocol
                and obj["from_port"] <= destination_port <= obj["to_port"]
            )
        )

    def sg(self, endpoint: str, direction: str, peer: Any, packet: dict) -> dict:
        self.charge()
        obj = self.endpoints[endpoint][0]
        refs = []
        complete = obj["security_groups_complete"]
        witness = None
        for identifier in sorted(obj["security_group_ids"]):
            self.charge()
            policy = self.groups[identifier]
            refs.append(
                {
                    "policy_kind": "security_group",
                    "policy_id": identifier,
                    "policy_sha256": _PLACEHOLDER,
                }
            )
            complete = complete and policy.document[direction + "_complete"]
            if witness is None:
                for rule in getattr(policy, direction):
                    if self.matches(rule, peer, packet["protocol"], packet["destination_port"]):
                        witness = self.witness("security_group", identifier, direction, rule)
                        break
        return _gate(
            True if witness else False if complete else None,
            True,
            "known_security_group_allow"
            if witness
            else "complete_security_group_no_allow"
            if complete
            else "incomplete_security_group_membership_or_rules",
            refs,
            witness,
        )

    def acl(
        self, endpoint: str, direction: str, peer: Any, packet: dict, same_subnet: bool
    ) -> dict:
        self.charge()
        subnet_id = self.endpoints[endpoint][0]["subnet_id"]
        identifier = self.subnets[subnet_id][0]["network_acl_id"]
        policy = self.acls[identifier]
        refs = [
            {"policy_kind": "network_acl", "policy_id": identifier, "policy_sha256": _PLACEHOLDER}
        ]
        if same_subnet:
            return _gate(True, False, "not_applied_same_subnet", refs)
        if not policy.document[direction + "_complete"]:
            return _gate(None, True, "incomplete_network_acl_rules", refs)
        for rule in getattr(policy, direction):
            if self.matches(rule, peer, packet["protocol"], packet["destination_port"]):
                return _gate(
                    rule.document["action"] == "allow",
                    True,
                    "network_acl_first_match",
                    refs,
                    self.witness("network_acl", identifier, direction, rule),
                )
        return _gate(False, True, "complete_network_acl_default_deny", refs)

    def direction(self, packet: dict, conditional: bool = False) -> dict:
        source = packet["source_endpoint_id"]
        destination = packet["destination_endpoint_id"]
        source_obj, source_address, _ = self.endpoints[source]
        destination_obj, destination_address, _ = self.endpoints[destination]
        same_subnet = source_obj["subnet_id"] == destination_obj["subnet_id"]
        if conditional:
            sg = {}
            for endpoint, name in (
                (source, "source_security_group_egress"),
                (destination, "destination_security_group_ingress"),
            ):
                self.charge()
                refs = []
                for identifier in sorted(self.endpoints[endpoint][0]["security_group_ids"]):
                    self.charge()
                    refs.append(
                        {
                            "policy_kind": "security_group",
                            "policy_id": identifier,
                            "policy_sha256": _PLACEHOLDER,
                        }
                    )
                sg[name] = _gate(True, True, "conditional_stateful_response", refs)
        else:
            sg = {
                "source_security_group_egress": self.sg(
                    source, "egress", destination_address, packet
                ),
                "destination_security_group_ingress": self.sg(
                    destination, "ingress", source_address, packet
                ),
            }
        gates = {
            **sg,
            "source_network_acl_egress": self.acl(
                source, "egress", destination_address, packet, same_subnet
            ),
            "destination_network_acl_ingress": self.acl(
                destination, "ingress", source_address, packet, same_subnet
            ),
        }
        allowed = [gate["allowed"] for gate in gates.values()]
        outcome = (
            "blocked_in_supplied_policy_model"
            if False in allowed
            else "unknown_in_supplied_policy_model"
            if None in allowed
            else "conditionally_allowed_in_supplied_policy_model"
            if conditional
            else "allowed_in_supplied_policy_model"
        )
        return {"packet": packet, "conditional": conditional, "outcome": outcome, "gates": gates}


def _gate(
    allowed: bool | None, applies: bool | None, basis: str, refs: list, witness: dict | None = None
) -> dict:
    return {
        "allowed": allowed,
        "applies": applies,
        "basis": basis,
        "policy_refs": refs,
        "witness": witness,
    }


def _unassessed(packet: dict, basis: str, conditional: bool = False) -> dict:
    return {
        "packet": packet,
        "conditional": conditional,
        "outcome": "unassessed",
        "gates": {name: _gate(None, None, basis, []) for name in _GATE_NAMES},
    }


def _derive(prepared: tuple) -> dict:
    model, subnets, endpoints, groups, acls, issues = prepared
    matching = _Matching(subnets, endpoints, groups, acls)
    rows = []
    for flow in sorted(model["flows"], key=lambda item: item["flow_id"]):
        packet = {field: flow[field] for field in _PACKET_FIELDS}
        reverse = {
            "source_endpoint_id": packet["destination_endpoint_id"],
            "destination_endpoint_id": packet["source_endpoint_id"],
            "protocol": packet["protocol"],
            "source_port": packet["destination_port"],
            "destination_port": packet["source_port"],
        }
        conditional = flow["return_mode"] == "assumed_tracked_response"
        basis = (
            "traffic_class_outside_subset"
            if flow["traffic_class"] != "ordinary_eni_to_eni"
            else "same_endpoint_outside_subset"
            if packet["source_endpoint_id"] == packet["destination_endpoint_id"]
            else "endpoint_address_outside_subset"
            if endpoints[packet["source_endpoint_id"]][2]
            or endpoints[packet["destination_endpoint_id"]][2]
            else None
        )
        if basis:
            forward_result = _unassessed(packet, basis)
            reverse_result = _unassessed(reverse, basis, conditional)
        else:
            forward_result = matching.direction(packet)
            if flow["return_mode"] == "unknown":
                reverse_result = _unassessed(reverse, "return_mode_unknown")
            elif conditional and forward_result["outcome"] != "allowed_in_supplied_policy_model":
                reverse_result = _unassessed(reverse, "forward_premise_not_satisfied", True)
            else:
                reverse_result = matching.direction(reverse, conditional)
        rows.append({"flow": flow, "forward": forward_result, "reverse": reverse_result})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GC-D14-CMD",
        "group_commander_profile_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": "aws-same-vpc-single-family-cidr-predicates-v1",
        "source_model": model,
        "source_model_sha256": _PLACEHOLDER,
        "bounds": dict(_BOUNDS),
        "flow_results": rows,
        "incomplete_reasons": issues,
        "analysis_status": "incomplete"
        if issues
        or any(
            direction["outcome"] in {"unknown_in_supplied_policy_model", "unassessed"}
            for row in rows
            for direction in (row["forward"], row["reverse"])
        )
        else "complete_declared_subset",
        "input_provenance": "operator_supplied_unverified",
        **_FLAGS,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    # Charge full canonical output with fixed-width address placeholders before hashing.
    report = _capture({"analysis_id": "VFA-" + "0" * 32, "analysis_sha256": _PLACEHOLDER, **body})
    del report["analysis_id"]
    del report["analysis_sha256"]
    policy_hashes = {}
    for kind, collection in (("security_group", groups), ("network_acl", acls)):
        for identifier, policy in collection.items():
            policy_hashes[(kind, identifier)] = _hash(
                "sunderkey.aws-vpc-flow-" + kind.replace("_", "-") + ".v1", policy.document
            )
    for row in report["flow_results"]:
        for name in ("forward", "reverse"):
            for gate in row[name]["gates"].values():
                for ref in gate["policy_refs"]:
                    ref["policy_sha256"] = policy_hashes[(ref["policy_kind"], ref["policy_id"])]
                witness = gate["witness"]
                if witness is not None:
                    witness["policy_sha256"] = policy_hashes[
                        (witness["policy_kind"], witness["policy_id"])
                    ]
    report["source_model_sha256"] = _hash(MODEL_DOMAIN, model)
    digest = _hash(DOMAIN, report)
    return {"analysis_id": "VFA-" + digest[7:39].upper(), "analysis_sha256": digest, **report}


def _result_shape(actual: dict) -> None:
    for row in _list(actual.get("flow_results"), MAX_FLOWS, "Flow results"):
        _fields(row, {"flow", "forward", "reverse"}, "Flow result")
        _flow(row["flow"])
        for name in ("forward", "reverse"):
            direction = _fields(
                row[name], {"packet", "conditional", "outcome", "gates"}, "Direction result"
            )
            _bool(direction["conditional"])
            if type(direction["outcome"]) is not str or direction["outcome"] not in _OUTCOMES:
                raise AwsVpcFlowAnalysisError("Result outcome is unsupported")
            packet = _fields(direction["packet"], _PACKET_FIELDS, "Packet result")
            for field in ("source_endpoint_id", "destination_endpoint_id"):
                _id(packet[field])
            if type(packet["protocol"]) is not str or packet["protocol"] not in {"TCP", "UDP"}:
                raise AwsVpcFlowAnalysisError("Packet result protocol is unsupported")
            _port(packet["source_port"])
            _port(packet["destination_port"])
            for gate in _fields(direction["gates"], set(_GATE_NAMES), "Direction gates").values():
                _fields(gate, {"allowed", "applies", "basis", "policy_refs", "witness"}, "Gate")
                for field in ("allowed", "applies"):
                    if gate[field] is not None:
                        _bool(gate[field])
                if type(gate["basis"]) is not str or gate["basis"] not in _BASES:
                    raise AwsVpcFlowAnalysisError("Gate basis is unsupported")
                for ref in _list(gate["policy_refs"], MAX_GROUP_REFS, "Gate policy references"):
                    _fields(ref, {"policy_kind", "policy_id", "policy_sha256"}, "Policy reference")
                    _reference(ref)
                witness = gate["witness"]
                if witness is not None:
                    _fields(
                        witness,
                        {
                            "policy_kind",
                            "policy_id",
                            "policy_sha256",
                            "direction",
                            "source_rule_index",
                            "rule_id",
                            "rule_number",
                            "action",
                        },
                        "Rule witness",
                    )
                    _reference(witness)
                    index = witness["source_rule_index"]
                    if type(index) is not int or not 0 <= index < MAX_DIRECTION_RULES:
                        raise AwsVpcFlowAnalysisError("Witness index is outside its native bound")
                    if (
                        type(witness["direction"]) is not str
                        or type(witness["action"]) is not str
                        or witness["direction"] not in {"ingress", "egress"}
                        or witness["action"] not in {"allow", "deny"}
                    ):
                        raise AwsVpcFlowAnalysisError("Witness direction or action is unsupported")
                    if witness["policy_kind"] == "security_group":
                        _id(witness["rule_id"])
                        if witness["rule_number"] is not None:
                            raise AwsVpcFlowAnalysisError("SG witness has an ACL rule number")
                    elif (
                        type(witness["rule_number"]) is not int
                        or not 1 <= witness["rule_number"] <= 32766
                        or witness["rule_id"] is not None
                    ):
                        raise AwsVpcFlowAnalysisError("ACL witness has malformed native identity")


def _reference(value: dict) -> None:
    if type(value["policy_kind"]) is not str or value["policy_kind"] not in {
        "security_group",
        "network_acl",
    }:
        raise AwsVpcFlowAnalysisError("Policy reference kind is unsupported")
    _id(value["policy_id"])
    if type(value["policy_sha256"]) is not str or _DIGEST.fullmatch(value["policy_sha256"]) is None:
        raise AwsVpcFlowAnalysisError("Policy reference digest is malformed")


def _report(value: Any) -> dict:
    actual = _capture(value)
    _fields(
        actual,
        {
            "analysis_id",
            "analysis_sha256",
            "schema_version",
            "component_id",
            "profile_id",
            "capability_id",
            "vector_id",
            "wave_id",
            "commander_profile_id",
            "group_commander_profile_id",
            "independent_validator_id",
            "blueprint_sha256",
            "semantics_profile",
            "source_model",
            "source_model_sha256",
            "bounds",
            "flow_results",
            "incomplete_reasons",
            "analysis_status",
            "input_provenance",
            "effects",
            "limitations",
            *_FLAGS,
        },
        "Report",
    )
    if type(actual.get("schema_version")) is not int or actual["schema_version"] != 1:
        raise AwsVpcFlowAnalysisError("Report schema must be native integer one")
    for field in _FLAGS:
        if actual.get(field) is not False:
            raise AwsVpcFlowAnalysisError("Report cannot claim authentication or live effects")
    if _canonical(actual.get("effects")) != _canonical(_EFFECTS) or _canonical(
        actual.get("bounds")
    ) != _canonical(_BOUNDS):
        raise AwsVpcFlowAnalysisError("Report effects or native bounds differ")
    _result_shape(actual)
    expected = _derive(_prepare(actual["source_model"]))
    if _canonical(actual) != _canonical(expected):
        raise AwsVpcFlowAnalysisError("Report does not exactly replay its supplied model")
    return expected


@dataclass(frozen=True, slots=True)
class AwsVpcFlowAnalysis:
    """Detached unsigned predicates, never actual cloud access or live authority."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not AwsVpcFlowAnalysis:
            raise AwsVpcFlowAnalysisError("Report must be the exact native wrapper family")
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise AwsVpcFlowAnalysisError("Report native slots are incomplete") from exc
        return _report(_json(text))

    def to_dict(self) -> dict:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> AwsVpcFlowAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> AwsVpcFlowAnalysis:
        return cls(document)


def analyze_supplied_aws_vpc_flow(model: dict) -> AwsVpcFlowAnalysis:
    """Evaluate captured explicit predicates without acquiring cloud or target state."""
    return AwsVpcFlowAnalysis.from_dict(_derive(_prepare(model)))


def analyze_supplied_aws_vpc_flow_bytes(*, model_bytes: bytes) -> AwsVpcFlowAnalysis:
    """Bound exact native ASCII bytes before decoding the supplied metadata model."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise AwsVpcFlowAnalysisError("Model bytes must be bounded exact native bytes")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AwsVpcFlowAnalysisError("Model bytes must be ASCII") from exc
    return analyze_supplied_aws_vpc_flow(_json(text))


def verify_supplied_aws_vpc_flow_analysis(
    report: AwsVpcFlowAnalysis, *, model: dict
) -> AwsVpcFlowAnalysis:
    """Require the separate original model, without authenticating its source."""
    if type(report) is not AwsVpcFlowAnalysis:
        raise AwsVpcFlowAnalysisError("Report must be the exact native wrapper family")
    actual = report.to_json()
    expected = analyze_supplied_aws_vpc_flow(model)
    if actual != expected.to_json():
        raise AwsVpcFlowAnalysisError("Report differs from the exact original model")
    return AwsVpcFlowAnalysis.from_json(expected.to_json())


__all__ = [
    "AwsVpcFlowAnalysis",
    "AwsVpcFlowAnalysisError",
    "CAPABILITY_ID",
    "COMPONENT_ID",
    "DOMAIN",
    "PROFILE_ID",
    "VECTOR_ID",
    "WAVE_ID",
    "analyze_supplied_aws_vpc_flow",
    "analyze_supplied_aws_vpc_flow_bytes",
    "verify_supplied_aws_vpc_flow_analysis",
]
