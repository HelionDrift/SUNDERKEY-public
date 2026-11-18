"""Finite supplied GCP VPC new-flow rule arithmetic without external effects."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "gcp_supplied_vpc_firewall_new_flow_predicates"
PROFILE_ID = "AOE-GC-D14-S07"
CAPABILITY_ID = "army.gc.d14.s07"
VECTOR_ID = "AV-GC-D14-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S07"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GC-D14-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e6adfbee776bae2c829904271d023368b12f8e26b6f810d48922b2cc4e7a6eb8"
SEMANTICS_PROFILE = "gcp-declared-vpc-new-flow-priority-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-gcp-firewall-model.v1"
DOMAIN = "sunderkey.offline-gcp-firewall-analysis.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 65_536
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_ID_BYTES = 64
MAX_RULES = 256
MAX_FLOWS = 128
MAX_ATOMS = 64
MAX_WORK = 8_388_608
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ANALYSIS_ID = re.compile(r"GCFA-[0-9A-F]{32}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ROOT_FIELDS = {"schema_version", "network_id", "rules_complete", "traffic_kind", "rules", "flows"}
_RULE_FIELDS = {
    "rule_id",
    "network_id",
    "direction",
    "disabled",
    "priority",
    "action",
    "targets",
    "predicate",
}
_FLOW_FIELDS = {
    "flow_id",
    "network_id",
    "target_id",
    "direction",
    "protocol",
    "source_ip",
    "destination_ip",
    "destination_port",
}
_PREDICATE_FIELDS = {"kind", "protocol", "source_cidrs", "destination_cidrs", "destination_ports"}
_TARGET_REASONS = {"target_tag", "target_service_account", "other_target"}
_PREDICATE_REASONS = {"source_tag", "source_service_account", "protocol", "other_predicate"}
_DECISIONS = {
    "allow_under_supplied_vpc_predicates",
    "deny_under_supplied_vpc_predicates",
    "unassessed",
}
_REASONS = {
    "known_deny_at_lowest_candidate_priority",
    "known_allow_at_lowest_candidate_priority",
    "possible_earlier_or_equal_rule",
    "no_supplied_match",
    "rule_projection_incomplete",
}
_WITNESS_FIELDS = {"rule_id", "priority", "action"}
_POSSIBLE_FIELDS = {*_WITNESS_FIELDS, "reasons"}
_ROW_FIELDS = {
    "flow_id",
    "network_id",
    "target_id",
    "direction",
    "decision",
    "reason",
    "candidate_priority",
    "matched_rules",
    "possible_rules",
    "winning_rule_ids",
    "winning_witnesses_complete",
}
_METADATA = {
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
}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "inventory_completeness_verified",
        "target_membership_verified",
        "tag_membership_resolved",
        "network_currentness_verified",
        "connection_state_verified",
        "effective_firewall_verdict_proven",
        "reachability_proven",
        "authorization_granted",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "deployment",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "routing",
        "target",
    ),
    "none",
)
_LIMITATIONS = (
    "Network, rules, completeness, target applicability and new-flow coordinates "
    "are caller premises.",
    "Only explicit same-family CIDRs, tcp/udp/all and destination-port predicates are calculated.",
    "The lowest potentially matching priority group retains known and unresolved witnesses.",
    "Equal-priority deny can settle action while unresolved winning-witness membership "
    "remains unknown.",
    "No uniquely processed same-action rule, source-port filtering or implicit defaults "
    "are invented.",
    "No acquisition, tag/service-account resolution, authenticated source or current authority.",
    "No stateful return, existing connections, hierarchical/global/regional policy "
    "or effective verdict.",
    "No VM-self/metadata exception, NIC-address proof, forwarding, NAT, routing "
    "or load-balancer model.",
    "This is partial supplied-rule arithmetic, not GCP API validity, reachability "
    "or qualification.",
)


class GcpFirewallAnalysisError(ValueError):
    """Input, replay or cost exceeds this closed software subset."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or self.used + amount > MAX_WORK:
            raise GcpFirewallAnalysisError("Cumulative software work bound exhausted")
        self.used += amount


def _bounds() -> dict:
    return {
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
        "string_bytes": MAX_STRING_BYTES,
        "id_bytes": MAX_ID_BYTES,
        "rules": MAX_RULES,
        "flows": MAX_FLOWS,
        "atoms_per_dimension": MAX_ATOMS,
        "cumulative_work": MAX_WORK,
        "integer_minimum": MIN_INTEGER,
        "integer_maximum": MAX_INTEGER,
    }


def _measure(value: Any, budget: _Budget | None, *, report: bool = False) -> tuple[int, int]:
    """Bound and charge repeated native subtrees before copying or canonical encoding."""
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if size + amount > byte_limit:
            raise GcpFirewallAnalysisError("Canonical document byte bound exhausted")
        if budget is not None:
            budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise GcpFirewallAnalysisError("Native node/depth bound exhausted")
        if budget is not None:
            budget.charge(1)
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise GcpFirewallAnalysisError("Native string bound exhausted")
            add(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise GcpFirewallAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise GcpFirewallAnalysisError("Native signed-64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise GcpFirewallAnalysisError("Cyclic native graph")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise GcpFirewallAnalysisError("Native pending-child bound exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise GcpFirewallAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        if budget is not None:
                            budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise GcpFirewallAnalysisError("Only exact native JSON families are supported")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, str]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(size + nodes)
    owned = _clone(value)
    return owned, _canonical(owned)


def _integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise GcpFirewallAnalysisError("Raw integer grammar or lexical bound failed")
    value = int(token)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise GcpFirewallAnalysisError("Raw integer exceeds signed 64-bit")
    return value


def _decode(content: Any, budget: _Budget, *, report: bool = False) -> Any:
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(content) is not str or not content or len(content) > maximum:
        raise GcpFirewallAnalysisError("Bounded native JSON text required")
    budget.charge(len(content))
    if not content.isascii():
        raise GcpFirewallAnalysisError("ASCII JSON text required")
    index = depth = nodes = 0
    while index < len(content):
        char = content[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise GcpFirewallAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(content):
                    raise GcpFirewallAnalysisError("Unterminated raw string")
                char = content[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(content):
                        raise GcpFirewallAnalysisError("Unterminated raw escape")
                    escape = content[index]
                    if escape == "u":
                        digits = content[index + 1 : index + 5]
                        if (
                            len(digits) != 4
                            or any(digit not in "0123456789abcdefABCDEF" for digit in digits)
                            or not 32 <= int(digits, 16) <= 126
                        ):
                            raise GcpFirewallAnalysisError(
                                "Printable ASCII Unicode escape required"
                            )
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise GcpFirewallAnalysisError("Unsupported raw escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise GcpFirewallAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise GcpFirewallAnalysisError("Raw decoded-string bound exhausted")
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
                raise GcpFirewallAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(content) and content[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise GcpFirewallAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = content[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise GcpFirewallAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise GcpFirewallAnalysisError("Unterminated raw structure")
    budget.charge(18 * len(content) + 2 * nodes)

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, child in items:
            if key in result:
                raise GcpFirewallAnalysisError("Duplicate JSON object field")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise GcpFirewallAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        result = json.loads(
            content,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, GcpFirewallAnalysisError):
            raise
        raise GcpFirewallAnalysisError("Malformed supplied JSON") from exc
    _measure(result, None, report=report)
    return result


def _object(value: Any, fields: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != fields:
        raise GcpFirewallAnalysisError(f"Exact closed {label} fields required")


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> None:
    if type(value) is not list or len(value) > maximum or (nonempty and not value):
        raise GcpFirewallAnalysisError(f"Bounded native {label} array required")


def _identifier(value: Any) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise GcpFirewallAnalysisError("Bounded exact native identifier required")


def _enum(value: Any, choices: set[str], label: str) -> None:
    if type(value) is not str or value not in choices:
        raise GcpFirewallAnalysisError(f"Exact native supported {label} required")


def _priority(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= 65535:
        raise GcpFirewallAnalysisError("Native priority 0..65535 required")


def _port(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= 65535:
        raise GcpFirewallAnalysisError("Native destination port 0..65535 required")


def _networks(values: Any, budget: _Budget) -> tuple:
    _list(values, MAX_ATOMS, "CIDR", nonempty=True)
    seen: set[str] = set()
    result = []
    for value in values:
        if type(value) is not str or len(value) > 64:
            raise GcpFirewallAnalysisError("Bounded native CIDR required")
        budget.charge(len(value) + 128)
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise GcpFirewallAnalysisError("Canonical explicit CIDR required") from exc
        if str(network) != value or value in seen:
            raise GcpFirewallAnalysisError("Unique canonical explicit CIDRs required")
        seen.add(value)
        result.append(network)
    return tuple(result)


def _ranges(values: Any, budget: _Budget) -> tuple:
    _list(values, MAX_ATOMS, "destination-port")
    seen: set[tuple[int, int]] = set()
    result = []
    for value in values:
        if type(value) is not list or len(value) != 2:
            raise GcpFirewallAnalysisError("Native inclusive destination-port pair required")
        _port(value[0])
        _port(value[1])
        if value[0] > value[1] or tuple(value) in seen:
            raise GcpFirewallAnalysisError("Unique nonreversed destination-port pair required")
        budget.charge(4)
        seen.add(tuple(value))
        result.append(tuple(value))
    return tuple(result)


def _address_ip(value: Any, budget: _Budget) -> Any:
    if type(value) is not str or len(value) > 64 or "%" in value:
        raise GcpFirewallAnalysisError("Bounded native unscoped IP required")
    budget.charge(len(value) + 128)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise GcpFirewallAnalysisError("Canonical IP address required") from exc
    if str(address) != value:
        raise GcpFirewallAnalysisError("Canonical IP address required")
    return address


def _targets(value: Any, budget: _Budget) -> tuple[Any, str | None]:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise GcpFirewallAnalysisError("Closed native target predicate required")
    kind = value["kind"]
    if kind == "all":
        _object(value, {"kind"}, "all-target")
        return None, None
    if kind == "declared_ids":
        _object(value, {"kind", "target_ids"}, "declared-target")
        _list(value["target_ids"], MAX_ATOMS, "target-ID", nonempty=True)
        seen: set[str] = set()
        for item in value["target_ids"]:
            _identifier(item)
            budget.charge(len(item) + 1)
            if item in seen:
                raise GcpFirewallAnalysisError("Unique declared target IDs required")
            seen.add(item)
        return seen, None
    _object(value, {"kind", "reason"}, "unsupported-target")
    _enum(kind, {"unsupported"}, "target kind")
    _enum(value["reason"], _TARGET_REASONS, "target reason")
    return None, value["reason"]


def _predicate(value: Any, budget: _Budget) -> tuple[Any, str | None]:
    if type(value) is not dict or type(value.get("kind")) is not str:
        raise GcpFirewallAnalysisError("Closed native packet predicate required")
    if value["kind"] == "unsupported":
        _object(value, {"kind", "reason"}, "unsupported-predicate")
        _enum(value["reason"], _PREDICATE_REASONS, "predicate reason")
        return None, value["reason"]
    _object(value, _PREDICATE_FIELDS, "CIDR-protocol-port")
    _enum(value["kind"], {"cidr_protocol_ports"}, "predicate kind")
    _enum(value["protocol"], {"tcp", "udp", "all"}, "rule protocol")
    source = _networks(value["source_cidrs"], budget)
    destination = _networks(value["destination_cidrs"], budget)
    family = source[0].version
    if any(network.version != family for network in (*source, *destination)):
        raise GcpFirewallAnalysisError("One coherent CIDR family per rule required")
    ports = _ranges(value["destination_ports"], budget)
    if value["protocol"] == "all" and ports:
        raise GcpFirewallAnalysisError("All-protocol predicate cannot contain ports")
    return (value["protocol"], source, destination, ports), None


def _compile(model: dict, budget: _Budget) -> tuple[list, list]:
    _object(model, _ROOT_FIELDS, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GcpFirewallAnalysisError("Native model schema version 1 required")
    _identifier(model["network_id"])
    if type(model["rules_complete"]) is not bool:
        raise GcpFirewallAnalysisError("Native rules-complete bool required")
    _enum(model["traffic_kind"], {"new_flow"}, "traffic premise")
    _list(model["rules"], MAX_RULES, "rule")
    _list(model["flows"], MAX_FLOWS, "flow", nonempty=True)
    rules = []
    seen: set[str] = set()
    for rule in model["rules"]:
        budget.charge(32)
        _object(rule, _RULE_FIELDS, "rule")
        _identifier(rule["rule_id"])
        _identifier(rule["network_id"])
        if rule["network_id"] != model["network_id"] or rule["rule_id"] in seen:
            raise GcpFirewallAnalysisError("Unique rules must join the declared network")
        seen.add(rule["rule_id"])
        _enum(rule["direction"], {"INGRESS", "EGRESS"}, "rule direction")
        _enum(rule["action"], {"allow", "deny"}, "rule action")
        _priority(rule["priority"])
        if type(rule["disabled"]) is not bool:
            raise GcpFirewallAnalysisError("Native disabled bool required")
        targets = _targets(rule["targets"], budget)
        predicate = _predicate(rule["predicate"], budget)
        rules.append((rule, targets, predicate))
    budget.charge(
        sum(len(rule[0]["rule_id"]) + 1 for rule in rules) * (len(rules).bit_length() + 1)
    )
    rules.sort(key=lambda item: (item[0]["priority"], item[0]["rule_id"]))
    flows = []
    seen.clear()
    for flow in model["flows"]:
        budget.charge(32)
        _object(flow, _FLOW_FIELDS, "flow")
        for name in ("flow_id", "network_id", "target_id"):
            _identifier(flow[name])
        if flow["network_id"] != model["network_id"] or flow["flow_id"] in seen:
            raise GcpFirewallAnalysisError("Unique flows must join the declared network")
        seen.add(flow["flow_id"])
        _enum(flow["direction"], {"INGRESS", "EGRESS"}, "flow direction")
        _enum(flow["protocol"], {"tcp", "udp"}, "flow protocol")
        _port(flow["destination_port"])
        source = _address_ip(flow["source_ip"], budget)
        destination = _address_ip(flow["destination_ip"], budget)
        if source.version != destination.version:
            raise GcpFirewallAnalysisError("One coherent IP family per flow required")
        flows.append((flow, source, destination))
    return rules, flows


def _matches(compiled_flow: tuple, compiled_rule: tuple, budget: _Budget) -> list[str] | None:
    """None is a known nonmatch; [] is known match; codes mean potentially matching."""
    flow, source, destination = compiled_flow
    rule, (targets, target_reason), (predicate, predicate_reason) = compiled_rule
    budget.charge(len(flow["target_id"]) + 4)
    if rule["disabled"] or rule["direction"] != flow["direction"]:
        return None
    if targets is not None and flow["target_id"] not in targets:
        return None
    if predicate is not None:
        protocol, source_ranges, destination_ranges, ports = predicate
        if protocol not in ("all", flow["protocol"]):
            return None
        for address, ranges in ((source, source_ranges), (destination, destination_ranges)):
            found = False
            for network in ranges:
                budget.charge(1)
                if address.version == network.version and address in network:
                    found = True
                    break
            if not found:
                return None
        if ports:
            found = False
            for low, high in ports:
                budget.charge(1)
                if low <= flow["destination_port"] <= high:
                    found = True
                    break
            if not found:
                return None
    return [reason for reason in (target_reason, predicate_reason) if reason is not None]


def _witness(rule: dict) -> dict:
    return {"rule_id": rule["rule_id"], "priority": rule["priority"], "action": rule["action"]}


def _observe(compiled_flow: tuple, rules: list, complete: bool, budget: _Budget) -> dict:
    flow = compiled_flow[0]
    row = {
        "flow_id": flow["flow_id"],
        "network_id": flow["network_id"],
        "target_id": flow["target_id"],
        "direction": flow["direction"],
        "decision": "unassessed",
        "reason": "rule_projection_incomplete",
        "candidate_priority": None,
        "matched_rules": [],
        "possible_rules": [],
        "winning_rule_ids": [],
        "winning_witnesses_complete": False,
    }
    if not complete:
        return row
    row["reason"] = "no_supplied_match"
    priority = None
    for compiled in rules:
        rule = compiled[0]
        if priority is not None and rule["priority"] != priority:
            break
        reasons = _matches(compiled_flow, compiled, budget)
        if reasons is None:
            continue
        priority = rule["priority"]
        budget.charge(4 * len(rule["rule_id"]) + 128)
        witness = _witness(rule)
        if reasons:
            witness["reasons"] = reasons
            row["possible_rules"].append(witness)
        else:
            row["matched_rules"].append(witness)
    row["candidate_priority"] = priority
    if priority is None:
        return row
    budget.charge(4 * (len(row["matched_rules"]) + len(row["possible_rules"])) + 32)
    denies = [rule for rule in row["matched_rules"] if rule["action"] == "deny"]
    chosen = None
    if denies:
        chosen = "deny"
    elif row["matched_rules"] and not any(
        rule["action"] == "deny" for rule in row["possible_rules"]
    ):
        chosen = "allow"
    if chosen is None:
        row["reason"] = "possible_earlier_or_equal_rule"
        return row
    row["decision"] = chosen + "_under_supplied_vpc_predicates"
    row["reason"] = "known_" + chosen + "_at_lowest_candidate_priority"
    row["winning_rule_ids"] = [
        rule["rule_id"] for rule in row["matched_rules"] if rule["action"] == chosen
    ]
    row["winning_witnesses_complete"] = not any(
        rule["action"] == chosen for rule in row["possible_rules"]
    )
    return row


def _prepare(model: Any, budget: _Budget) -> tuple[dict, str]:
    owned, source_text = _capture(model, budget)
    rules, flows = _compile(owned, budget)
    budget.charge(512)
    rows: list[dict] = []
    summary = {"flows": len(flows), "allow": 0, "deny": 0, "unassessed": 0}
    body = {
        "schema_version": 1,
        **_METADATA,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "flow_observations": rows,
        "summary": summary,
        "flags": _clone(_FLAGS),
        "effects": _clone(_EFFECTS),
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "GCFA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    total_size, total_nodes = _measure(body, budget, report=True)
    for flow in flows:
        row = _observe(flow, rules, owned["rules_complete"], budget)
        row_size, row_nodes = _measure(row, budget, report=True)
        if (
            total_size + row_size + 1 > MAX_REPORT_BYTES
            or total_nodes + row_nodes > MAX_REPORT_NODES
        ):
            raise GcpFirewallAnalysisError("Cumulative observation retention bound exhausted")
        total_size += row_size + 1
        total_nodes += row_nodes
        budget.charge(row_size + row_nodes)
        rows.append(row)
        count = (
            "allow"
            if row["decision"].startswith("allow_")
            else "deny"
            if row["decision"].startswith("deny_")
            else "unassessed"
        )
        summary[count] += 1
    return body, source_text


def _report_header(document: dict, budget: _Budget) -> None:
    fields = {
        "schema_version",
        *_METADATA,
        "source_model",
        "source_model_sha256",
        "flow_observations",
        "summary",
        "flags",
        "effects",
        "bounds",
        "limitations",
        "analysis_id",
        "analysis_sha256",
    }
    _object(document, fields, "report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise GcpFirewallAnalysisError("Native report schema version 1 required")
    for name, expected in _METADATA.items():
        if type(document[name]) is not str or document[name] != expected:
            raise GcpFirewallAnalysisError("Exact source/ownership metadata required")
    for name in ("source_model_sha256", "analysis_sha256"):
        if type(document[name]) is not str or _SHA.fullmatch(document[name]) is None:
            raise GcpFirewallAnalysisError("Exact native lowercase digest required")
    if (
        type(document["analysis_id"]) is not str
        or _ANALYSIS_ID.fullmatch(document["analysis_id"]) is None
    ):
        raise GcpFirewallAnalysisError("Exact native analysis identity required")
    _object(document["flags"], set(_FLAGS), "flags")
    if any(type(value) is not bool or value is not False for value in document["flags"].values()):
        raise GcpFirewallAnalysisError("Every proof/promotion flag must be native false")
    _object(document["effects"], set(_EFFECTS), "effects")
    if any(type(value) is not str or value != "none" for value in document["effects"].values()):
        raise GcpFirewallAnalysisError("Every effect must be native none")
    for name, expected in (("bounds", _bounds()), ("limitations", list(_LIMITATIONS))):
        size, _ = _measure(document[name], budget, report=True)
        expected_size, _ = _measure(expected, budget, report=True)
        budget.charge(2 * (size + expected_size))
        if _canonical(document[name]) != _canonical(expected):
            raise GcpFirewallAnalysisError("Exact software bounds and limitations required")
    _object(document["summary"], {"flows", "allow", "deny", "unassessed"}, "summary")
    if any(
        type(value) is not int or not 0 <= value <= MAX_FLOWS
        for value in document["summary"].values()
    ):
        raise GcpFirewallAnalysisError("Native bounded summary integers required")
    _list(document["flow_observations"], MAX_FLOWS, "observation", nonempty=True)
    for row in document["flow_observations"]:
        budget.charge(32)
        _object(row, _ROW_FIELDS, "flow observation")
        for name in ("flow_id", "network_id", "target_id"):
            _identifier(row[name])
        _enum(row["direction"], {"INGRESS", "EGRESS"}, "observation direction")
        _enum(row["decision"], _DECISIONS, "decision")
        _enum(row["reason"], _REASONS, "observation reason")
        if row["candidate_priority"] is not None:
            _priority(row["candidate_priority"])
        if type(row["winning_witnesses_complete"]) is not bool:
            raise GcpFirewallAnalysisError("Native witness-completeness bool required")
        _list(row["winning_rule_ids"], MAX_RULES, "winning-rule-ID")
        for identifier in row["winning_rule_ids"]:
            _identifier(identifier)
        for name in ("matched_rules", "possible_rules"):
            _list(row[name], MAX_RULES, "rule witness")
            for witness in row[name]:
                budget.charge(16)
                _object(
                    witness,
                    _POSSIBLE_FIELDS if name == "possible_rules" else _WITNESS_FIELDS,
                    "rule witness",
                )
                _identifier(witness["rule_id"])
                _priority(witness["priority"])
                _enum(witness["action"], {"allow", "deny"}, "witness action")
                if name == "possible_rules":
                    _list(witness["reasons"], 2, "uncertainty reason", nonempty=True)
                    for reason in witness["reasons"]:
                        _enum(reason, _TARGET_REASONS | _PREDICATE_REASONS, "uncertainty reason")


def _plan_report(document: Any, budget: _Budget) -> tuple[tuple[dict, str], str]:
    owned, text = _capture(document, budget, report=True)
    _report_header(owned, budget)
    return _prepare(owned["source_model"], budget), text


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _seal(
    plans: list[tuple[dict, str]],
    budget: _Budget,
    originals: list[str | None],
    *,
    compare_originals: bool = False,
) -> list[tuple[dict, str]]:
    """Reserve every final encoding, digest, equality and storage before any hash."""
    prepared = []
    lengths = []
    for (body, source_text), original in zip(plans, originals, strict=True):
        size, nodes = _measure(body, budget, report=True)
        budget.charge(2 * len(body))
        unsigned = {
            key: value
            for key, value in body.items()
            if key not in {"analysis_id", "analysis_sha256"}
        }
        unsigned_size, unsigned_nodes = _measure(unsigned, budget, report=True)
        budget.charge(
            size
            + nodes
            + 4 * unsigned_size
            + unsigned_nodes
            + 3 * len(source_text)
            + 3 * (len(DOMAIN) + len(MODEL_DOMAIN) + 2)
            + 256
        )
        if original is not None:
            budget.charge(size + len(original))
        lengths.append(size)
        prepared.append((body, source_text, unsigned))
    if compare_originals:
        budget.charge(sum(lengths))
    results = []
    for (body, source_text, unsigned), original in zip(prepared, originals, strict=True):
        source_digest = _address(MODEL_DOMAIN, source_text)
        body["source_model_sha256"] = source_digest
        unsigned["source_model_sha256"] = source_digest
        digest = _address(DOMAIN, _canonical(unsigned))
        body["analysis_id"] = "GCFA-" + digest[7:39].upper()
        body["analysis_sha256"] = digest
        text = _canonical(body)
        if original is not None and text != original:
            raise GcpFirewallAnalysisError("Report does not exactly replay the embedded original")
        results.append((body, text))
    if compare_originals and results[0][1] != results[1][1]:
        raise GcpFirewallAnalysisError("Report differs from separately supplied original model")
    return results


def _storage(report: Any, budget: _Budget) -> Any:
    if type(report) is not GcpFirewallAnalysis:
        raise GcpFirewallAnalysisError("Exact native GCP firewall analysis family required")
    return _decode(getattr(report, "_document_json", None), budget, report=True)


@dataclass(frozen=True, slots=True, init=False)
class GcpFirewallAnalysis:
    """Owned supplied-rule arithmetic, not effective access, a grant or provider evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(self) is not GcpFirewallAnalysis:
            raise GcpFirewallAnalysisError("Exact native report family required")
        budget = _Budget()
        plan, original = _plan_report(document, budget)
        object.__setattr__(self, "_document_json", _seal([plan], budget, [original])[0][1])

    @classmethod
    def from_dict(cls, document: Any) -> GcpFirewallAnalysis:
        if cls is not GcpFirewallAnalysis:
            raise GcpFirewallAnalysisError("Exact native report family required")
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> GcpFirewallAnalysis:
        if cls is not GcpFirewallAnalysis:
            raise GcpFirewallAnalysisError("Exact native report family required")
        budget = _Budget()
        plan, original = _plan_report(_decode(content, budget, report=True), budget)
        return _owned(_seal([plan], budget, [original])[0][1])

    def to_dict(self) -> dict:
        budget = _Budget()
        plan, original = _plan_report(_storage(self, budget), budget)
        return _seal([plan], budget, [original])[0][0]

    def to_json(self) -> str:
        budget = _Budget()
        plan, original = _plan_report(_storage(self, budget), budget)
        return _seal([plan], budget, [original])[0][1]

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _owned(content: str) -> GcpFirewallAnalysis:
    result = object.__new__(GcpFirewallAnalysis)
    object.__setattr__(result, "_document_json", content)
    return result


def analyze_supplied_gcp_firewall(model: Any) -> GcpFirewallAnalysis:
    """Calculate only the closed supplied VPC new-flow rule predicates."""
    budget = _Budget()
    return _owned(_seal([_prepare(model, budget)], budget, [None])[0][1])


def analyze_supplied_gcp_firewall_bytes(*, model_bytes: Any) -> GcpFirewallAnalysis:
    """Accept bounded native ASCII JSON bytes, never a path or acquired resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise GcpFirewallAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GcpFirewallAnalysisError("ASCII model bytes required") from exc
    model = _decode(text, budget)
    return _owned(_seal([_prepare(model, budget)], budget, [None])[0][1])


def verify_supplied_gcp_firewall_analysis(report: Any, *, model: Any) -> GcpFirewallAnalysis:
    """Compare separately supplied originals; never verify provider state or permission."""
    budget = _Budget()
    embedded, original = _plan_report(_storage(report, budget), budget)
    separate = _prepare(model, budget)
    return _owned(
        _seal([embedded, separate], budget, [original, None], compare_originals=True)[1][1]
    )


def component_fixture() -> dict:
    """Fresh synthetic equal-action ingress witnesses and unresolved egress tag."""
    predicate = {
        "kind": "cidr_protocol_ports",
        "protocol": "tcp",
        "source_cidrs": ["10.0.0.0/24"],
        "destination_cidrs": ["10.0.1.0/24"],
        "destination_ports": [[443, 443]],
    }
    rule = {
        "rule_id": "ingress-one",
        "network_id": "synthetic-vpc",
        "direction": "INGRESS",
        "disabled": False,
        "priority": 100,
        "action": "allow",
        "targets": {"kind": "all"},
        "predicate": predicate,
    }
    flow = {
        "flow_id": "synthetic-ingress",
        "network_id": "synthetic-vpc",
        "target_id": "synthetic-nic",
        "direction": "INGRESS",
        "protocol": "tcp",
        "source_ip": "10.0.0.7",
        "destination_ip": "10.0.1.8",
        "destination_port": 443,
    }
    return {
        "schema_version": 1,
        "network_id": "synthetic-vpc",
        "rules_complete": True,
        "traffic_kind": "new_flow",
        "rules": [
            rule,
            {**rule, "rule_id": "ingress-two", "predicate": _clone(predicate)},
            {
                **rule,
                "rule_id": "egress-unknown",
                "direction": "EGRESS",
                "priority": 50,
                "targets": {"kind": "unsupported", "reason": "target_tag"},
                "predicate": _clone(predicate),
            },
        ],
        "flows": [flow, {**flow, "flow_id": "synthetic-egress", "direction": "EGRESS"}],
    }


__all__ = [
    "GcpFirewallAnalysis",
    "GcpFirewallAnalysisError",
    "analyze_supplied_gcp_firewall",
    "analyze_supplied_gcp_firewall_bytes",
    "verify_supplied_gcp_firewall_analysis",
    "component_fixture",
]
