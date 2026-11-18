"""Bounded Azure NSG predicates over supplied declarations, without external I/O."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "azure_supplied_nsg_directional_predicates"
PROFILE_ID = "AOE-GC-D14-S05"
CAPABILITY_ID = "army.gc.d14.s05"
VECTOR_ID = "AV-GC-D14-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S05"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GC-D14-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8e08953c3b08ca3bbf9eafee8f429ff727ec444c8104d2bf11141d8d6f492ec9"
SEMANTICS_PROFILE = "azure-declared-cidr-nsg-priority-subset.v1"
DOMAIN = "sunderkey.offline-azure-nsg-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-azure-nsg-model.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_NATIVE_DEPTH = 16
MAX_MODEL_NODES = 32_768
MAX_REPORT_NODES = 65_536
MAX_STRING_BYTES = 512
MAX_NSGS = 16
MAX_RULES_PER_NSG = 256
MAX_TOTAL_RULES = 2048
MAX_PREDICATE_ATOMS = 64
MAX_FLOWS = 128
MAX_WORK = 4_194_304
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ANALYSIS_ID = re.compile(r"NSGA-[0-9A-F]{32}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLOW_FIELDS = {
    "flow_id",
    "direction",
    "protocol",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
}
_RULE_FIELDS = {"rule_id", "priority", "direction", "access", "predicate"}
_CIDR_FIELDS = {
    "kind",
    "protocol",
    "source_cidrs",
    "destination_cidrs",
    "source_ports",
    "destination_ports",
}
_UNSUPPORTED_REASONS = {
    "service_tag",
    "application_security_group",
    "unsupported_protocol",
    "other_predicate",
}
_LAYER_FIELDS = {
    "layer",
    "nsg_id",
    "decision",
    "reason",
    "candidate_rule_id",
    "candidate_priority",
    "candidate_declared_access",
}
_LAYER_REASONS = {
    "known_first_supplied_match",
    "unsupported_earlier_predicate",
    "rules_incomplete",
    "no_supplied_match",
    "declared_attachment_absent",
    "attachment_projection_incomplete",
}
_ROW_FIELDS = {"flow_id", "direction", "layer_order", "layers", "decision", "uncertainty"}
_DECISIONS = {
    "allow_under_supplied_nsg_predicates",
    "deny_under_supplied_nsg_predicates",
    "not_filtered_by_declared_nsgs",
    "unassessed",
}
_SUMMARY_FIELDS = {"flows", "allow", "deny", "not_filtered", "unassessed"}
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
        "service_tags_resolved",
        "attachment_currentness_verified",
        "routing_verified",
        "conntrack_verified",
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
    "Every rule, attachment, completeness premise and packet coordinate is a caller assertion.",
    "Only new directional TCP/UDP CIDR and inclusive port-range predicates are calculated.",
    "Unsupported predicates retain their declared priority; default rules are never synthesized.",
    "Absent attachments describe an NSG layer only, not permission or effective connectivity.",
    "No service-tag acquisition, ASG resolution, security-admin rules or provider exceptions.",
    "No NAT, routing, stateful return, existing connections, target, provider "
    "or current authority.",
    "A declared conjunction denial may retain uncertainty in the other NSG layer.",
    "This is partial supplied-model arithmetic, not Azure completeness or qualification.",
)


class AzureNsgAnalysisError(ValueError):
    """The supplied projection or replay is outside this finite software contract."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or self.used + amount > MAX_WORK:
            raise AzureNsgAnalysisError("Cumulative software work bound exhausted")
        self.used += amount


def _bounds() -> dict:
    return {
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "string_bytes": MAX_STRING_BYTES,
        "nsgs": MAX_NSGS,
        "rules_per_nsg": MAX_RULES_PER_NSG,
        "total_rules": MAX_TOTAL_RULES,
        "atoms_per_dimension": MAX_PREDICATE_ATOMS,
        "flows": MAX_FLOWS,
        "cumulative_work": MAX_WORK,
        "integer_minimum": MIN_INTEGER,
        "integer_maximum": MAX_INTEGER,
    }


def _measure(value: Any, budget: _Budget | None, *, report: bool = False) -> tuple[int, int]:
    """Charge native graphs, escaping and key ordering before allocation or encoding."""
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if size + amount > byte_limit:
            raise AzureNsgAnalysisError("Canonical document byte bound exhausted")
        if budget is not None:
            budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise AzureNsgAnalysisError("Native node/depth bound exhausted")
        if budget is not None:
            budget.charge(1)
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise AzureNsgAnalysisError("Native string bound exhausted")
            add(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise AzureNsgAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise AzureNsgAnalysisError("Exact native signed-64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise AzureNsgAnalysisError("Cyclic native graph")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise AzureNsgAnalysisError("Native pending-child bound exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise AzureNsgAnalysisError("Exact native string keys required")
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
            raise AzureNsgAnalysisError("Only exact native JSON families are supported")

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
        raise AzureNsgAnalysisError("Raw integer grammar or lexical bound failed")
    value = int(token)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise AzureNsgAnalysisError("Raw integer exceeds signed 64-bit")
    return value


def _decode(content: Any, budget: _Budget, *, report: bool = False) -> Any:
    """Preflight lexical scalar/container costs before the JSON decoder can allocate."""
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(content) is not str or not content or len(content) > maximum:
        raise AzureNsgAnalysisError("Bounded native JSON text required")
    budget.charge(len(content))
    if not content.isascii():
        raise AzureNsgAnalysisError("Native ASCII JSON text required")
    index = depth = nodes = 0
    while index < len(content):
        char = content[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise AzureNsgAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(content):
                    raise AzureNsgAnalysisError("Unterminated raw string")
                char = content[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(content):
                        raise AzureNsgAnalysisError("Unterminated raw escape")
                    escape = content[index]
                    if escape == "u":
                        digits = content[index + 1 : index + 5]
                        if (
                            len(digits) != 4
                            or any(digit not in "0123456789abcdefABCDEF" for digit in digits)
                            or not 32 <= int(digits, 16) <= 126
                        ):
                            raise AzureNsgAnalysisError("Printable ASCII Unicode escape required")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise AzureNsgAnalysisError("Unsupported raw escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise AzureNsgAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise AzureNsgAnalysisError("Raw decoded-string bound exhausted")
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
                raise AzureNsgAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(content) and content[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise AzureNsgAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = content[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise AzureNsgAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise AzureNsgAnalysisError("Unterminated raw structure")
    # Conservatively fund decoder allocation, native validation and bounded key sorting.
    budget.charge(18 * len(content) + 2 * nodes)

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, child in items:
            if key in result:
                raise AzureNsgAnalysisError("Duplicate JSON object field")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise AzureNsgAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        value = json.loads(
            content,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, AzureNsgAnalysisError):
            raise
        raise AzureNsgAnalysisError("Malformed supplied JSON") from exc
    _measure(value, None, report=report)
    return value


def _object(value: Any, fields: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != fields:
        raise AzureNsgAnalysisError(f"Exact closed {label} fields required")


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> None:
    if type(value) is not list or not (1 if nonempty else 0) <= len(value) <= maximum:
        raise AzureNsgAnalysisError(f"Bounded native {label} array required")


def _identifier(value: Any) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AzureNsgAnalysisError("Bounded native declared identity required")


def _enum(value: Any, choices: set[str], label: str) -> None:
    if type(value) is not str or value not in choices:
        raise AzureNsgAnalysisError(f"Exact native {label} required")


def _port(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= 65535:
        raise AzureNsgAnalysisError("Exact native port in 0..65535 required")


def _priority(value: Any) -> None:
    if type(value) is not int or not (100 <= value <= 4096 or value in {65000, 65001, 65500}):
        raise AzureNsgAnalysisError("Custom or supported declared default priority required")


def _networks(values: Any, budget: _Budget) -> tuple:
    _list(values, MAX_PREDICATE_ATOMS, "CIDR", nonempty=True)
    seen: set[str] = set()
    parsed: list = []
    for value in values:
        if type(value) is not str or len(value) > 64 or value in seen:
            raise AzureNsgAnalysisError("Unique canonical native CIDRs required")
        budget.charge(len(value) + 128)
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise AzureNsgAnalysisError("Canonical strict CIDR required") from exc
        if str(network) != value:
            raise AzureNsgAnalysisError("Canonical CIDR spelling required")
        seen.add(value)
        parsed.append(network)
    return tuple(parsed)


def _ranges(values: Any, budget: _Budget) -> tuple:
    _list(values, MAX_PREDICATE_ATOMS, "port range", nonempty=True)
    seen: set[tuple[int, int]] = set()
    parsed: list = []
    for pair in values:
        budget.charge(4)
        if type(pair) is not list or len(pair) != 2:
            raise AzureNsgAnalysisError("Native inclusive [minimum,maximum] port pair required")
        low, high = pair
        _port(low)
        _port(high)
        if low > high or (low, high) in seen:
            raise AzureNsgAnalysisError("Ordered unique port ranges required")
        seen.add((low, high))
        parsed.append((low, high))
    return tuple(parsed)


def _address_ip(value: Any, budget: _Budget) -> Any:
    if type(value) is not str or len(value) > 64:
        raise AzureNsgAnalysisError("Bounded canonical native IP address required")
    budget.charge(len(value) + 128)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AzureNsgAnalysisError("Canonical IP address required") from exc
    if str(address) != value or "%" in value:
        raise AzureNsgAnalysisError("Canonical unscoped IP spelling required")
    return address


def _compile(model: dict, budget: _Budget) -> tuple[dict, list]:
    _object(model, {"schema_version", "nsgs", "attachments", "flows"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AzureNsgAnalysisError("Exact native schema version 1 required")
    _list(model["nsgs"], MAX_NSGS, "NSG")
    _list(model["flows"], MAX_FLOWS, "flow", nonempty=True)
    attachments = model["attachments"]
    _object(attachments, {"complete", "subnet_nsg_id", "nic_nsg_id"}, "attachment")
    if type(attachments["complete"]) is not bool:
        raise AzureNsgAnalysisError("Exact native attachment completeness bool required")
    nsgs: dict = {}
    total_rules = 0
    for group in model["nsgs"]:
        budget.charge(8)
        _object(group, {"nsg_id", "rules_complete", "rules"}, "NSG")
        _identifier(group["nsg_id"])
        if group["nsg_id"] in nsgs or type(group["rules_complete"]) is not bool:
            raise AzureNsgAnalysisError("Unique NSG and native completeness bool required")
        _list(group["rules"], MAX_RULES_PER_NSG, "rule")
        total_rules += len(group["rules"])
        if total_rules > MAX_TOTAL_RULES:
            raise AzureNsgAnalysisError("Aggregate rule bound exhausted")
        identities: set[str] = set()
        priorities: set[tuple[str, int]] = set()
        rules: list = []
        for rule in group["rules"]:
            budget.charge(12)
            _object(rule, _RULE_FIELDS, "rule")
            _identifier(rule["rule_id"])
            _priority(rule["priority"])
            _enum(rule["direction"], {"Inbound", "Outbound"}, "direction")
            _enum(rule["access"], {"Allow", "Deny"}, "access")
            key = (rule["direction"], rule["priority"])
            if rule["rule_id"] in identities or key in priorities:
                raise AzureNsgAnalysisError("Rule IDs and direction/priority pairs must be unique")
            identities.add(rule["rule_id"])
            priorities.add(key)
            predicate = rule["predicate"]
            if type(predicate) is not dict or "kind" not in predicate:
                raise AzureNsgAnalysisError("Exact tagged predicate required")
            if predicate["kind"] == "unsupported":
                _object(predicate, {"kind", "reason"}, "unsupported predicate")
                _enum(predicate["reason"], _UNSUPPORTED_REASONS, "unsupported reason")
                compiled = None
            else:
                _object(predicate, _CIDR_FIELDS, "CIDR predicate")
                _enum(predicate["kind"], {"cidr_ports"}, "predicate kind")
                _enum(predicate["protocol"], {"TCP", "UDP", "Any"}, "predicate protocol")
                compiled = (
                    predicate["protocol"],
                    _networks(predicate["source_cidrs"], budget),
                    _networks(predicate["destination_cidrs"], budget),
                    _ranges(predicate["source_ports"], budget),
                    _ranges(predicate["destination_ports"], budget),
                )
            rules.append((rule, compiled))
        budget.charge(len(rules) * (len(rules).bit_length() + 1))
        rules.sort(key=lambda entry: entry[0]["priority"])
        nsgs[group["nsg_id"]] = (group["rules_complete"], rules)
    for name in ("subnet_nsg_id", "nic_nsg_id"):
        reference = attachments[name]
        if reference is not None:
            _identifier(reference)
            if reference not in nsgs:
                raise AzureNsgAnalysisError("Every declared attachment must join a supplied NSG")
    flow_ids: set[str] = set()
    flows: list = []
    for flow in model["flows"]:
        budget.charge(10)
        _object(flow, _FLOW_FIELDS, "flow")
        _identifier(flow["flow_id"])
        if flow["flow_id"] in flow_ids:
            raise AzureNsgAnalysisError("Duplicate flow identity")
        flow_ids.add(flow["flow_id"])
        _enum(flow["direction"], {"Inbound", "Outbound"}, "flow direction")
        _enum(flow["protocol"], {"TCP", "UDP"}, "flow protocol")
        _port(flow["source_port"])
        _port(flow["destination_port"])
        source = _address_ip(flow["source_ip"], budget)
        destination = _address_ip(flow["destination_ip"], budget)
        if source.version != destination.version:
            raise AzureNsgAnalysisError("A concrete flow must use one declared address family")
        flows.append((flow, source, destination))
    return nsgs, flows


def _matches(flow: dict, source: Any, destination: Any, predicate: tuple, budget: _Budget) -> bool:
    protocol, source_nets, destination_nets, source_ports, destination_ports = predicate
    budget.charge(1)
    if protocol != "Any" and protocol != flow["protocol"]:
        return False
    for address, networks in ((source, source_nets), (destination, destination_nets)):
        found = False
        for network in networks:
            budget.charge(1)
            if address.version == network.version and address in network:
                found = True
                break
        if not found:
            return False
    for port, ranges in (
        (flow["source_port"], source_ports),
        (flow["destination_port"], destination_ports),
    ):
        found = False
        for low, high in ranges:
            budget.charge(1)
            if low <= port <= high:
                found = True
                break
        if not found:
            return False
    return True


def _layer(
    layer: str,
    reference: Any,
    attachments_complete: bool,
    nsgs: dict,
    compiled_flow: tuple,
    budget: _Budget,
) -> dict:
    budget.charge(8)
    row = {
        "layer": layer,
        "nsg_id": reference,
        "decision": "unassessed",
        "reason": "no_supplied_match",
        "candidate_rule_id": None,
        "candidate_priority": None,
        "candidate_declared_access": None,
    }
    if not attachments_complete:
        row["reason"] = "attachment_projection_incomplete"
    elif reference is None:
        row.update(decision="not_attached", reason="declared_attachment_absent")
    else:
        complete, rules = nsgs[reference]
        if not complete:
            row["reason"] = "rules_incomplete"
            return row
        flow, source, destination = compiled_flow
        for rule, predicate in rules:
            budget.charge(1)
            if rule["direction"] != flow["direction"]:
                continue
            if predicate is None or _matches(flow, source, destination, predicate, budget):
                row.update(
                    candidate_rule_id=rule["rule_id"],
                    candidate_priority=rule["priority"],
                    candidate_declared_access=rule["access"],
                )
                if predicate is None:
                    row["reason"] = "unsupported_earlier_predicate"
                else:
                    row.update(decision=rule["access"].lower(), reason="known_first_supplied_match")
                break
    return row


def _prepare(model: Any, budget: _Budget) -> tuple[dict, str]:
    owned, source_text = _capture(model, budget)
    nsgs, flows = _compile(owned, budget)
    budget.charge(512)
    rows: list[dict] = []
    summary = {"flows": len(flows), "allow": 0, "deny": 0, "not_filtered": 0, "unassessed": 0}
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
        "analysis_id": "NSGA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    total_size, total_nodes = _measure(body, budget, report=True)
    attachments = owned["attachments"]
    for flow in flows:
        budget.charge(16)
        order = ["subnet", "nic"] if flow[0]["direction"] == "Inbound" else ["nic", "subnet"]
        layers = [
            _layer(name, attachments[name + "_nsg_id"], attachments["complete"], nsgs, flow, budget)
            for name in order
        ]
        decisions = [layer["decision"] for layer in layers]
        uncertainty = [
            layer["layer"] + ":" + layer["reason"]
            for layer in layers
            if layer["decision"] == "unassessed"
        ]
        if not attachments["complete"]:
            decision, count = "unassessed", "unassessed"
        elif "deny" in decisions:
            decision, count = "deny_under_supplied_nsg_predicates", "deny"
        elif "unassessed" in decisions:
            decision, count = "unassessed", "unassessed"
        elif decisions == ["not_attached", "not_attached"]:
            decision, count = "not_filtered_by_declared_nsgs", "not_filtered"
        else:
            decision, count = "allow_under_supplied_nsg_predicates", "allow"
        row = {
            "flow_id": flow[0]["flow_id"],
            "direction": flow[0]["direction"],
            "layer_order": order,
            "layers": layers,
            "decision": decision,
            "uncertainty": uncertainty,
        }
        row_size, row_nodes = _measure(row, budget, report=True)
        if (
            total_size + row_size + 1 > MAX_REPORT_BYTES
            or total_nodes + row_nodes > MAX_REPORT_NODES
        ):
            raise AzureNsgAnalysisError("Cumulative observation retention bound exhausted")
        total_size += row_size + 1
        total_nodes += row_nodes
        budget.charge(row_size + row_nodes)
        rows.append(row)
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
        raise AzureNsgAnalysisError("Native report schema version 1 required")
    for name, expected in _METADATA.items():
        if type(document[name]) is not str or document[name] != expected:
            raise AzureNsgAnalysisError("Exact report source/ownership metadata required")
    for name in ("source_model_sha256", "analysis_sha256"):
        if type(document[name]) is not str or _SHA.fullmatch(document[name]) is None:
            raise AzureNsgAnalysisError("Exact native lowercase digest required")
    if (
        type(document["analysis_id"]) is not str
        or _ANALYSIS_ID.fullmatch(document["analysis_id"]) is None
    ):
        raise AzureNsgAnalysisError("Exact native analysis identity required")
    _object(document["flags"], set(_FLAGS), "flags")
    if any(type(value) is not bool or value is not False for value in document["flags"].values()):
        raise AzureNsgAnalysisError("Every promotion/proof flag must be native false")
    _object(document["effects"], set(_EFFECTS), "effects")
    if any(type(value) is not str or value != "none" for value in document["effects"].values()):
        raise AzureNsgAnalysisError("Every effect must be native none")
    for name, expected in (("bounds", _bounds()), ("limitations", list(_LIMITATIONS))):
        supplied_size, _ = _measure(document[name], budget, report=True)
        expected_size, _ = _measure(expected, budget, report=True)
        budget.charge(2 * (supplied_size + expected_size))
        if _canonical(document[name]) != _canonical(expected):
            raise AzureNsgAnalysisError("Exact declared software bounds and limitations required")
    _object(document["summary"], _SUMMARY_FIELDS, "summary")
    if any(
        type(value) is not int or not 0 <= value <= MAX_FLOWS
        for value in document["summary"].values()
    ):
        raise AzureNsgAnalysisError("Native bounded summary counters required")
    _list(document["flow_observations"], MAX_FLOWS, "observation", nonempty=True)
    for row in document["flow_observations"]:
        budget.charge(20)
        _object(row, _ROW_FIELDS, "observation")
        _identifier(row["flow_id"])
        _enum(row["direction"], {"Inbound", "Outbound"}, "observation direction")
        _enum(row["decision"], _DECISIONS, "observation decision")
        if type(row["layer_order"]) is not list or row["layer_order"] not in (
            ["subnet", "nic"],
            ["nic", "subnet"],
        ):
            raise AzureNsgAnalysisError("Exact native directional layer order required")
        _list(row["uncertainty"], 2, "uncertainty")
        if any(type(reason) is not str for reason in row["uncertainty"]):
            raise AzureNsgAnalysisError("Native uncertainty codes required")
        if type(row["layers"]) is not list or len(row["layers"]) != 2:
            raise AzureNsgAnalysisError("Exactly two declared layer observations required")
        for layer in row["layers"]:
            _object(layer, _LAYER_FIELDS, "layer observation")
            _enum(layer["layer"], {"subnet", "nic"}, "layer")
            _enum(
                layer["decision"], {"allow", "deny", "unassessed", "not_attached"}, "layer decision"
            )
            _enum(layer["reason"], _LAYER_REASONS, "layer reason")
            for name in ("nsg_id", "candidate_rule_id"):
                if layer[name] is not None:
                    _identifier(layer[name])
            if layer["candidate_priority"] is not None:
                _priority(layer["candidate_priority"])
            if layer["candidate_declared_access"] is not None:
                _enum(layer["candidate_declared_access"], {"Allow", "Deny"}, "candidate access")


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
    """Fund all final encoding, digests, comparisons and storage before the first hash."""
    prepared: list[tuple[dict, str, dict]] = []
    final_lengths: list[int] = []
    for (body, source_text), original in zip(plans, originals, strict=True):
        size, nodes = _measure(body, budget, report=True)
        budget.charge(2 * len(body))
        unsigned = {
            key: value
            for key, value in body.items()
            if key not in {"analysis_id", "analysis_sha256"}
        }
        unsigned_size, unsigned_nodes = _measure(unsigned, budget, report=True)
        # Canonical unsigned encoding, hash-buffer concatenation, ASCII copies and
        # digest reads are distinct passes. The final full encoding is also funded.
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
        final_lengths.append(size)
        prepared.append((body, source_text, unsigned))
    if compare_originals:
        budget.charge(sum(final_lengths))
    results: list[tuple[dict, str]] = []
    for (body, source_text, unsigned), original in zip(prepared, originals, strict=True):
        digest_source = _address(MODEL_DOMAIN, source_text)
        body["source_model_sha256"] = digest_source
        unsigned["source_model_sha256"] = digest_source
        digest = _address(DOMAIN, _canonical(unsigned))
        body["analysis_id"] = "NSGA-" + digest[7:39].upper()
        body["analysis_sha256"] = digest
        text = _canonical(body)
        if original is not None and original != text:
            raise AzureNsgAnalysisError(
                "Report does not exactly replay the embedded original source"
            )
        results.append((body, text))
    if compare_originals and results[0][1] != results[1][1]:
        raise AzureNsgAnalysisError("Report differs from separately supplied original model")
    return results


def _storage(report: Any, budget: _Budget) -> Any:
    if type(report) is not AzureNsgAnalysis:
        raise AzureNsgAnalysisError("Exact native Azure NSG analysis family required")
    return _decode(getattr(report, "_document_json", None), budget, report=True)


@dataclass(frozen=True, slots=True, init=False)
class AzureNsgAnalysis:
    """Detached NSG arithmetic, never a transport, connectivity proof or authorization."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        budget = _Budget()
        plan, original = _plan_report(document, budget)
        result = _seal([plan], budget, [original])[0]
        object.__setattr__(self, "_document_json", result[1])

    @classmethod
    def from_dict(cls, document: Any) -> AzureNsgAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> AzureNsgAnalysis:
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


def _owned(content: str) -> AzureNsgAnalysis:
    result = object.__new__(AzureNsgAnalysis)
    object.__setattr__(result, "_document_json", content)
    return result


def analyze_supplied_azure_nsg(model: Any) -> AzureNsgAnalysis:
    """Calculate only supplied directional rule predicates and uncertainty."""
    budget = _Budget()
    return _owned(_seal([_prepare(model, budget)], budget, [None])[0][1])


def analyze_supplied_azure_nsg_bytes(*, model_bytes: Any) -> AzureNsgAnalysis:
    """Accept bounded original ASCII JSON bytes, without reading any resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise AzureNsgAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AzureNsgAnalysisError("ASCII model bytes required") from exc
    model = _decode(text, budget)
    return _owned(_seal([_prepare(model, budget)], budget, [None])[0][1])


def verify_supplied_azure_nsg_analysis(report: Any, *, model: Any) -> AzureNsgAnalysis:
    """Replay separately supplied original declarations, never provider state or authority."""
    budget = _Budget()
    embedded, original = _plan_report(_storage(report, budget), budget)
    separate = _prepare(model, budget)
    result = _seal([embedded, separate], budget, [original, None], compare_originals=True)[1]
    return _owned(result[1])


def component_fixture() -> dict:
    """Return fresh small synthetic inbound/outbound declared predicates."""
    predicate = {
        "kind": "cidr_ports",
        "protocol": "TCP",
        "source_cidrs": ["10.0.0.0/24"],
        "destination_cidrs": ["10.0.1.0/24"],
        "source_ports": [[0, 65535]],
        "destination_ports": [[443, 443]],
    }
    group = {
        "nsg_id": "synthetic-nsg",
        "rules_complete": True,
        "rules": [
            {
                "rule_id": "inbound-tls",
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "predicate": predicate,
            },
            {
                "rule_id": "outbound-unknown-tag",
                "priority": 200,
                "direction": "Outbound",
                "access": "Allow",
                "predicate": {"kind": "unsupported", "reason": "service_tag"},
            },
        ],
    }
    flow = {
        "flow_id": "synthetic-inbound",
        "direction": "Inbound",
        "protocol": "TCP",
        "source_ip": "10.0.0.7",
        "source_port": 49152,
        "destination_ip": "10.0.1.8",
        "destination_port": 443,
    }
    return {
        "schema_version": 1,
        "nsgs": [group],
        "attachments": {"complete": True, "subnet_nsg_id": "synthetic-nsg", "nic_nsg_id": None},
        "flows": [flow, {**flow, "flow_id": "synthetic-outbound", "direction": "Outbound"}],
    }


__all__ = [
    "AzureNsgAnalysis",
    "AzureNsgAnalysisError",
    "analyze_supplied_azure_nsg",
    "analyze_supplied_azure_nsg_bytes",
    "verify_supplied_azure_nsg_analysis",
    "component_fixture",
]
