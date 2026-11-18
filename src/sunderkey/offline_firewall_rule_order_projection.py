"""Project a supplied ordered firewall policy without device interaction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_firewall_rule_order"
PROFILE_ID = "AOE-GC-D13-S05"
CAPABILITY_ID = "network.boundary.firewall-proxy-vpn"
VECTOR_ID = "AV-GC-D13-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S05"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a73727ef47cd0262461800375f1d9f442506b96d0583f799a928fdecdaeb63e3"
DOMAIN = "sunderkey.offline-firewall-rule-order.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_RULES = 256
MAX_QUERIES = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PROTOCOLS = {"tcp", "udp"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class FirewallRuleOrderError(ValueError):
    """A supplied firewall model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise FirewallRuleOrderError(f"{label} must be synthetic")
    return identifier


def _port(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 65_535:
        raise FirewallRuleOrderError(f"{label} must be an integer from 1 to 65535")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_id", "policy_complete",
            "order_complete", "match_semantics_complete", "default_action",
            "rules", "queries",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FirewallRuleOrderError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    _synthetic(model["policy_id"], "policy ID")
    for field in ("policy_complete", "order_complete", "match_semantics_complete"):
        core.boolean(model[field], field)
    core.choice(model["default_action"], {"allow", "deny"}, "default action")
    rules = core.bounded_list(model["rules"], MAX_RULES, "rules")
    queries = core.bounded_list(model["queries"], MAX_QUERIES, "queries")
    if not queries:
        raise FirewallRuleOrderError("At least one query is required")
    seen_rules: set[str] = set()
    for item in rules:
        rule = core.exact(
            item,
            {
                "rule_id", "ingress_zone_id", "egress_zone_id", "protocol",
                "destination_port_min", "destination_port_max", "action",
            },
            "rule",
        )
        rule_id = _synthetic(rule["rule_id"], "rule ID")
        if rule_id in seen_rules:
            raise FirewallRuleOrderError("Duplicate rule ID")
        seen_rules.add(rule_id)
        _synthetic(rule["ingress_zone_id"], "ingress zone ID")
        _synthetic(rule["egress_zone_id"], "egress zone ID")
        core.choice(rule["protocol"], PROTOCOLS, "protocol")
        first = _port(rule["destination_port_min"], "destination port minimum")
        last = _port(rule["destination_port_max"], "destination port maximum")
        if first > last:
            raise FirewallRuleOrderError("Destination port interval is reversed")
        core.choice(rule["action"], {"allow", "deny"}, "rule action")
    seen_queries: set[str] = set()
    for item in queries:
        query = core.exact(
            item,
            {
                "query_id", "ingress_zone_id", "egress_zone_id", "protocol",
                "destination_port",
            },
            "query",
        )
        query_id = _synthetic(query["query_id"], "query ID")
        if query_id in seen_queries:
            raise FirewallRuleOrderError("Duplicate query ID")
        seen_queries.add(query_id)
        _synthetic(query["ingress_zone_id"], "ingress zone ID")
        _synthetic(query["egress_zone_id"], "egress zone ID")
        core.choice(query["protocol"], PROTOCOLS, "protocol")
        _port(query["destination_port"], "destination port")
    return model


def _matches(rule: dict, query: dict) -> bool:
    return (
        rule["ingress_zone_id"] == query["ingress_zone_id"]
        and rule["egress_zone_id"] == query["egress_zone_id"]
        and rule["protocol"] == query["protocol"]
        and rule["destination_port_min"] <= query["destination_port"]
        <= rule["destination_port_max"]
    )


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[field]
        for field in ("policy_complete", "order_complete", "match_semantics_complete")
    )
    projections: list[dict] = []
    for query in model["queries"]:
        matched = next((rule for rule in model["rules"] if _matches(rule, query)), None)
        action = matched["action"] if matched is not None else model["default_action"]
        disposition = (
            "unknown_incomplete_declarations" if not complete
            else "allow_under_declared_policy" if action == "allow"
            else "deny_under_declared_policy"
        )
        projections.append({
            "query_id": query["query_id"],
            "matched_rule_id": matched["rule_id"] if complete and matched else None,
            "used_default_action": bool(complete and matched is None),
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "query_count": len(projections),
            "declared_allow_count": sum(
                row["disposition"] == "allow_under_declared_policy"
                for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations"
                for row in projections
            ),
        },
        "source_authenticated": False,
        "rule_installation_observed": False,
        "device_order_observed": False,
        "traffic_observed": False,
        "nat_proxy_or_vpn_modeled": False,
        "firewall_effectiveness_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Rule order, zones, match semantics and default action are caller declarations.",
            "The first supplied match controls only this local model, not a device.",
            "NAT, proxy, VPN, stateful replies, IP prefixes and nested policies are not modeled.",
            "An allow or deny projection does not prove live reachability or isolation.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="FRO-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class FirewallRuleOrderReport:
    """Unsigned firewall projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FirewallRuleOrderError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FirewallRuleOrderReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_firewall_rule_order(model: Any) -> FirewallRuleOrderReport:
    try:
        return FirewallRuleOrderReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise FirewallRuleOrderError(str(exc)) from exc


def verify_supplied_firewall_rule_order(
    report: Any, *, model: Any,
) -> FirewallRuleOrderReport:
    if type(report) is not FirewallRuleOrderReport:
        raise FirewallRuleOrderError("Exact report wrapper required")
    expected = analyze_supplied_firewall_rule_order(model)
    if report.to_json() != expected.to_json():
        raise FirewallRuleOrderError("Report differs from separate original model")
    return expected


def verify_supplied_firewall_rule_order_bytes(
    report_bytes: bytes, *, model: Any,
) -> FirewallRuleOrderReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise FirewallRuleOrderError(str(exc)) from exc
    expected = analyze_supplied_firewall_rule_order(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise FirewallRuleOrderError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:firewall-source",
        "policy_id": "synthetic:policy-one",
        "policy_complete": True,
        "order_complete": True,
        "match_semantics_complete": True,
        "default_action": "deny",
        "rules": [
            {"rule_id": "synthetic:deny-admin", "ingress_zone_id": "synthetic:guest",
             "egress_zone_id": "synthetic:service", "protocol": "tcp",
             "destination_port_min": 8443, "destination_port_max": 8443,
             "action": "deny"},
            {"rule_id": "synthetic:allow-web", "ingress_zone_id": "synthetic:guest",
             "egress_zone_id": "synthetic:service", "protocol": "tcp",
             "destination_port_min": 8000, "destination_port_max": 9000,
             "action": "allow"},
        ],
        "queries": [
            {"query_id": "synthetic:admin", "ingress_zone_id": "synthetic:guest",
             "egress_zone_id": "synthetic:service", "protocol": "tcp",
             "destination_port": 8443},
            {"query_id": "synthetic:web", "ingress_zone_id": "synthetic:guest",
             "egress_zone_id": "synthetic:service", "protocol": "tcp",
             "destination_port": 8080},
            {"query_id": "synthetic:other", "ingress_zone_id": "synthetic:guest",
             "egress_zone_id": "synthetic:service", "protocol": "udp",
             "destination_port": 8080},
        ],
    }


__all__ = [
    "FirewallRuleOrderError", "FirewallRuleOrderReport",
    "analyze_supplied_firewall_rule_order", "verify_supplied_firewall_rule_order",
    "verify_supplied_firewall_rule_order_bytes", "component_fixture",
]
