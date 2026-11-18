"""Compare synthetic A1 policy targets with supplied RIC support declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "telecom_supplied_oran_policy_target_projection"
PROFILE_ID = "AOE-GC-D13-S19"
CAPABILITY_ID = "army.gc.d13.s19"
VECTOR_ID = "AV-GC-D13-S19-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S19"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3a1b4fbbbc3051e4bdd467388067e3449fcc8782a4afd2ea4013eaf88fb79637"
DOMAIN = "sunderkey.offline-oran-policy-targets.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OranPolicyTargetError(ValueError):
    """A supplied O-RAN policy-target model or replay is invalid."""


def _identifiers(value: Any, *, label: str) -> list[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, 32, label)]
    if len(items) != len(set(items)):
        raise OranPolicyTargetError(f"Duplicate {label}")
    return items


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "ric_support", "policy_intents",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OranPolicyTargetError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise OranPolicyTargetError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    support = {}
    for item in core.bounded_list(model["ric_support"], 32, "RIC support"):
        row = core.exact(item, {"ric_id", "supported_policy_type_ids"}, "RIC support")
        ric_id = core.identifier(row["ric_id"], "RIC ID")
        if ric_id in support:
            raise OranPolicyTargetError("Duplicate RIC ID")
        support[ric_id] = set(_identifiers(
            row["supported_policy_type_ids"], label="policy type ID"
        ))
    if not support:
        raise OranPolicyTargetError("At least one RIC is required")
    intents = core.bounded_list(model["policy_intents"], 64, "policy intents")
    if not intents:
        raise OranPolicyTargetError("At least one policy intent is required")
    rows = []
    seen = set()
    unknown_targets = []
    for item in intents:
        row = core.exact(item, {
            "intent_id", "ric_id", "policy_type_id", "active_declared",
        }, "policy intent")
        intent_id = core.identifier(row["intent_id"], "intent ID")
        ric_id = core.identifier(row["ric_id"], "RIC ID")
        policy_type_id = core.identifier(row["policy_type_id"], "policy type ID")
        if intent_id in seen:
            raise OranPolicyTargetError("Duplicate intent ID")
        seen.add(intent_id)
        active = core.boolean(row["active_declared"], "active declaration")
        known = ric_id in support
        if active and not known:
            unknown_targets.append(intent_id)
        flags = (
            ["policy_type_outside_supplied_ric_support"]
            if active and known and policy_type_id not in support[ric_id] else []
        )
        rows.append({
            "intent_id": intent_id,
            "ric_id": ric_id,
            "policy_type_id": policy_type_id,
            "active_declared": active,
            "ric_in_supplied_inventory": known,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["intent_id"])
    deviations = [row["intent_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_ric_inventory_incomplete"]
    if unknown_targets:
        unknown.append("policy_target_absent_from_supplied_ric_inventory")
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "intent_projections": rows,
        "declared_policy_deviation_intent_ids": deviations,
        "unknown_target_intent_ids": sorted(unknown_targets),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_oran_policy_target_projection",
        "source_authenticated": False,
        "ric_connected": False,
        "a1_request_sent": False,
        "policy_applied": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "RIC support, intents, policy types, and completeness are assertions.",
            "The model does not validate the A1 interface or effective policy support.",
            "A mismatch does not prove deployment, exploitation, or impact.",
            "No RIC, network, credential, policy service, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OPT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OranPolicyTargetReport:
    """Unsigned policy-target projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OranPolicyTargetError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OranPolicyTargetReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_oran_policy_targets(model: Any) -> OranPolicyTargetReport:
    return OranPolicyTargetReport._owned(_derive(model))


def verify_supplied_oran_policy_targets(
    report: Any, *, model: Any
) -> OranPolicyTargetReport:
    if type(report) is not OranPolicyTargetReport:
        raise OranPolicyTargetError("Exact O-RAN policy-target wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OranPolicyTargetError("Report differs from separate original model")
    return OranPolicyTargetReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-oran-policy-targets",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "ric_support": [{
            "ric_id": "ric-a", "supported_policy_type_ids": ["policy-type-a"],
        }],
        "policy_intents": [{
            "intent_id": "intent-a", "ric_id": "ric-a",
            "policy_type_id": "policy-type-b", "active_declared": True,
        }],
    }
