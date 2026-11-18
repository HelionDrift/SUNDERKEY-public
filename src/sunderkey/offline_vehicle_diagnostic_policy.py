"""Project supplied vehicle diagnostic declarations against a local policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "vehicle_supplied_diagnostic_policy_projection"
PROFILE_ID = "AOE-GD-D25-S02"
CAPABILITY_ID = "army.gd.d25.s02"
VECTOR_ID = "AV-GD-D25-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GD-D25-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:88bc73b0c0cf075c21313886ff7abf86c7b0fb9d7dcd2db683cbf70802f0b7ab"
DOMAIN = "sunderkey.offline-vehicle-diagnostic-policy.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
CONTEXT_TAGS = {"can", "uds", "doip"}
SERVICE_CLASSES = {"observation", "state_change"}
CONTROL_LABELS = {"approved_scope", "supervised", "change_window", "rollback_plan"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class VehicleDiagnosticPolicyError(ValueError):
    """A supplied policy declaration or original-model replay is invalid."""


def _identifiers(value: Any, maximum: int, label: str) -> list[str]:
    values = core.bounded_list(value, maximum, label)
    if not values:
        raise VehicleDiagnosticPolicyError(f"{label} must be nonempty")
    for item in values:
        core.identifier(item, label)
    if len(values) != len(set(values)):
        raise VehicleDiagnosticPolicyError(f"{label} contains a duplicate")
    return values


def _choices(value: Any, allowed: set[str], maximum: int, label: str) -> list[str]:
    values = core.bounded_list(value, maximum, label)
    if not values:
        raise VehicleDiagnosticPolicyError(f"{label} must be nonempty")
    for item in values:
        core.choice(item, allowed, label)
    if len(values) != len(set(values)):
        raise VehicleDiagnosticPolicyError(f"{label} contains a duplicate")
    return values


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "declarations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VehicleDiagnosticPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {
            "allowed_actor_roles", "allowed_session_labels", "allowed_target_ids",
            "allowed_service_classes", "required_controls",
        },
        "policy",
    )
    _identifiers(policy["allowed_actor_roles"], 32, "allowed actor roles")
    _identifiers(policy["allowed_session_labels"], 32, "allowed session labels")
    _identifiers(policy["allowed_target_ids"], 64, "allowed target IDs")
    _choices(policy["allowed_service_classes"], SERVICE_CLASSES, 2, "allowed service classes")
    required = _choices(policy["required_controls"], CONTROL_LABELS, 4, "required controls")
    if "approved_scope" not in required:
        raise VehicleDiagnosticPolicyError("Policy must require declared approved scope")
    declarations = core.bounded_list(model["declarations"], 64, "declarations")
    if not declarations:
        raise VehicleDiagnosticPolicyError("At least one declaration is required")
    seen: set[str] = set()
    for item in declarations:
        row = core.exact(
            item,
            {
                "declaration_id", "actor_role", "session_label", "target_id",
                "service_class", "context_tags", "controls", "expected_policy_match",
            },
            "declaration",
        )
        declaration_id = core.identifier(row["declaration_id"], "declaration ID")
        if declaration_id in seen:
            raise VehicleDiagnosticPolicyError("Duplicate declaration ID")
        seen.add(declaration_id)
        core.identifier(row["actor_role"], "actor role")
        core.identifier(row["session_label"], "session label")
        core.identifier(row["target_id"], "target ID")
        core.choice(row["service_class"], SERVICE_CLASSES, "service class")
        _choices(row["context_tags"], CONTEXT_TAGS, 3, "context tags")
        controls = core.bounded_list(row["controls"], 4, "declaration controls")
        for control in controls:
            core.choice(control, CONTROL_LABELS, "declaration control")
        if len(controls) != len(set(controls)):
            raise VehicleDiagnosticPolicyError("Duplicate declaration control")
        core.boolean(row["expected_policy_match"], "expected policy match")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    policy = model["policy"]
    allowed_actors = set(policy["allowed_actor_roles"])
    allowed_sessions = set(policy["allowed_session_labels"])
    allowed_targets = set(policy["allowed_target_ids"])
    allowed_classes = set(policy["allowed_service_classes"])
    required = set(policy["required_controls"])
    rows = []
    mismatches = []
    for declaration in model["declarations"]:
        missing = sorted(required - set(declaration["controls"]))
        checks = {
            "actor_role_listed": declaration["actor_role"] in allowed_actors,
            "session_label_listed": declaration["session_label"] in allowed_sessions,
            "target_id_listed": declaration["target_id"] in allowed_targets,
            "service_class_listed": declaration["service_class"] in allowed_classes,
        }
        computed = all(checks.values()) and not missing if complete else None
        rows.append({
            "declaration_id": declaration["declaration_id"],
            "context_tags": declaration["context_tags"],
            "service_class": declaration["service_class"],
            **(checks if complete else dict.fromkeys(checks)),
            "missing_required_controls": missing if complete else None,
            "computed_policy_match": computed,
            "expected_policy_match": declaration["expected_policy_match"],
            "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
        })
        if complete and computed != declaration["expected_policy_match"]:
            mismatches.append({
                "declaration_id": declaration["declaration_id"],
                "issue": "unexpected_declared_mismatch"
                if computed else "declared_match_conflicts_with_policy",
            })
    disposition = (
        "unknown"
        if not complete
        else "candidate_supplied_diagnostic_policy_mismatch"
        if mismatches
        else "supplied_diagnostic_declarations_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "declaration_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(not complete),
        "source_authenticated": False,
        "policy_authenticated": False,
        "vehicle_or_network_contacted": False,
        "protocol_message_generated": False,
        "vehicle_state_or_service_effect_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Actors, sessions, targets, service classes, contexts and controls "
            "are caller-supplied labels.",
            "The policy is local metadata, not a CAN, UDS or DoIP protocol "
            "decision or standard requirement.",
            "A policy match is not operational approval, vehicle safety "
            "evidence or service-effect verification.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VDP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class VehicleDiagnosticPolicyReport:
    """Unsigned local-policy projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VehicleDiagnosticPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VehicleDiagnosticPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_vehicle_diagnostic_policy(model: Any) -> VehicleDiagnosticPolicyReport:
    return VehicleDiagnosticPolicyReport._owned(_derive(model))


def verify_supplied_vehicle_diagnostic_policy(
    report: Any, *, model: Any
) -> VehicleDiagnosticPolicyReport:
    if type(report) is not VehicleDiagnosticPolicyReport:
        raise VehicleDiagnosticPolicyError("Exact vehicle diagnostic policy wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VehicleDiagnosticPolicyError("Report differs from separate original model")
    return VehicleDiagnosticPolicyReport._owned(expected)


def verify_supplied_vehicle_diagnostic_policy_bytes(
    report_bytes: bytes, *, model: Any
) -> VehicleDiagnosticPolicyReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise VehicleDiagnosticPolicyError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise VehicleDiagnosticPolicyError("Exported report differs from original replay")
    return VehicleDiagnosticPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-vehicle-diagnostic-policy",
        "inventory_complete": True,
        "policy": {
            "allowed_actor_roles": ["maintenance"],
            "allowed_session_labels": ["inspection"],
            "allowed_target_ids": ["simulated-module-a"],
            "allowed_service_classes": ["observation"],
            "required_controls": ["approved_scope", "supervised"],
        },
        "declarations": [{
            "declaration_id": "synthetic-declaration-a",
            "actor_role": "maintenance",
            "session_label": "inspection",
            "target_id": "simulated-module-a",
            "service_class": "observation",
            "context_tags": ["can", "uds"],
            "controls": ["approved_scope"],
            "expected_policy_match": True,
        }],
    }
