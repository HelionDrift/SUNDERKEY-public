"""Compare synthetic eSIM profile transitions with a supplied transition policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "telecom_supplied_esim_profile_transition_projection"
PROFILE_ID = "AOE-GC-D13-S20"
CAPABILITY_ID = "army.gc.d13.s20"
VECTOR_ID = "AV-GC-D13-S20-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S20"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:1b8f40a2bcf336321a8c35a24c5de788bce20b5e081e449303ae7f021cb4d088"
DOMAIN = "sunderkey.offline-esim-profile-transitions.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class EsimProfileTransitionError(ValueError):
    """A supplied profile-transition model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "allowed_transitions", "profile_events",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EsimProfileTransitionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise EsimProfileTransitionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    allowed = set()
    for item in core.bounded_list(model["allowed_transitions"], 32, "allowed transitions"):
        row = core.exact(item, {"from_state", "to_state"}, "allowed transition")
        pair = (
            core.choice(row["from_state"], {"absent", "disabled", "enabled"}, "from state"),
            core.choice(row["to_state"], {"absent", "disabled", "enabled"}, "to state"),
        )
        if pair in allowed:
            raise EsimProfileTransitionError("Duplicate allowed transition")
        allowed.add(pair)
    events = core.bounded_list(model["profile_events"], 64, "profile events")
    if not events:
        raise EsimProfileTransitionError("At least one profile event is required")
    seen = set()
    rows = []
    for item in events:
        row = core.exact(item, {
            "event_id", "profile_ref", "sequence", "from_state", "to_state",
        }, "profile event")
        event_id = core.identifier(row["event_id"], "event ID")
        profile_ref = core.identifier(row["profile_ref"], "opaque profile reference")
        sequence = row["sequence"]
        if type(sequence) is not int or not 0 <= sequence <= 100_000:
            raise EsimProfileTransitionError("Sequence must be a bounded nonnegative integer")
        if event_id in seen:
            raise EsimProfileTransitionError("Duplicate event ID")
        seen.add(event_id)
        pair = (
            core.choice(row["from_state"], {"absent", "disabled", "enabled"}, "from state"),
            core.choice(row["to_state"], {"absent", "disabled", "enabled"}, "to state"),
        )
        rows.append({
            "event_id": event_id,
            "profile_ref": profile_ref,
            "sequence": sequence,
            "from_state": pair[0],
            "to_state": pair[1],
            "outside_supplied_transition_policy": pair not in allowed,
        })
    rows.sort(key=lambda row: (row["profile_ref"], row["sequence"], row["event_id"]))
    sequence_uncertainty = []
    prior = {}
    for row in rows:
        earlier = prior.get(row["profile_ref"])
        if earlier is not None and (
            row["sequence"] <= earlier["sequence"] or row["from_state"] != earlier["to_state"]
        ):
            sequence_uncertainty.append(row["event_id"])
        prior[row["profile_ref"]] = row
    deviations = [row["event_id"] for row in rows if row["outside_supplied_transition_policy"]]
    unknown = [] if complete else ["supplied_profile_event_inventory_incomplete"]
    if sequence_uncertainty:
        unknown.append("supplied_profile_sequence_discontinuity")
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
        "event_projections": rows,
        "declared_transition_deviation_event_ids": deviations,
        "sequence_uncertainty_event_ids": sequence_uncertainty,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_esim_transition_projection",
        "source_authenticated": False,
        "esim_service_connected": False,
        "profile_provisioned": False,
        "subscriber_data_accessed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Profile references, transitions, sequences, policy, and completeness are assertions.",
            "Opaque profile references must not contain identifiers or provisioning material.",
            "The model does not validate eUICC state, subscriber identity, or provisioning.",
            "A mismatch does not prove exploitation or impact.",
            "No SIM, eSIM service, network, credential, subscriber, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EPT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class EsimProfileTransitionReport:
    """Unsigned transition projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EsimProfileTransitionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EsimProfileTransitionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_esim_profile_transitions(model: Any) -> EsimProfileTransitionReport:
    return EsimProfileTransitionReport._owned(_derive(model))


def verify_supplied_esim_profile_transitions(
    report: Any, *, model: Any
) -> EsimProfileTransitionReport:
    if type(report) is not EsimProfileTransitionReport:
        raise EsimProfileTransitionError("Exact eSIM transition wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EsimProfileTransitionError("Report differs from separate original model")
    return EsimProfileTransitionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-esim-transitions",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "allowed_transitions": [
            {"from_state": "absent", "to_state": "disabled"},
            {"from_state": "disabled", "to_state": "enabled"},
        ],
        "profile_events": [{
            "event_id": "event-a", "profile_ref": "profile-opaque-a",
            "sequence": 1, "from_state": "absent", "to_state": "enabled",
        }],
    }
