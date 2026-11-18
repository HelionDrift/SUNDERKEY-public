"""Project acceptance paths in a supplied cryptographic protocol state graph."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_protocol_state_graph"
PROFILE_ID = "AOE-GE-D22-S01"
CAPABILITY_ID = "army.ge.d22.s01"
VECTOR_ID = "AV-GE-D22-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S01"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e8212502bf85c41809b7a569d5fb86c7c880ebc1fdf4f4738d2adac3e359cd87"
DOMAIN = "sunderkey.offline-crypto-protocol-state-graph.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_STATES = 32
MAX_TRANSITIONS = 128
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class CryptoProtocolStateGraphError(ValueError):
    """The supplied protocol model or its original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, bool], dict[str, list[tuple]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "state_inventory_complete",
            "initial_state_id", "states", "transitions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CryptoProtocolStateGraphError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["state_inventory_complete"], "inventory completeness")
    initial = core.identifier(model["initial_state_id"], "initial state ID")
    states: dict[str, bool] = {}
    for item in core.bounded_list(model["states"], MAX_STATES, "states"):
        row = core.exact(item, {"state_id", "accepts_application_data"}, "state")
        state = core.identifier(row["state_id"], "state ID")
        if state in states:
            raise CryptoProtocolStateGraphError("Duplicate state ID")
        states[state] = core.boolean(row["accepts_application_data"], "acceptance flag")
    if initial not in states:
        raise CryptoProtocolStateGraphError("Initial state is outside supplied inventory")
    transitions: dict[str, list[tuple]] = {state: [] for state in states}
    seen_ids = set()
    for item in core.bounded_list(model["transitions"], MAX_TRANSITIONS, "transitions"):
        row = core.exact(
            item,
            {
                "transition_id", "from_state_id", "to_state_id",
                "asserted_peer_authentication",
            },
            "transition",
        )
        transition_id = core.identifier(row["transition_id"], "transition ID")
        source = core.identifier(row["from_state_id"], "source state ID")
        target = core.identifier(row["to_state_id"], "target state ID")
        if transition_id in seen_ids:
            raise CryptoProtocolStateGraphError("Duplicate transition ID")
        if source not in states or target not in states:
            raise CryptoProtocolStateGraphError("Transition state is outside supplied inventory")
        seen_ids.add(transition_id)
        marker = core.boolean(row["asserted_peer_authentication"], "authentication marker")
        transitions[source].append((transition_id, target, marker))
    for rows in transitions.values():
        rows.sort()
    return model, states, transitions, core.canonical(model)


def _derive(value: Any) -> dict:
    model, states, transitions, source_text = _model(value)
    initial = model["initial_state_id"]
    queue = deque([(initial, False, ())])
    visited = {(initial, False)}
    reachable = set()
    unmarked_path: tuple[str, ...] | None = None
    while queue:
        state, marked, path = queue.popleft()
        reachable.add(state)
        if states[state] and not marked and unmarked_path is None:
            unmarked_path = path
        for transition_id, target, marker in transitions[state]:
            next_state = (target, marked or marker)
            if next_state not in visited:
                visited.add(next_state)
                queue.append((target, next_state[1], (*path, transition_id)))
    unknown = []
    if not model["state_inventory_complete"]:
        unknown.append("supplied_state_inventory_incomplete")
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "state_inventory_complete_asserted": model["state_inventory_complete"],
        "supplied_state_count": len(states),
        "supplied_transition_count": sum(len(rows) for rows in transitions.values()),
        "reachable_state_ids": sorted(reachable),
        "unreachable_state_ids": sorted(set(states) - reachable),
        "accepting_state_ids": sorted(state for state, accepts in states.items() if accepts),
        "acceptance_without_supplied_auth_marker_path_ids": (
            list(unmarked_path) if unmarked_path is not None else None
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_state_graph_projection",
        "source_authenticated": False,
        "authentication_verified": False,
        "protocol_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "States, transitions, acceptance and authentication markers are supplied assertions.",
            "An unmarked graph path is not proof of an authentication bypass.",
            "No protocol packets, keys, endpoints or target were observed.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CPS-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CryptoProtocolStateGraphReport:
    """Unsigned state projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CryptoProtocolStateGraphError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CryptoProtocolStateGraphReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_crypto_protocol(model: Any) -> CryptoProtocolStateGraphReport:
    return CryptoProtocolStateGraphReport._owned(_derive(model))


def verify_supplied_crypto_protocol(
    report: Any, *, model: Any
) -> CryptoProtocolStateGraphReport:
    if type(report) is not CryptoProtocolStateGraphReport:
        raise CryptoProtocolStateGraphError("Exact protocol wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CryptoProtocolStateGraphError("Report differs from separate original model")
    return CryptoProtocolStateGraphReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-protocol-state-graph",
        "state_inventory_complete": True,
        "initial_state_id": "start",
        "states": [
            {"state_id": "start", "accepts_application_data": False},
            {"state_id": "authenticated", "accepts_application_data": False},
            {"state_id": "accepted", "accepts_application_data": True},
        ],
        "transitions": [
            {
                "transition_id": "t1", "from_state_id": "start", "to_state_id": "authenticated",
                "asserted_peer_authentication": True,
            },
            {
                "transition_id": "t2", "from_state_id": "authenticated", "to_state_id": "accepted",
                "asserted_peer_authentication": False,
            },
        ],
    }
