"""Replay caller-supplied workflow transitions without contacting a service."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_workflow_state_replay"
PROFILE_ID = "AOE-GB-D09-S01"
CAPABILITY_ID = "business-logic.workflow-state-machine"
VECTOR_ID = "AV-GB-D09-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6429f2549b0dc4a73038198adddc5a1229b08bd9ee5bd4b951b66a6f983cb1b2"
SEMANTICS_PROFILE = "supplied-workflow-state-replay-v1"
DOMAIN = "sunderkey.offline-workflow-state-replay.v1"
MAX_STATES = 128
MAX_TRANSITIONS = 512
MAX_EVENTS = 512
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_WORKFLOW = re.compile(r"workflow:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
        "workflow_write",
    ),
    "none",
)


class WorkflowStateReplayError(ValueError):
    """The supplied workflow model or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise WorkflowStateReplayError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise WorkflowStateReplayError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise WorkflowStateReplayError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise WorkflowStateReplayError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise WorkflowStateReplayError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise WorkflowStateReplayError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise WorkflowStateReplayError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise WorkflowStateReplayError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise WorkflowStateReplayError(f"{label} identifier is invalid")
    return value


def _unique_ids(values: Any, label: str, maximum: int) -> list[str]:
    if type(values) is not list or not 1 <= len(values) <= maximum:
        raise WorkflowStateReplayError(f"{label} count is invalid")
    result = [_identifier(value, label) for value in values]
    if len(result) != len(set(result)):
        raise WorkflowStateReplayError(f"Duplicate {label}")
    return result


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "workflow_ref",
            "states",
            "terminal_states",
            "initial_state",
            "transitions",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WorkflowStateReplayError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise WorkflowStateReplayError("Semantics profile is invalid")
    if type(model["workflow_ref"]) is not str or _WORKFLOW.fullmatch(model["workflow_ref"]) is None:
        raise WorkflowStateReplayError("Opaque workflow reference is required")
    states = set(_unique_ids(model["states"], "state", MAX_STATES))
    terminals = model["terminal_states"]
    if type(terminals) is not list or len(terminals) > MAX_STATES:
        raise WorkflowStateReplayError("Terminal state count is invalid")
    if any(_identifier(state, "terminal state") not in states for state in terminals) or len(
        set(terminals)
    ) != len(terminals):
        raise WorkflowStateReplayError("Terminal states are invalid")
    if _identifier(model["initial_state"], "initial state") not in states:
        raise WorkflowStateReplayError("Initial state is undeclared")
    transitions = model["transitions"]
    if type(transitions) is not list or not 1 <= len(transitions) <= MAX_TRANSITIONS:
        raise WorkflowStateReplayError("Transition count is invalid")
    transition_ids: set[str] = set()
    for transition in transitions:
        _fields(
            transition, {"transition_id", "from_state", "to_state", "guard_label"}, "transition"
        )
        transition_id = _identifier(transition["transition_id"], "transition")
        if transition_id in transition_ids:
            raise WorkflowStateReplayError("Duplicate transition identifier")
        transition_ids.add(transition_id)
        if (
            _identifier(transition["from_state"], "from state") not in states
            or _identifier(transition["to_state"], "to state") not in states
        ):
            raise WorkflowStateReplayError("Transition references undeclared state")
        _identifier(transition["guard_label"], "guard label")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise WorkflowStateReplayError("Event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id",
                "transition_id",
                "declared_before_state",
                "declared_after_state",
                "guard_outcome",
                "result",
            },
            "event",
        )
        event_id = _identifier(event["event_id"], "event")
        if event_id in event_ids:
            raise WorkflowStateReplayError("Duplicate event identifier")
        event_ids.add(event_id)
        _identifier(event["transition_id"], "event transition")
        for field in ("declared_before_state", "declared_after_state"):
            if _identifier(event[field], field) not in states:
                raise WorkflowStateReplayError("Event references undeclared state")
        if event["guard_outcome"] not in ("satisfied", "unsatisfied", "unknown"):
            raise WorkflowStateReplayError("Guard outcome is invalid")
        if event["result"] not in ("accepted", "rejected"):
            raise WorkflowStateReplayError("Event result is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    transitions = {row["transition_id"]: row for row in plan["transitions"]}
    terminals = set(plan["terminal_states"])
    state = plan["initial_state"]
    evaluations = []
    for position, event in enumerate(plan["events"]):
        flags = []
        before = state
        transition = transitions.get(event["transition_id"])
        if event["declared_before_state"] != before:
            flags.append("declared_before_state_mismatch")
        if event["result"] == "accepted":
            if transition is None:
                flags.append("accepted_unknown_transition")
            else:
                if transition["from_state"] != before:
                    flags.append("accepted_from_state_mismatch")
                if before in terminals:
                    flags.append("accepted_from_terminal_state")
                if event["guard_outcome"] != "satisfied":
                    flags.append("accepted_guard_not_declared_satisfied")
                state = transition["to_state"]
        if event["declared_after_state"] != state:
            flags.append("declared_after_state_mismatch")
        evaluations.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "expected_before_state": before,
                "expected_after_state": state,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": evaluations,
        "final_expected_state": state,
        "flags": {
            "workflow_source_authenticated": False,
            "event_order_proven": False,
            "guard_truth_proven": False,
            "deployed_transition_proven": False,
            "exploit_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "States, transitions, guards, event order, and outcomes are caller-supplied.",
            "A transition anomaly is a review signal, not proof of a deployed workflow defect.",
            "An accepted record updates only this local projection, even when inconsistent.",
            "No workflow, account, credential, service, or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "WSR-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class WorkflowStateReplay:
    """Replay-checked local projection of supplied workflow events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise WorkflowStateReplayError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise WorkflowStateReplayError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_workflow_states(model: Any) -> WorkflowStateReplay:
    """Derive only a supplied state-machine timeline."""
    return WorkflowStateReplay(_derive(model))


def verify_supplied_workflow_states(report: Any, *, model: Any) -> WorkflowStateReplay:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not WorkflowStateReplay:
        raise WorkflowStateReplayError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise WorkflowStateReplayError("Report differs from supplied model replay")
    return WorkflowStateReplay(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "WorkflowStateReplay",
    "WorkflowStateReplayError",
    "analyze_supplied_workflow_states",
    "verify_supplied_workflow_states",
]
