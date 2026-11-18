"""Find unordered conflicts in a supplied event graph without running code."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_happens_before_conflicts"
PROFILE_ID = "AOE-GE-D21-S11"
CAPABILITY_ID = "army.ge.d21.s11"
VECTOR_ID = "AV-GE-D21-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S11"
WAVE_ID = "IW2-023"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3b4d0ce310738f1208a741dec330b8470bcd3aa0f911fd248ea3d3a6c3124fae"
DOMAIN = "sunderkey.offline-happens-before-conflicts.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_EVENTS = 24
MAX_EDGES = 128
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class HappensBeforeConflictsError(ValueError):
    """The supplied event graph or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, dict], dict[str, set[str]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "trace_complete", "events", "ordering_edges"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HappensBeforeConflictsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["trace_complete"], "trace completeness")
    events = {}
    for item in core.bounded_list(model["events"], MAX_EVENTS, "events"):
        row = core.exact(
            item, {"event_id", "actor_id", "resource_id", "access"}, "event"
        )
        event_id = core.identifier(row["event_id"], "event ID")
        if event_id in events:
            raise HappensBeforeConflictsError("Duplicate event ID")
        core.identifier(row["actor_id"], "actor ID")
        core.identifier(row["resource_id"], "resource ID")
        core.choice(row["access"], {"read", "write"}, "access")
        events[event_id] = row
    if not events:
        raise HappensBeforeConflictsError("At least one event is required")
    edges = {event_id: set() for event_id in events}
    seen = set()
    for item in core.bounded_list(model["ordering_edges"], MAX_EDGES, "edges"):
        row = core.exact(item, {"before_event_id", "after_event_id"}, "edge")
        before = core.identifier(row["before_event_id"], "before event")
        after = core.identifier(row["after_event_id"], "after event")
        if before not in events or after not in events:
            raise HappensBeforeConflictsError("Ordering edge references missing event")
        if before == after or (before, after) in seen:
            raise HappensBeforeConflictsError("Self or duplicate ordering edge")
        seen.add((before, after))
        edges[before].add(after)
    return model, events, edges, core.canonical(model)


def _closure(edges: dict[str, set[str]]) -> dict[str, set[str]]:
    state: dict[str, int] = {}
    reachable: dict[str, set[str]] = {}

    def visit(event_id: str) -> set[str]:
        if state.get(event_id) == 1:
            raise HappensBeforeConflictsError("Ordering graph has a cycle")
        if state.get(event_id) == 2:
            return reachable[event_id]
        state[event_id] = 1
        result = set()
        for successor in sorted(edges[event_id]):
            result.add(successor)
            result.update(visit(successor))
        state[event_id] = 2
        reachable[event_id] = result
        return result

    for event_id in sorted(edges):
        visit(event_id)
    return reachable


def _derive(value: Any) -> dict:
    model, events, edges, source_text = _model(value)
    reachable = _closure(edges)
    ids = sorted(events)
    conflicts = []
    for left_index, left_id in enumerate(ids):
        left = events[left_id]
        for right_id in ids[left_index + 1:]:
            right = events[right_id]
            if (
                left["resource_id"] == right["resource_id"]
                and left["actor_id"] != right["actor_id"]
                and (left["access"] == "write" or right["access"] == "write")
                and right_id not in reachable[left_id]
                and left_id not in reachable[right_id]
            ):
                conflicts.append({
                    "left_event_id": left_id,
                    "right_event_id": right_id,
                    "resource_id": left["resource_id"],
                })
    uncertainty = []
    if not model["trace_complete"]:
        uncertainty.append("supplied_trace_incomplete")
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
        "trace_complete_asserted": model["trace_complete"],
        "supplied_event_count": len(events),
        "supplied_ordering_edge_count": sum(len(items) for items in edges.values()),
        "unordered_conflicting_pairs": conflicts,
        "unordered_conflicting_pair_count": len(conflicts),
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_unordered_conflict_projection",
        "source_authenticated": False,
        "execution_trace_verified": False,
        "memory_aliasing_verified": False,
        "race_verified": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Events, actors, resources, access modes and ordering are supplied assertions.",
            "An unordered conflict is not proof of concurrent execution or a data race.",
            "Aliasing, synchronization and execution traces are not verified.",
            "No process, target, vulnerability test or finding is involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HBC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class HappensBeforeConflictsReport:
    """Unsigned event-order projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HappensBeforeConflictsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HappensBeforeConflictsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_happens_before(model: Any) -> HappensBeforeConflictsReport:
    return HappensBeforeConflictsReport._owned(_derive(model))


def verify_supplied_happens_before(
    report: Any, *, model: Any
) -> HappensBeforeConflictsReport:
    if type(report) is not HappensBeforeConflictsReport:
        raise HappensBeforeConflictsError("Exact event-order wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HappensBeforeConflictsError("Report differs from separate original model")
    return HappensBeforeConflictsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-event-graph",
        "trace_complete": True,
        "events": [
            {"event_id": "a_write", "actor_id": "a", "resource_id": "x", "access": "write"},
            {"event_id": "a_read", "actor_id": "a", "resource_id": "x", "access": "read"},
            {"event_id": "b_write", "actor_id": "b", "resource_id": "x", "access": "write"},
            {"event_id": "b_read", "actor_id": "b", "resource_id": "y", "access": "read"},
        ],
        "ordering_edges": [
            {"before_event_id": "a_write", "after_event_id": "a_read"},
            {"before_event_id": "a_read", "after_event_id": "b_read"},
        ],
    }
