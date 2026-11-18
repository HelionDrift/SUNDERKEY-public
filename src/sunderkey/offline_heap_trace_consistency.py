"""Check a supplied heap-operation trace without allocating target memory."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_heap_trace_consistency"
PROFILE_ID = "AOE-GE-D21-S09"
CAPABILITY_ID = "army.ge.d21.s09"
VECTOR_ID = "AV-GE-D21-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S09"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7c05b0d23c0c49524093d0c0f11fd838df829be989ee058edf8bd0e0ffde1dce"
DOMAIN = "sunderkey.offline-heap-trace-consistency.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_EVENTS = 64
MAX_ADDRESS = 1_000_000_000
MAX_SIZE = 4096
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class HeapTraceConsistencyError(ValueError):
    """The supplied heap trace or original-model replay is invalid."""


def _integer(value: Any, label: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise HeapTraceConsistencyError(f"{label} is outside the supported bound")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "trace_complete", "events"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HeapTraceConsistencyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["trace_complete"], "trace completeness")
    events = core.bounded_list(model["events"], MAX_EVENTS, "events")
    if not events:
        raise HeapTraceConsistencyError("At least one event is required")
    seen_events = set()
    seen_allocations = set()
    for item in events:
        if type(item) is not dict or "kind" not in item:
            raise HeapTraceConsistencyError("Event kind is required")
        kind = core.choice(item["kind"], {"allocate", "free", "access"}, "kind")
        fields = {
            "allocate": {"event_id", "kind", "allocation_id", "base_address", "size"},
            "free": {"event_id", "kind", "allocation_id"},
            "access": {"event_id", "kind", "allocation_id", "offset", "length", "mode"},
        }[kind]
        row = core.exact(item, fields, "event")
        event_id = core.identifier(row["event_id"], "event ID")
        allocation_id = core.identifier(row["allocation_id"], "allocation ID")
        if event_id in seen_events:
            raise HeapTraceConsistencyError("Duplicate event ID")
        seen_events.add(event_id)
        if kind == "allocate":
            if allocation_id in seen_allocations:
                raise HeapTraceConsistencyError("Allocation ID reuse is unsupported")
            seen_allocations.add(allocation_id)
            _integer(row["base_address"], "base address", 0, MAX_ADDRESS)
            _integer(row["size"], "allocation size", 1, MAX_SIZE)
        elif kind == "access":
            _integer(row["offset"], "access offset", -MAX_SIZE, MAX_SIZE)
            _integer(row["length"], "access length", 1, MAX_SIZE)
            core.choice(row["mode"], {"read", "write"}, "access mode")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    active: dict[str, tuple[int, int]] = {}
    ever_allocated: set[str] = set()
    anomalies = []

    def record(event_id: str, allocation_id: str, code: str, related: str | None = None) -> None:
        anomalies.append({
            "event_id": event_id,
            "allocation_id": allocation_id,
            "code": code,
            "related_allocation_id": related,
        })

    for row in model["events"]:
        event_id, allocation_id, kind = row["event_id"], row["allocation_id"], row["kind"]
        if kind == "allocate":
            base, size = row["base_address"], row["size"]
            for other_id, (other_base, other_size) in sorted(active.items()):
                if base < other_base + other_size and other_base < base + size:
                    record(event_id, allocation_id, "overlapping_live_ranges", other_id)
            active[allocation_id] = (base, size)
            ever_allocated.add(allocation_id)
        elif kind == "free":
            if allocation_id in active:
                del active[allocation_id]
            elif allocation_id in ever_allocated:
                record(event_id, allocation_id, "duplicate_free")
            else:
                record(event_id, allocation_id, "unknown_free")
        elif allocation_id not in active:
            record(
                event_id, allocation_id,
                "access_after_free" if allocation_id in ever_allocated else "unknown_access",
            )
        else:
            _, size = active[allocation_id]
            if row["offset"] < 0 or row["offset"] + row["length"] > size:
                record(event_id, allocation_id, "out_of_declared_bounds")
    uncertainty = []
    if not model["trace_complete"]:
        uncertainty.append("supplied_heap_trace_incomplete")
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
        "supplied_event_count": len(model["events"]),
        "active_allocation_ids_at_end": sorted(active),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_heap_trace_projection",
        "source_authenticated": False,
        "allocator_semantics_verified": False,
        "heap_state_observed": False,
        "memory_access_verified": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Heap events, addresses and allocation IDs are supplied assertions.",
            "Overlap and access anomalies are model inconsistencies, not proven memory flaws.",
            "Allocator reuse, aliasing, concurrency and platform semantics are not modeled.",
            "No binary, process, target, exploit or finding is involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HTC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class HeapTraceConsistencyReport:
    """Unsigned heap-trace projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HeapTraceConsistencyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HeapTraceConsistencyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_heap_trace(model: Any) -> HeapTraceConsistencyReport:
    return HeapTraceConsistencyReport._owned(_derive(model))


def verify_supplied_heap_trace(
    report: Any, *, model: Any
) -> HeapTraceConsistencyReport:
    if type(report) is not HeapTraceConsistencyReport:
        raise HeapTraceConsistencyError("Exact heap-trace wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HeapTraceConsistencyError("Report differs from separate original model")
    return HeapTraceConsistencyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-heap-trace",
        "trace_complete": True,
        "events": [
            {"event_id": "alloc_a", "kind": "allocate", "allocation_id": "a",
             "base_address": 100, "size": 16},
            {"event_id": "alloc_b", "kind": "allocate", "allocation_id": "b",
             "base_address": 108, "size": 16},
            {"event_id": "access_a", "kind": "access", "allocation_id": "a",
             "offset": 15, "length": 2, "mode": "read"},
            {"event_id": "free_a", "kind": "free", "allocation_id": "a"},
            {"event_id": "access_freed_a", "kind": "access", "allocation_id": "a",
             "offset": 0, "length": 1, "mode": "write"},
            {"event_id": "free_again_a", "kind": "free", "allocation_id": "a"},
        ],
    }
