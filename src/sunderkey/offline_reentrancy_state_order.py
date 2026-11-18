"""Project supplied callback traces against state-update order."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "evm_supplied_callback_state_order"
PROFILE_ID = "AOE-GB-D10-S08"
CAPABILITY_ID = "army.gb.d10.s08"
VECTOR_ID = "AV-GB-D10-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:fd9485a7464278a5cfb9617a4327bc5f848651f1ed82618a3177061b609d9ad3"
DOMAIN = "sunderkey.offline-reentrancy-state-order.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
KINDS = {"state_read", "state_write", "external_call", "callback_enter"}
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class ReentrancyStateOrderError(ValueError):
    """A supplied callback-state trace or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "traces"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ReentrancyStateOrderError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    traces = core.bounded_list(model["traces"], 32, "traces")
    if not traces:
        raise ReentrancyStateOrderError("At least one trace is required")
    trace_ids: set[str] = set()
    for item in traces:
        trace = core.exact(item, {"trace_id", "resource_id", "context_complete", "events"}, "trace")
        trace_id = core.identifier(trace["trace_id"], "trace ID")
        if trace_id in trace_ids:
            raise ReentrancyStateOrderError("Duplicate trace ID")
        trace_ids.add(trace_id)
        resource_id = core.identifier(trace["resource_id"], "resource ID")
        core.boolean(trace["context_complete"], "context completeness")
        events = core.bounded_list(trace["events"], 128, "events")
        if not events:
            raise ReentrancyStateOrderError("Trace events must not be empty")
        event_ids: set[str] = set()
        for item_event in events:
            event = core.exact(item_event, {"event_id", "kind", "resource_id"}, "event")
            event_id = core.identifier(event["event_id"], "event ID")
            if event_id in event_ids:
                raise ReentrancyStateOrderError("Duplicate event ID within trace")
            event_ids.add(event_id)
            core.choice(event["kind"], KINDS, "event kind")
            if event["resource_id"] != resource_id:
                raise ReentrancyStateOrderError("Event resource must match trace resource")
    return model, core.canonical(model)


def _trace_disposition(trace: dict) -> tuple[str, dict]:
    kinds = [event["kind"] for event in trace["events"]]
    if not trace["context_complete"]:
        return "unknown", {}
    reads = [index for index, kind in enumerate(kinds) if kind == "state_read"]
    if not reads:
        return "unknown_no_state_read", {}
    saw_following_write = False
    saw_call_without_callback = False
    for read_index in reads:
        writes = [
            index
            for index, kind in enumerate(kinds)
            if kind == "state_write" and index > read_index
        ]
        if not writes:
            continue
        saw_following_write = True
        write_index = writes[0]
        calls = [
            index
            for index, kind in enumerate(kinds)
            if kind == "external_call" and read_index < index < write_index
        ]
        for call_index in calls:
            callbacks = [
                index
                for index, kind in enumerate(kinds)
                if kind == "callback_enter" and call_index < index < write_index
            ]
            if callbacks:
                return "candidate_declared_callback_before_state_write", {
                    "read_event_id": trace["events"][read_index]["event_id"],
                    "external_call_event_id": trace["events"][call_index]["event_id"],
                    "callback_event_id": trace["events"][callbacks[0]]["event_id"],
                    "write_event_id": trace["events"][write_index]["event_id"],
                }
        saw_call_without_callback |= bool(calls)
    if saw_call_without_callback:
        return "declared_external_call_before_write_without_callback", {}
    if not saw_following_write:
        return "unknown_no_state_write", {}
    return "no_declared_callback_before_state_write", {}


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for trace in model["traces"]:
        disposition, witness = _trace_disposition(trace)
        projections.append(
            {
                "trace_id": trace["trace_id"],
                "resource_id": trace["resource_id"],
                "disposition": disposition,
                "witness_event_ids": witness,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "trace_count": len(model["traces"]),
        "trace_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in projections),
        "source_authenticated": False,
        "contract_executed": False,
        "reentrant_effect_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Event order, resource identity and trace completeness are caller-supplied.",
            "A callback between an external call and a later write is only a state-order signal.",
            "Locks, rollback, invariants and actual callback behavior are not evaluated.",
            "No EVM transaction is sent, contract executed or exploitable effect asserted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RSO-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ReentrancyStateOrderReport:
    """Unsigned event-order projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ReentrancyStateOrderError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ReentrancyStateOrderReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_reentrancy_state_order(model: Any) -> ReentrancyStateOrderReport:
    return ReentrancyStateOrderReport._owned(_derive(model))


def verify_supplied_reentrancy_state_order(
    report: Any, *, model: Any
) -> ReentrancyStateOrderReport:
    if type(report) is not ReentrancyStateOrderReport:
        raise ReentrancyStateOrderError("Exact state-order wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ReentrancyStateOrderError("Report differs from separate original model")
    return ReentrancyStateOrderReport._owned(expected)


def verify_supplied_reentrancy_state_order_bytes(
    report_bytes: bytes, *, model: Any
) -> ReentrancyStateOrderReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ReentrancyStateOrderError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ReentrancyStateOrderError("Exported report differs from original replay")
    return ReentrancyStateOrderReport._owned(expected)


def component_fixture() -> dict:
    def events(*kinds: str) -> list[dict]:
        return [
            {"event_id": f"step-{index}", "kind": kind, "resource_id": "balance"}
            for index, kind in enumerate(kinds)
        ]

    return {
        "schema_version": 1,
        "source_id": "synthetic-callback-traces",
        "traces": [
            {
                "trace_id": "callback-before-write",
                "resource_id": "balance",
                "context_complete": True,
                "events": events("state_read", "external_call", "callback_enter", "state_write"),
            },
            {
                "trace_id": "write-before-call",
                "resource_id": "balance",
                "context_complete": True,
                "events": events("state_read", "state_write", "external_call", "callback_enter"),
            },
        ],
    }
