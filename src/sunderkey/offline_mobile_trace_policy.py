"""Compare synthetic mobile trace transitions with supplied test policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

_SPECS = {
    "android_instrumentation": (
        "AOE-GB-D08-S02", "IW2-006",
        "sha256:fe2f7871be528a129b11374078e074732106c2bc3f7d7f5ba0cbfaf86fd7cd9d",
        "mobile_supplied_android_instrumentation_trace_projection",
    ),
    "android_device_trust": (
        "AOE-GB-D08-S04", "IW2-008",
        "sha256:df8e34bbd1a9aa65dd133fff7c8bfc9cf01756ba793b53b10d00f57d6f916008",
        "mobile_supplied_android_device_trust_trace_projection",
    ),
    "ios_instrumentation": (
        "AOE-GB-D08-S06", "IW2-010",
        "sha256:8f34a851aa7f1ccca9eb76d119646146ba31f2e70e039c7b29b4f757362c4c46",
        "mobile_supplied_ios_instrumentation_trace_projection",
    ),
    "ios_device_trust": (
        "AOE-GB-D08-S08", "IW2-012",
        "sha256:64cb25977e72fe9297637e2501d19d7529ea7ba73dd39da6f9dc6eaf56369161",
        "mobile_supplied_ios_device_trust_trace_projection",
    ),
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MobileTracePolicyError(ValueError):
    """A supplied mobile trace or original-model replay is invalid."""


def _transitions(value: Any, *, label: str) -> set[tuple[str, str]]:
    transitions = set()
    for item in core.bounded_list(value, 32, label):
        row = core.exact(item, {"from_state", "to_state"}, label)
        pair = (
            core.identifier(row["from_state"], "from state"),
            core.identifier(row["to_state"], "to state"),
        )
        if pair in transitions:
            raise MobileTracePolicyError(f"Duplicate {label} transition")
        transitions.add(pair)
    return transitions


def _derive(value: Any, *, trace_kind: str) -> dict:
    if trace_kind not in _SPECS:
        raise MobileTracePolicyError("Unknown closed trace kind")
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "trace_complete",
        "trace_kind", "allowed_transitions", "trace_events",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MobileTracePolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MobileTracePolicyError("Only synthetic fixtures are accepted")
    if model["trace_kind"] != trace_kind:
        raise MobileTracePolicyError("Model trace kind differs from specialist")
    complete = core.boolean(model["trace_complete"], "trace completeness")
    allowed = _transitions(model["allowed_transitions"], label="allowed transitions")
    events = core.bounded_list(model["trace_events"], 64, "trace events")
    if not events:
        raise MobileTracePolicyError("At least one trace event is required")
    rows = []
    seen = set()
    for item in events:
        row = core.exact(item, {
            "event_ref", "sequence", "from_state", "to_state",
        }, "trace event")
        event_ref = core.identifier(row["event_ref"], "opaque event reference")
        sequence = row["sequence"]
        if type(sequence) is not int or not 0 <= sequence <= 100_000:
            raise MobileTracePolicyError("Sequence must be a bounded nonnegative integer")
        if event_ref in seen:
            raise MobileTracePolicyError("Duplicate event reference")
        seen.add(event_ref)
        pair = (
            core.identifier(row["from_state"], "from state"),
            core.identifier(row["to_state"], "to state"),
        )
        rows.append({
            "event_ref": event_ref,
            "sequence": sequence,
            "from_state": pair[0],
            "to_state": pair[1],
            "outside_supplied_transition_policy": pair not in allowed,
        })
    rows.sort(key=lambda row: (row["sequence"], row["event_ref"]))
    discontinuities = [
        row["event_ref"] for earlier, row in zip(rows, rows[1:])
        if row["sequence"] <= earlier["sequence"]
        or row["from_state"] != earlier["to_state"]
    ]
    deviations = [row["event_ref"] for row in rows if row["outside_supplied_transition_policy"]]
    unknown = [] if complete else ["supplied_mobile_trace_incomplete"]
    if discontinuities:
        unknown.append("supplied_mobile_trace_discontinuous")
    profile_id, wave_id, blueprint_sha256, component_id = _SPECS[trace_kind]
    segment = profile_id.rsplit("-", 1)[-1].lower()
    body = {
        "schema_version": 1,
        "component_id": component_id,
        "profile_id": profile_id,
        "capability_id": f"army.gb.d08.{segment}",
        "vector_id": f"AV-GB-D08-{profile_id.rsplit('-', 1)[-1]}-01",
        "work_package_id": f"IWP2-{profile_id}",
        "wave_id": wave_id,
        "commander_id": "AOE-GB-D08-CMD",
        "group_owner_id": "AOE-HQ-04",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": blueprint_sha256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "trace_complete_asserted": complete,
        "trace_kind": trace_kind,
        "trace_event_projections": rows,
        "outside_supplied_policy_event_refs": deviations,
        "discontinuous_event_refs": discontinuities,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_mobile_trace_projection",
        "source_authenticated": False,
        "device_connected": False,
        "instrumentation_run": False,
        "device_trust_changed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Trace states, event order, policy, and completeness are synthetic assertions.",
            "The model accepts no hook, exploit, payload, device command, or trace bytes.",
            "It does not establish actual instrumentation or a trust-state transition.",
            "No mobile device, app, process, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(
        body, domain=f"sunderkey.offline-mobile-trace.{trace_kind}.v1", prefix="MTP-"
    )
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MobileTracePolicyReport:
    """Unsigned trace projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MobileTracePolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MobileTracePolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mobile_trace(
    model: Any, *, trace_kind: str
) -> MobileTracePolicyReport:
    return MobileTracePolicyReport._owned(_derive(model, trace_kind=trace_kind))


def verify_supplied_mobile_trace(
    report: Any, *, model: Any, trace_kind: str
) -> MobileTracePolicyReport:
    if type(report) is not MobileTracePolicyReport:
        raise MobileTracePolicyError("Exact mobile trace wrapper required")
    expected = _derive(model, trace_kind=trace_kind)
    if report.to_json() != core.canonical(expected):
        raise MobileTracePolicyError("Report differs from separate original model")
    return MobileTracePolicyReport._owned(expected)


def component_fixture(trace_kind: str) -> dict:
    if trace_kind not in _SPECS:
        raise MobileTracePolicyError("Unknown closed trace kind")
    return {
        "schema_version": 1,
        "source_id": f"synthetic-{trace_kind}-trace",
        "synthetic_fixture": True,
        "trace_complete": True,
        "trace_kind": trace_kind,
        "allowed_transitions": [{"from_state": "baseline", "to_state": "test_observation"}],
        "trace_events": [{
            "event_ref": "event-opaque-a", "sequence": 1,
            "from_state": "baseline", "to_state": "unsupported_state",
        }],
    }


def analyze_supplied_android_instrumentation(model: Any) -> MobileTracePolicyReport:
    return analyze_supplied_mobile_trace(model, trace_kind="android_instrumentation")


def analyze_supplied_android_device_trust(model: Any) -> MobileTracePolicyReport:
    return analyze_supplied_mobile_trace(model, trace_kind="android_device_trust")


def analyze_supplied_ios_instrumentation(model: Any) -> MobileTracePolicyReport:
    return analyze_supplied_mobile_trace(model, trace_kind="ios_instrumentation")


def analyze_supplied_ios_device_trust(model: Any) -> MobileTracePolicyReport:
    return analyze_supplied_mobile_trace(model, trace_kind="ios_device_trust")
