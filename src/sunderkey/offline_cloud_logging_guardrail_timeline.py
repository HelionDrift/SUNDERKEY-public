"""Locate supplied unalerted logging-disable events under a guardrail rule."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cloud_supplied_unalerted_logging_disable"
PROFILE_ID = "AOE-GC-D14-S14"
CAPABILITY_ID = "army.gc.d14.s14"
VECTOR_ID = "AV-GC-D14-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S14"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9133205d93b15ecfd53f2864bd64e7ebb4457c6830e81a7776cc2ba879fb33a0"
DOMAIN = "sunderkey.offline-cloud-logging-guardrail-timeline.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ACTIONS = {"enable", "disable"}
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


class CloudLoggingGuardrailError(ValueError):
    """A supplied logging control timeline or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "controls"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CloudLoggingGuardrailError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    controls = core.bounded_list(model["controls"], 16, "controls")
    if not controls:
        raise CloudLoggingGuardrailError("At least one control is required")
    seen_controls: set[str] = set()
    for item in controls:
        row = core.exact(
            item,
            {"control_id", "resource_id", "alert_required", "context_complete", "events"},
            "control",
        )
        control_id = core.identifier(row["control_id"], "control ID")
        if control_id in seen_controls:
            raise CloudLoggingGuardrailError("Duplicate control ID")
        seen_controls.add(control_id)
        core.identifier(row["resource_id"], "resource ID")
        core.boolean(row["alert_required"], "alert requirement")
        core.boolean(row["context_complete"], "context completeness")
        events = core.bounded_list(row["events"], 32, "events")
        if not events:
            raise CloudLoggingGuardrailError("At least one event is required")
        seen_events: set[str] = set()
        seen_positions: set[int] = set()
        for item_event in events:
            event = core.exact(
                item_event,
                {"event_id", "position", "action", "alert_recorded"},
                "event",
            )
            event_id = core.identifier(event["event_id"], "event ID")
            if event_id in seen_events:
                raise CloudLoggingGuardrailError("Duplicate event ID")
            seen_events.add(event_id)
            position = event["position"]
            if type(position) is not int or not 0 <= position <= 1_000_000:
                raise CloudLoggingGuardrailError("Event position must be a bounded integer")
            if position in seen_positions:
                raise CloudLoggingGuardrailError("Duplicate event position")
            seen_positions.add(position)
            core.choice(event["action"], ACTIONS, "logging action")
            core.boolean(event["alert_recorded"], "alert record")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["controls"]:
        unalerted = sorted(
            event["event_id"]
            for event in row["events"]
            if event["action"] == "disable" and not event["alert_recorded"]
        )
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_unalerted_logging_disable"
            if row["alert_required"] and unalerted
            else "no_declared_unalerted_logging_disable"
        )
        projections.append(
            {
                "control_id": row["control_id"],
                "resource_id": row["resource_id"],
                "event_count": len(row["events"]),
                "unalerted_disable_event_ids": unalerted,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "control_count": len(model["controls"]),
        "control_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "provider_queried": False,
        "alert_delivery_verified": False,
        "logging_effect_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Events, alert observations and guardrail requirements are caller-supplied.",
            "No provider control, logging sink, alert transport or delivery is inspected.",
            "An unalerted label does not prove monitoring impairment or malicious action.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CLG-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class CloudLoggingGuardrailReport:
    """Unsigned event projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CloudLoggingGuardrailError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CloudLoggingGuardrailReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cloud_logging(model: Any) -> CloudLoggingGuardrailReport:
    return CloudLoggingGuardrailReport._owned(_derive(model))


def verify_supplied_cloud_logging(report: Any, *, model: Any) -> CloudLoggingGuardrailReport:
    if type(report) is not CloudLoggingGuardrailReport:
        raise CloudLoggingGuardrailError("Exact logging-guardrail wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CloudLoggingGuardrailError("Report differs from separate original model")
    return CloudLoggingGuardrailReport._owned(expected)


def verify_supplied_cloud_logging_bytes(
    report_bytes: bytes, *, model: Any
) -> CloudLoggingGuardrailReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise CloudLoggingGuardrailError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise CloudLoggingGuardrailError("Exported report differs from original replay")
    return CloudLoggingGuardrailReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-cloud-logging",
        "controls": [
            {
                "control_id": "control-one",
                "resource_id": "project-one",
                "alert_required": True,
                "context_complete": True,
                "events": [
                    {
                        "event_id": "event-one",
                        "position": 1,
                        "action": "disable",
                        "alert_recorded": False,
                    },
                    {
                        "event_id": "event-two",
                        "position": 2,
                        "action": "enable",
                        "alert_recorded": True,
                    },
                ],
            }
        ],
    }
