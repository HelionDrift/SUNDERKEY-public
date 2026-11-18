"""Project supplied agent-output handling declarations without interpreting output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "agent_supplied_output_handling_boundary"
PROFILE_ID = "AOE-GD-D20-S13"
CAPABILITY_ID = "army.gd.d20.s13"
VECTOR_ID = "AV-GD-D20-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S13"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:40d53e49797b798220e6a2b8fd642b42208cc8d14eb11e2e997eef799d257582"
DOMAIN = "sunderkey.offline-agent-output-handling.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_ITEMS = 64
SENSITIVE_SINKS = frozenset(("markup", "query", "command", "privileged_tool"))
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AgentOutputHandlingError(ValueError):
    """A supplied output-handling model or replay is invalid."""


def _rows(value: Any, *, label: str, maximum: int = MAX_ITEMS) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    if not rows:
        raise AgentOutputHandlingError(f"{label} must not be empty")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    owned = json.loads(core.canonical(value))
    model = core.exact(
        owned, {"schema_version", "source_id", "outputs", "sinks", "flows"}, "model"
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AgentOutputHandlingError("Unsupported model version")
    core.identifier(model["source_id"], "model source ID")
    outputs: set[str] = set()
    for item in _rows(model["outputs"], label="outputs"):
        row = core.exact(item, {"output_id", "origin", "trust"}, "output")
        output_id = core.identifier(row["output_id"], "output ID")
        if output_id in outputs:
            raise AgentOutputHandlingError("Duplicate output ID")
        outputs.add(output_id)
        core.choice(row["origin"], {"model", "retrieval", "operator", "unknown"}, "origin")
        core.choice(row["trust"], {"trusted", "untrusted", "unknown"}, "trust")
    sinks: set[str] = set()
    for item in _rows(model["sinks"], label="sinks"):
        row = core.exact(item, {"sink_id", "kind"}, "sink")
        sink_id = core.identifier(row["sink_id"], "sink ID")
        if sink_id in sinks:
            raise AgentOutputHandlingError("Duplicate sink ID")
        sinks.add(sink_id)
        core.choice(row["kind"], SENSITIVE_SINKS | {"display"}, "sink kind")
    flows: set[str] = set()
    for item in _rows(model["flows"], label="flows", maximum=128):
        row = core.exact(
            item,
            {
                "flow_id", "output_id", "sink_id", "handling", "delivery",
                "context_complete",
            },
            "flow",
        )
        flow_id = core.identifier(row["flow_id"], "flow ID")
        if flow_id in flows:
            raise AgentOutputHandlingError("Duplicate flow ID")
        flows.add(flow_id)
        output_id = core.identifier(row["output_id"], "flow output ID")
        sink_id = core.identifier(row["sink_id"], "flow sink ID")
        if output_id not in outputs or sink_id not in sinks:
            raise AgentOutputHandlingError("Flow references an absent output or sink")
        core.choice(
            row["handling"],
            {"raw", "context_encoded", "schema_validated", "unknown"},
            "handling",
        )
        core.choice(row["delivery"], {"accepted", "rejected", "unknown"}, "delivery")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _disposition(output: dict, sink: dict, flow: dict) -> str:
    if not flow["context_complete"] or "unknown" in (
        output["origin"], output["trust"], flow["handling"], flow["delivery"]
    ):
        return "unknown"
    if flow["delivery"] == "rejected":
        return "declared_rejected"
    if sink["kind"] == "display":
        return "declared_display_only"
    if flow["handling"] != "raw":
        return "declared_handled_unverified"
    if output["trust"] == "trusted":
        return "declared_trusted_source_unverified"
    return "candidate_declared_unhandled_output"


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    outputs = {item["output_id"]: item for item in model["outputs"]}
    sinks = {item["sink_id"]: item for item in model["sinks"]}
    projections = []
    for flow in model["flows"]:
        output = outputs[flow["output_id"]]
        sink = sinks[flow["sink_id"]]
        projections.append({
            "flow_id": flow["flow_id"],
            "output_id": flow["output_id"],
            "sink_id": flow["sink_id"],
            "sink_kind": sink["kind"],
            "disposition": _disposition(output, sink, flow),
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "flow_projections": projections,
        "candidate_count": sum(
            item["disposition"] == "candidate_declared_unhandled_output"
            for item in projections
        ),
        "unknown_count": sum(item["disposition"] == "unknown" for item in projections),
        "source_authenticated": False,
        "output_content_interpreted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Trust, handling, delivery and sink labels are caller declarations.",
            "No output content, prompt, command, query or target response is processed.",
            "A candidate is a declaration conflict, not an observed exploit or finding.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="AOH-")
    document = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(document, maximum=MAX_REPORT_BYTES)
    return document


@dataclass(frozen=True, slots=True, init=False)
class AgentOutputHandlingReport:
    """Unsigned projection that requires separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AgentOutputHandlingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AgentOutputHandlingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_agent_output_handling(model: Any) -> AgentOutputHandlingReport:
    """Analyze only bounded, caller-supplied labels with no runtime effects."""
    return AgentOutputHandlingReport._owned(_derive(model))


def verify_supplied_agent_output_handling(
    report: Any, *, model: Any
) -> AgentOutputHandlingReport:
    """Require an independently retained model; embedded report content is insufficient."""
    if type(report) is not AgentOutputHandlingReport:
        raise AgentOutputHandlingError("Exact output-handling wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AgentOutputHandlingError("Report differs from separate original model")
    return AgentOutputHandlingReport._owned(expected)


def verify_supplied_agent_output_handling_bytes(
    report_bytes: bytes, *, model: Any
) -> AgentOutputHandlingReport:
    """Verify bounded exported JSON without trusting its embedded source copy."""
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AgentOutputHandlingError("Report must be a native object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AgentOutputHandlingError("Exported report differs from original replay")
    return AgentOutputHandlingReport._owned(expected)


def component_fixture() -> dict:
    """Return a synthetic metadata-only case for the checked dispatcher envelope."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-output-flow",
        "outputs": [
            {"output_id": "retrieval-one", "origin": "retrieval", "trust": "untrusted"},
            {"output_id": "model-two", "origin": "model", "trust": "unknown"},
        ],
        "sinks": [
            {"sink_id": "query-one", "kind": "query"},
            {"sink_id": "display-one", "kind": "display"},
        ],
        "flows": [
            {
                "flow_id": "raw-query", "output_id": "retrieval-one",
                "sink_id": "query-one", "handling": "raw",
                "delivery": "accepted", "context_complete": True,
            },
            {
                "flow_id": "display-only", "output_id": "retrieval-one",
                "sink_id": "display-one", "handling": "raw",
                "delivery": "accepted", "context_complete": True,
            },
            {
                "flow_id": "uncertain-query", "output_id": "model-two",
                "sink_id": "query-one", "handling": "raw",
                "delivery": "accepted", "context_complete": True,
            },
        ],
    }
