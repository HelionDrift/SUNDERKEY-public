"""Compare two caller-supplied parser traces for inert protocol-fuzz triage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_protocol_trace_differential"
PROFILE_ID = "AOE-GC-D13-S17"
CAPABILITY_ID = "army.gc.d13.s17"
VECTOR_ID = "AV-GC-D13-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S17"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:02f99df28e4286fd2cb9ce20b6e0fe02e596380b9b7736a0adfe62694dda0a19"
DOMAIN = "sunderkey.offline-protocol-trace-differential.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_CASES = 64
MAX_STAGES = 16
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OUTCOMES = {"accepted", "rejected", "incomplete", "error_signal"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class ProtocolTraceDifferentialError(ValueError):
    """The supplied trace model or its original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, tuple[str, str], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "case_inventory_complete",
            "implementation_ids", "cases",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ProtocolTraceDifferentialError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["case_inventory_complete"], "case inventory completeness")
    ids = core.bounded_list(model["implementation_ids"], 2, "implementation IDs")
    if len(ids) != 2 or any(core.identifier(item, "implementation ID") != item for item in ids):
        raise ProtocolTraceDifferentialError("Exactly two implementation IDs are required")
    if ids[0] == ids[1]:
        raise ProtocolTraceDifferentialError("Implementation IDs must differ")
    seen_cases: set[str] = set()
    seen_inputs: set[str] = set()
    cases = core.bounded_list(model["cases"], MAX_CASES, "cases")
    if not cases:
        raise ProtocolTraceDifferentialError("At least one case is required")
    for item in cases:
        case = core.exact(
            item, {"case_id", "input_sha256", "message_kind", "traces"}, "case"
        )
        case_id = core.identifier(case["case_id"], "case ID")
        message_kind = core.identifier(case["message_kind"], "message kind")
        if not message_kind:
            raise ProtocolTraceDifferentialError("Message kind is required")
        digest = case["input_sha256"]
        if type(digest) is not str or DIGEST.fullmatch(digest) is None:
            raise ProtocolTraceDifferentialError("Input digest must be SHA-256 text")
        if case_id in seen_cases or digest in seen_inputs:
            raise ProtocolTraceDifferentialError("Duplicate case ID or input digest")
        seen_cases.add(case_id)
        seen_inputs.add(digest)
        traces = core.exact(case["traces"], set(ids), "traces")
        for implementation_id in ids:
            trace = core.exact(traces[implementation_id], {"stages", "outcome"}, "trace")
            core.choice(trace["outcome"], OUTCOMES, "outcome")
            stages = core.bounded_list(trace["stages"], MAX_STAGES, "stages")
            for stage in stages:
                core.identifier(stage, "stage ID")
    return model, (ids[0], ids[1]), core.canonical(model)


def _derive(value: Any) -> dict:
    model, ids, source_text = _model(value)
    projections = []
    for case in sorted(model["cases"], key=lambda row: row["case_id"]):
        first, second = (case["traces"][identifier] for identifier in ids)
        first_stages = first["stages"]
        second_stages = second["stages"]
        common = 0
        while (
            common < min(len(first_stages), len(second_stages))
            and first_stages[common] == second_stages[common]
        ):
            common += 1
        stage_differs = first_stages != second_stages
        outcome_differs = first["outcome"] != second["outcome"]
        if stage_differs and outcome_differs:
            disposition = "stage_and_outcome_divergence"
        elif stage_differs:
            disposition = "stage_divergence"
        elif outcome_differs:
            disposition = "outcome_divergence"
        else:
            disposition = "same_supplied_trace"
        projections.append({
            "case_id": case["case_id"],
            "input_sha256": case["input_sha256"],
            "message_kind": case["message_kind"],
            "common_stage_prefix_count": common,
            "first_differing_stage_index": common if stage_differs else None,
            "outcomes": {ids[0]: first["outcome"], ids[1]: second["outcome"]},
            "disposition": disposition,
        })
    divergent = [
        row["case_id"] for row in projections
        if row["disposition"] != "same_supplied_trace"
    ]
    unknown = [] if model["case_inventory_complete"] else [
        "supplied_case_inventory_incomplete"
    ]
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
        "implementation_ids": list(ids),
        "case_inventory_complete_asserted": model["case_inventory_complete"],
        "supplied_case_count": len(projections),
        "case_projections": projections,
        "divergent_case_ids": divergent,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_trace_differential_projection",
        "source_authenticated": False,
        "input_bytes_read": False,
        "trace_origin_verified": False,
        "target_executed": False,
        "crash_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Implementation, stages, outcomes and completeness are supplied assertions.",
            "A differential is not evidence of a parser defect, crash or exploitable condition.",
            "No input bytes, instrumented process, network endpoint or target is inspected.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PTD-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ProtocolTraceDifferentialReport:
    """Unsigned differential projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ProtocolTraceDifferentialError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ProtocolTraceDifferentialReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_protocol_trace_differential(
    model: Any,
) -> ProtocolTraceDifferentialReport:
    try:
        return ProtocolTraceDifferentialReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise ProtocolTraceDifferentialError(str(exc)) from exc


def verify_supplied_protocol_trace_differential(
    report: Any, *, model: Any
) -> ProtocolTraceDifferentialReport:
    if type(report) is not ProtocolTraceDifferentialReport:
        raise ProtocolTraceDifferentialError("Exact differential wrapper required")
    try:
        expected = _derive(model)
    except core.FrameworkDeclarationError as exc:
        raise ProtocolTraceDifferentialError(str(exc)) from exc
    if report.to_json() != core.canonical(expected):
        raise ProtocolTraceDifferentialError("Report differs from separate original model")
    return ProtocolTraceDifferentialReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-protocol-traces",
        "case_inventory_complete": True,
        "implementation_ids": ["parser_a", "parser_b"],
        "cases": [
            {
                "case_id": "c1",
                "input_sha256": "sha256:" + "1" * 64,
                "message_kind": "request",
                "traces": {
                    "parser_a": {"stages": ["header", "body"], "outcome": "accepted"},
                    "parser_b": {"stages": ["header", "body"], "outcome": "accepted"},
                },
            },
            {
                "case_id": "c2",
                "input_sha256": "sha256:" + "2" * 64,
                "message_kind": "request",
                "traces": {
                    "parser_a": {"stages": ["header", "body"], "outcome": "accepted"},
                    "parser_b": {"stages": ["header"], "outcome": "rejected"},
                },
            },
        ],
    }
