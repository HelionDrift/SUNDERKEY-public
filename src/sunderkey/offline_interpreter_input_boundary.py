"""Project supplied data-to-interpreter boundaries without executing content."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_interpreter_input_boundary"
PROFILE_ID = "AOE-GE-D23-S02"
CAPABILITY_ID = "army.ge.d23.s02"
VECTOR_ID = "AV-GE-D23-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S02"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d65f895a5f6dae3abca314c08d278d8eb8145c3b4be6d958451d619c19f7f9c0"
SEMANTICS_PROFILE = "supplied-interpreter-input-boundary-v1"
DOMAIN = "sunderkey.offline-interpreter-input-boundary.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_SINKS = 64
MAX_INPUTS = 16
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_FAMILIES = {"command", "code", "template"}
_TRUST = {"trusted", "untrusted", "unknown"}
_INCORPORATION = {"data_only", "interpreter_source", "unknown"}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

InterpreterInputBoundaryError = core.FrameworkDeclarationError


def _reference(value: Any) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise InterpreterInputBoundaryError("Input label must be an opaque reference")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "sinks"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise InterpreterInputBoundaryError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise InterpreterInputBoundaryError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"], {"declaration_complete", "untrusted_data_only_required"}, "policy"
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    core.boolean(policy["untrusted_data_only_required"], "data-only requirement")
    sinks = core.bounded_list(item["sinks"], MAX_SINKS, "sinks")
    if not sinks:
        raise InterpreterInputBoundaryError("At least one sink is required")
    sink_ids: set[str] = set()
    for raw in sinks:
        sink = core.exact(
            raw,
            {"sink_id", "sink_family", "inputs", "invocation_declared", "capture_complete"},
            "sink",
        )
        identity = core.identifier(sink["sink_id"], "sink ID")
        if identity in sink_ids:
            raise InterpreterInputBoundaryError("Sink identifier is repeated")
        sink_ids.add(identity)
        core.choice(sink["sink_family"], _FAMILIES, "sink family")
        core.boolean(sink["invocation_declared"], "invocation declaration")
        core.boolean(sink["capture_complete"], "capture completeness")
        inputs = core.bounded_list(sink["inputs"], MAX_INPUTS, "inputs")
        if not inputs:
            raise InterpreterInputBoundaryError("At least one input is required")
        input_ids: set[str] = set()
        for raw_input in inputs:
            entry = core.exact(
                raw_input, {"input_ref", "source_trust", "incorporation"}, "input"
            )
            source_ref = _reference(entry["input_ref"])
            if source_ref in input_ids:
                raise InterpreterInputBoundaryError("Input reference is repeated")
            input_ids.add(source_ref)
            core.choice(entry["source_trust"], _TRUST, "source trust")
            core.choice(entry["incorporation"], _INCORPORATION, "incorporation")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    projections = []
    for item in sorted(model["sinks"], key=lambda row: row["sink_id"]):
        unresolved = any(
            entry["source_trust"] == "unknown" or entry["incorporation"] == "unknown"
            for entry in item["inputs"]
        )
        interpreted = sorted(
            entry["input_ref"] for entry in item["inputs"]
            if entry["source_trust"] == "untrusted"
            and entry["incorporation"] == "interpreter_source"
        )
        negative = model["policy"]["untrusted_data_only_required"] and bool(interpreted)
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif unresolved:
            disposition = "unresolved_input_trust_or_incorporation"
        elif not negative:
            disposition = "no_declared_interpreted_untrusted_input"
        elif not item["invocation_declared"]:
            disposition = "declared_uninvoked_interpreter_construction_conflict"
        else:
            disposition = "candidate_declared_interpreter_input_boundary_conflict"
        projections.append(
            {"sink_id": item["sink_id"], "interpreted_untrusted_input_refs": interpreted,
             "negative_predicate": "untrusted_input_must_remain_data" if negative else None,
             "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "sink_count": len(projections),
        "projections": projections,
        "flags": {
            "interpreter_invocation_verified": False,
            "input_flow_verified": False,
            "injection_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Sink family, input trust, incorporation and invocation are caller assertions.",
            "No command, code, template or injection payload is accepted or generated.",
            "A declared conflict does not verify interpreter injection or execution.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IIB-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class InterpreterInputBoundary:
    """Immutable replay of one supplied interpreter-input model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise InterpreterInputBoundaryError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise InterpreterInputBoundaryError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_interpreter_input_boundary(model: Any) -> InterpreterInputBoundary:
    """Project supplied dataflow without running an interpreter."""
    return InterpreterInputBoundary(_derive(model))


def verify_supplied_interpreter_input_boundary(
    report: Any, *, model: Any
) -> InterpreterInputBoundary:
    if type(report) is not InterpreterInputBoundary:
        raise InterpreterInputBoundaryError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise InterpreterInputBoundaryError("Report differs from supplied source replay")
    return InterpreterInputBoundary(expected)
