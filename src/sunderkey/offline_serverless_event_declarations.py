"""Compare bounded, caller-supplied function and event binding declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "serverless_supplied_function_event_bindings"
PROFILE_ID = "AOE-GC-D15-S13"
CAPABILITY_ID = "army.gc.d15.s13"
VECTOR_ID = "AV-GC-D15-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S13"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:abe07d9922542325f8ff64c18646102de053dbd939e7f42dcad88492e7c62c12"
DOMAIN = "sunderkey.offline-serverless-event-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_RECORDS = 64
MAX_BINDINGS = 256
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class ServerlessEventDeclarationError(ValueError):
    """A supplied declaration or original-model replay is invalid."""


def _identifiers(value: Any, label: str) -> list[str]:
    rows = core.bounded_list(value, MAX_RECORDS, label)
    result = [core.identifier(item, label) for item in rows]
    if len(set(result)) != len(result):
        raise ServerlessEventDeclarationError(f"Duplicate {label}")
    return result


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "functions", "event_sources"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ServerlessEventDeclarationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    functions = core.bounded_list(model["functions"], MAX_RECORDS, "functions")
    sources = core.bounded_list(model["event_sources"], MAX_RECORDS, "event sources")
    function_ids: set[str] = set()
    source_ids: set[str] = set()
    binding_count = 0
    for index, value in enumerate(functions):
        item = core.exact(value, {"function_id", "event_source_ids"}, f"function {index}")
        function_id = core.identifier(item["function_id"], "function ID")
        if function_id in function_ids:
            raise ServerlessEventDeclarationError("Duplicate function ID")
        function_ids.add(function_id)
        binding_count += len(_identifiers(item["event_source_ids"], "event source IDs"))
        if binding_count > MAX_BINDINGS:
            raise ServerlessEventDeclarationError("Too many function-event bindings")
    for index, value in enumerate(sources):
        item = core.exact(value, {"event_source_id", "target_function_id"}, f"event source {index}")
        source_id = core.identifier(item["event_source_id"], "event source ID")
        if source_id in source_ids:
            raise ServerlessEventDeclarationError("Duplicate event source ID")
        source_ids.add(source_id)
        core.identifier(item["target_function_id"], "target function ID")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    complete = model["inventory_complete"]
    function_by_id = {item["function_id"]: item for item in model["functions"]}
    source_by_id = {item["event_source_id"]: item for item in model["event_sources"]}
    mismatches: list[dict[str, str]] = []
    function_rows = []
    for index, function in enumerate(model["functions"]):
        checks = []
        for source_id in function["event_source_ids"]:
            source = source_by_id.get(source_id)
            match = source is not None and source["target_function_id"] == function["function_id"]
            if complete and not match:
                mismatches.append({
                    "issue": "function_event_source_binding_mismatch",
                    "path": f"functions/{index}/event_source_ids/{source_id}",
                })
            checks.append({
                "event_source_id": source_id,
                "reciprocal_match": match if complete else None,
            })
        function_rows.append({
            "function_id": function["function_id"],
            "event_source_checks": checks,
        })
    source_rows = []
    for index, source in enumerate(model["event_sources"]):
        function = function_by_id.get(source["target_function_id"])
        match = function is not None and source["event_source_id"] in function["event_source_ids"]
        if complete and not match:
            mismatches.append({
                "issue": "event_target_binding_mismatch",
                "path": f"event_sources/{index}",
            })
        source_rows.append({
            "event_source_id": source["event_source_id"],
            "target_function_id": source["target_function_id"],
            "reciprocal_match": match if complete else None,
        })
    if not complete:
        disposition = "unknown"
    elif mismatches:
        disposition = "candidate_supplied_binding_mismatch"
    elif not function_rows or not source_rows:
        disposition = "unknown"
    else:
        disposition = "supplied_binding_consistent"
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
        "function_record_count": len(function_rows),
        "event_source_record_count": len(source_rows),
        "function_rows": function_rows,
        "event_source_rows": source_rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "provider_contacted": False,
        "function_invoked": False,
        "event_delivered": False,
        "authorization_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Function and event-source records, including completeness, are caller-supplied.",
            "Only reciprocal identifier bindings in a finite declaration subset are compared.",
            "No provider call, function invocation, event delivery, or authorization check occurs.",
            "A matching declaration does not establish runtime delivery or safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OSE-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ServerlessEventDeclarationReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ServerlessEventDeclarationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ServerlessEventDeclarationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_serverless_event_declarations(model: Any) -> ServerlessEventDeclarationReport:
    return ServerlessEventDeclarationReport._owned(_derive(model))


def verify_supplied_serverless_event_declarations(
    report: Any, *, model: Any,
) -> ServerlessEventDeclarationReport:
    if type(report) is not ServerlessEventDeclarationReport:
        raise ServerlessEventDeclarationError("Exact serverless declaration wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ServerlessEventDeclarationError("Report differs from separate original model")
    return ServerlessEventDeclarationReport._owned(expected)


def verify_supplied_serverless_event_declarations_bytes(
    report_bytes: bytes, *, model: Any,
) -> ServerlessEventDeclarationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ServerlessEventDeclarationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ServerlessEventDeclarationError("Exported report differs from original replay")
    return ServerlessEventDeclarationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-serverless-events",
        "inventory_complete": True,
        "functions": [{"function_id": "function-a", "event_source_ids": ["source-a"]}],
        "event_sources": [{"event_source_id": "source-a", "target_function_id": "function-a"}],
    }
