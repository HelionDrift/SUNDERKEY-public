"""Project supplied ETL dependencies and watermarks without running pipelines."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_etl_watermark_projection"
PROFILE_ID = "AOE-GB-D07-S11"
CAPABILITY_ID = "army.gb.d07.s11"
VECTOR_ID = "AV-GB-D07-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:3a59779a278478ee5acd52a24205b45121ec46deec04f5445302eaf3f812a23a"
SEMANTICS_PROFILE = "supplied-etl-watermarks-v1"
DOMAIN = "sunderkey.offline-etl-watermark-projection.v1"
MAX_STEPS = 128
MAX_DEPENDENCIES = 256
MAX_OBJECTIVES = 16
MAX_TICK = 1_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_STEP = re.compile(r"step:sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_STATES = frozenset(("complete", "pending", "failed"))
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "pipeline",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class EtlWatermarkProjectionError(ValueError):
    """A supplied ETL model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise EtlWatermarkProjectionError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise EtlWatermarkProjectionError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise EtlWatermarkProjectionError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise EtlWatermarkProjectionError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise EtlWatermarkProjectionError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise EtlWatermarkProjectionError("Native JSON text keys are required")
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
        raise EtlWatermarkProjectionError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise EtlWatermarkProjectionError(f"{label} fields are invalid")


def _step(value: Any, label: str) -> str:
    if type(value) is not str or _STEP.fullmatch(value) is None:
        raise EtlWatermarkProjectionError(f"{label} must be an opaque step digest")
    return value


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise EtlWatermarkProjectionError(f"{label} tick is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "steps", "dependencies", "objectives"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EtlWatermarkProjectionError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise EtlWatermarkProjectionError("Semantics profile is invalid")
    steps = model["steps"]
    dependencies = model["dependencies"]
    objectives = model["objectives"]
    if type(steps) is not list or not 1 <= len(steps) <= MAX_STEPS:
        raise EtlWatermarkProjectionError("Step count is invalid")
    if type(dependencies) is not list or len(dependencies) > MAX_DEPENDENCIES:
        raise EtlWatermarkProjectionError("Dependency count is invalid")
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise EtlWatermarkProjectionError("Objective count is invalid")
    by_ref: dict[str, dict] = {}
    for row in steps:
        _fields(row, {"step_ref", "declared_state", "output_watermark_tick"}, "step")
        step_ref = _step(row["step_ref"], "Step")
        if step_ref in by_ref:
            raise EtlWatermarkProjectionError("Duplicate step reference")
        state = row["declared_state"]
        if type(state) is not str or state not in _STATES:
            raise EtlWatermarkProjectionError("Step state is invalid")
        watermark = row["output_watermark_tick"]
        if state == "complete":
            _tick(watermark, "Output watermark")
        elif watermark is not None:
            raise EtlWatermarkProjectionError("Incomplete step cannot claim output watermark")
        by_ref[step_ref] = row
    edge_ids: set[str] = set()
    edge_pairs: set[tuple[str, str]] = set()
    upstreams: dict[str, list[str]] = {}
    for row in dependencies:
        _fields(row, {"dependency_id", "upstream_step_ref", "downstream_step_ref"}, "dependency")
        edge_id = row["dependency_id"]
        if type(edge_id) is not str or _ID.fullmatch(edge_id) is None:
            raise EtlWatermarkProjectionError("Dependency identifier is invalid")
        upstream = _step(row["upstream_step_ref"], "Upstream")
        downstream = _step(row["downstream_step_ref"], "Downstream")
        pair = (upstream, downstream)
        if edge_id in edge_ids or pair in edge_pairs or upstream == downstream:
            raise EtlWatermarkProjectionError("Duplicate or self dependency")
        if upstream not in by_ref or downstream not in by_ref:
            raise EtlWatermarkProjectionError("Dependency step is undeclared")
        edge_ids.add(edge_id)
        edge_pairs.add(pair)
        upstreams.setdefault(downstream, []).append(upstream)
    active: set[str] = set()
    visited: set[str] = set()

    def visit(step_ref: str) -> None:
        if step_ref in active:
            raise EtlWatermarkProjectionError("Dependency graph contains a cycle")
        if step_ref in visited:
            return
        active.add(step_ref)
        for upstream in upstreams.get(step_ref, []):
            visit(upstream)
        active.remove(step_ref)
        visited.add(step_ref)

    for step_ref in by_ref:
        visit(step_ref)
    objective_refs: set[str] = set()
    for row in objectives:
        _fields(row, {"step_ref", "required_watermark_tick"}, "objective")
        step_ref = _step(row["step_ref"], "Objective")
        if step_ref not in by_ref or step_ref in objective_refs:
            raise EtlWatermarkProjectionError("Objective step is undeclared or duplicate")
        _tick(row["required_watermark_tick"], "Required watermark")
        objective_refs.add(step_ref)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    by_ref = {row["step_ref"]: row for row in plan["steps"]}
    upstreams: dict[str, list[str]] = {}
    for edge in plan["dependencies"]:
        upstreams.setdefault(edge["downstream_step_ref"], []).append(edge["upstream_step_ref"])
    findings = []
    for objective in plan["objectives"]:
        lineage: set[str] = set()
        pending = [objective["step_ref"]]
        while pending:
            step_ref = pending.pop()
            if step_ref in lineage:
                continue
            lineage.add(step_ref)
            pending.extend(upstreams.get(step_ref, []))
        blockers = sorted(ref for ref in lineage if by_ref[ref]["declared_state"] != "complete")
        if blockers:
            minimum = None
            disposition = "declared_incomplete_lineage"
        else:
            minimum = min(by_ref[ref]["output_watermark_tick"] for ref in lineage)
            disposition = (
                "within_supplied_watermark"
                if minimum >= objective["required_watermark_tick"]
                else "below_supplied_watermark"
            )
        findings.append(
            {
                "step_ref": objective["step_ref"],
                "required_watermark_tick": objective["required_watermark_tick"],
                "lineage_step_refs": sorted(lineage),
                "blocking_step_refs": blockers,
                "minimum_declared_watermark_tick": minimum,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "pipeline_execution_verified": False,
            "source_data_freshness_verified": False,
            "lineage_completeness_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Step states, dependencies, and watermarks are caller-supplied.",
            "A declared complete lineage does not prove execution or data freshness.",
            "Only abstract integer ticks and explicitly supplied edges are compared.",
            "No pipeline, notebook, provider, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "EWP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class EtlWatermarkProjection:
    """Immutable report replayed from supplied ETL declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise EtlWatermarkProjectionError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise EtlWatermarkProjectionError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_etl_watermarks(model: Any) -> EtlWatermarkProjection:
    """Project only supplied dependency closure and declared watermarks."""
    return EtlWatermarkProjection(_derive(model))


def verify_supplied_etl_watermarks(report: Any, *, model: Any) -> EtlWatermarkProjection:
    if type(report) is not EtlWatermarkProjection:
        raise EtlWatermarkProjectionError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise EtlWatermarkProjectionError("Report differs from supplied model replay")
    return EtlWatermarkProjection(expected)
