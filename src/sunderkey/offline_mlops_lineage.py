"""Trace supplied MLOps stage lineage and declared release approvals."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mlops_supplied_release_lineage"
PROFILE_ID = "AOE-GD-D20-S01"
CAPABILITY_ID = "army.gd.d20.s01"
VECTOR_ID = "AV-GD-D20-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S01"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:faf83b569019ff650b2650f34c628cf09cad96e53b3efa4ec61ce6dbedb80175"
DOMAIN = "sunderkey.offline-mlops-lineage.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class MlopsLineageError(ValueError):
    """A supplied pipeline stage graph or replay is invalid."""


def _digest(value: Any, label: str, *, allow_none: bool = False) -> str:
    if allow_none and type(value) is str and value == "none":
        return value
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise MlopsLineageError(f"{label} must be exact SHA-256 text")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "stages", "releases"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MlopsLineageError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    stages = core.bounded_list(model["stages"], 32, "stages")
    releases = core.bounded_list(model["releases"], 32, "releases")
    if not stages or not releases:
        raise MlopsLineageError("Stages and releases must not be empty")
    seen: set[str] = set()
    for item in stages:
        row = core.exact(
            item,
            {
                "stage_id", "stage_kind", "predecessor_stage_id", "input_sha256",
                "output_sha256", "approval",
            },
            "stage",
        )
        stage_id = core.identifier(row["stage_id"], "stage ID")
        if stage_id in seen:
            raise MlopsLineageError("Duplicate stage ID")
        core.choice(
            row["stage_kind"], {"dataset", "training", "evaluation", "packaging"},
            "stage kind",
        )
        predecessor = row["predecessor_stage_id"]
        if predecessor == "none":
            if row["input_sha256"] != "none":
                raise MlopsLineageError("Root stage input must be none")
        elif core.identifier(predecessor, "predecessor ID") not in seen:
            raise MlopsLineageError("Predecessor must be an earlier stage")
        _digest(row["input_sha256"], "input digest", allow_none=predecessor == "none")
        _digest(row["output_sha256"], "output digest")
        core.choice(row["approval"], {"approved", "denied", "unknown"}, "approval")
        seen.add(stage_id)
    release_ids: set[str] = set()
    for item in releases:
        row = core.exact(
            item, {"release_id", "terminal_stage_id", "context_complete"}, "release"
        )
        release_id = core.identifier(row["release_id"], "release ID")
        if release_id in release_ids:
            raise MlopsLineageError("Duplicate release ID")
        release_ids.add(release_id)
        if core.identifier(row["terminal_stage_id"], "terminal stage ID") not in seen:
            raise MlopsLineageError("Release references an absent stage")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    stages = {item["stage_id"]: item for item in model["stages"]}
    projections = []
    for release in model["releases"]:
        chain: list[str] = []
        reasons: list[str] = []
        unknown = not release["context_complete"]
        current = stages[release["terminal_stage_id"]]
        while True:
            chain.append(current["stage_id"])
            if current["approval"] == "unknown":
                unknown = True
            elif current["approval"] == "denied":
                reasons.append("declared_unapproved_stage")
            predecessor_id = current["predecessor_stage_id"]
            if predecessor_id == "none":
                break
            predecessor = stages[predecessor_id]
            if current["input_sha256"] != predecessor["output_sha256"]:
                reasons.append("declared_digest_discontinuity")
            current = predecessor
        chain.reverse()
        if unknown:
            disposition = "unknown"
        elif reasons:
            disposition = "candidate_declared_lineage_conflict"
        else:
            disposition = "declared_continuous_approved_lineage_unverified"
        projections.append({
            "release_id": release["release_id"],
            "stage_path": chain,
            "risk_reasons": sorted(set(reasons)),
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "release_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "stage_execution_verified": False,
        "artifact_bytes_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Stage digests, approvals and release links are caller-supplied declarations.",
            "A continuous graph does not prove that stages ran or artifacts exist.",
            "No dataset, model, pipeline, provider or target is accessed.",
            "A candidate is a declared lineage conflict, not observed MLOps compromise.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MLL-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class MlopsLineageReport:
    """Unsigned lineage projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MlopsLineageError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MlopsLineageReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mlops_lineage(model: Any) -> MlopsLineageReport:
    return MlopsLineageReport._owned(_derive(model))


def verify_supplied_mlops_lineage(
    report: Any, *, model: Any
) -> MlopsLineageReport:
    if type(report) is not MlopsLineageReport:
        raise MlopsLineageError("Exact MLOps-lineage wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MlopsLineageError("Report differs from separate original model")
    return MlopsLineageReport._owned(expected)


def verify_supplied_mlops_lineage_bytes(
    report_bytes: bytes, *, model: Any
) -> MlopsLineageReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise MlopsLineageError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise MlopsLineageError("Exported report differs from original replay")
    return MlopsLineageReport._owned(expected)


def component_fixture() -> dict:
    first = "sha256:" + "a" * 64
    second = "sha256:" + "b" * 64
    third = "sha256:" + "c" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-mlops-lineage",
        "stages": [
            {
                "stage_id": "dataset", "stage_kind": "dataset",
                "predecessor_stage_id": "none", "input_sha256": "none",
                "output_sha256": first, "approval": "approved",
            },
            {
                "stage_id": "training", "stage_kind": "training",
                "predecessor_stage_id": "dataset", "input_sha256": first,
                "output_sha256": second, "approval": "approved",
            },
            {
                "stage_id": "package", "stage_kind": "packaging",
                "predecessor_stage_id": "training", "input_sha256": second,
                "output_sha256": third, "approval": "approved",
            },
            {
                "stage_id": "mismatch", "stage_kind": "evaluation",
                "predecessor_stage_id": "training", "input_sha256": first,
                "output_sha256": third, "approval": "approved",
            },
            {
                "stage_id": "denied", "stage_kind": "packaging",
                "predecessor_stage_id": "training", "input_sha256": second,
                "output_sha256": third, "approval": "denied",
            },
            {
                "stage_id": "uncertain", "stage_kind": "evaluation",
                "predecessor_stage_id": "training", "input_sha256": second,
                "output_sha256": third, "approval": "unknown",
            },
        ],
        "releases": [
            {"release_id": "clean", "terminal_stage_id": "package", "context_complete": True},
            {"release_id": "changed", "terminal_stage_id": "mismatch", "context_complete": True},
            {"release_id": "blocked", "terminal_stage_id": "denied", "context_complete": True},
            {"release_id": "unknown", "terminal_stage_id": "uncertain", "context_complete": True},
            {"release_id": "incomplete", "terminal_stage_id": "package", "context_complete": False},
        ],
    }
