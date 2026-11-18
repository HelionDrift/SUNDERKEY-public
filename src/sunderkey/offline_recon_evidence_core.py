"""Bounded replay core for supplied reconnaissance assertions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

MAX_OBSERVATIONS = 256
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REF = re.compile(r"(?:subject|source):sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class ReconEvidenceError(ValueError):
    """A supplied assertion model or replay report was refused."""


@dataclass(frozen=True, slots=True)
class ReconEvidenceSpec:
    component_id: str
    profile_id: str
    semantics_profile: str
    domain: str
    id_prefix: str
    kinds: frozenset[str]
    limitation: str


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ReconEvidenceError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise ReconEvidenceError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ReconEvidenceError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise ReconEvidenceError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ReconEvidenceError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ReconEvidenceError("Native JSON text keys are required")
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
        raise ReconEvidenceError("Document byte bound exceeded")
    return encoded


def _plan(model: Any, spec: ReconEvidenceSpec) -> dict:
    model = json.loads(_canonical(model))
    if type(model) is not dict or model.keys() != {
        "schema_version",
        "semantics_profile",
        "observations",
    }:
        raise ReconEvidenceError("Model fields are invalid")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ReconEvidenceError("Schema version is invalid")
    if model["semantics_profile"] != spec.semantics_profile:
        raise ReconEvidenceError("Semantics profile is invalid")
    observations = model["observations"]
    if type(observations) is not list or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise ReconEvidenceError("Observation count is invalid")
    ids: set[str] = set()
    signatures: set[tuple[str, str, str, str]] = set()
    for row in observations:
        if type(row) is not dict or row.keys() != {
            "observation_id",
            "subject_ref",
            "label",
            "kind",
            "source_ref",
            "asserted_present",
        }:
            raise ReconEvidenceError("Observation fields are invalid")
        if type(row["observation_id"]) is not str or _ID.fullmatch(row["observation_id"]) is None:
            raise ReconEvidenceError("Observation identifier is invalid")
        if (
            type(row["subject_ref"]) is not str
            or not row["subject_ref"].startswith("subject:")
            or _REF.fullmatch(row["subject_ref"]) is None
        ):
            raise ReconEvidenceError("Subject must be an opaque digest reference")
        if (
            type(row["source_ref"]) is not str
            or not row["source_ref"].startswith("source:")
            or _REF.fullmatch(row["source_ref"]) is None
        ):
            raise ReconEvidenceError("Source must be an opaque digest reference")
        if type(row["label"]) is not str or _LABEL.fullmatch(row["label"]) is None:
            raise ReconEvidenceError("Supplied label is invalid")
        if type(row["kind"]) is not str or row["kind"] not in spec.kinds:
            raise ReconEvidenceError("Observation kind is invalid")
        if type(row["asserted_present"]) is not bool:
            raise ReconEvidenceError("Presence must be an exact boolean")
        signature = (row["subject_ref"], row["label"], row["kind"], row["source_ref"])
        if row["observation_id"] in ids or signature in signatures:
            raise ReconEvidenceError("Duplicate supplied observation")
        ids.add(row["observation_id"])
        signatures.add(signature)
    return model


def _derive(model: Any, spec: ReconEvidenceSpec) -> dict:
    plan = _plan(model, spec)
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in plan["observations"]:
        groups.setdefault((row["subject_ref"], row["label"]), []).append(row)
    findings = []
    for (subject, label), rows in sorted(groups.items()):
        present = [row for row in rows if row["asserted_present"]]
        absent = [row for row in rows if not row["asserted_present"]]
        if present and absent:
            disposition = "conflicting_supplied_assertions"
        elif (
            len({row["source_ref"] for row in present}) > 1
            and len({row["kind"] for row in present}) > 1
        ):
            disposition = "multi_source_supplied_pattern"
        elif present:
            disposition = "single_source_or_kind_assertion"
        else:
            disposition = "no_positive_supplied_assertion"
        findings.append(
            {
                "subject_ref": subject,
                "label": label,
                "disposition": disposition,
                "present_observation_ids": sorted(row["observation_id"] for row in present),
                "absent_observation_ids": sorted(row["observation_id"] for row in absent),
                "positive_kinds": sorted({row["kind"] for row in present}),
                "declared_source_refs": sorted({row["source_ref"] for row in rows}),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": spec.component_id,
        "profile_id": spec.profile_id,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "source_independence_proven": False,
            "source_authenticity_proven": False,
            "live_subject_state_proven": False,
            "vulnerability_or_deception_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "All observations, labels, source references, and presence flags are caller-supplied.",
            "Distinct source references do not prove independent or authentic sources.",
            spec.limitation,
            "No collection, probing, network request, target access, or credential use occurs.",
        ],
    }
    digest = (
        "sha256:"
        + hashlib.sha256((spec.domain + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {
                **body,
                "analysis_id": spec.id_prefix + digest[7:39].upper(),
                "analysis_sha256": digest,
            }
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class ReconEvidenceReport:
    """Immutable replay-checked projection of supplied assertions."""

    _document_json: str
    _spec: ReconEvidenceSpec

    def __init__(self, document: Any, *, spec: ReconEvidenceSpec) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ReconEvidenceError("Exact native report with source model required")
        expected = _derive(document["source_model"], spec)
        if _canonical(document) != _canonical(expected):
            raise ReconEvidenceError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))
        object.__setattr__(self, "_spec", spec)

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze(model: Any, spec: ReconEvidenceSpec) -> ReconEvidenceReport:
    return ReconEvidenceReport(_derive(model, spec), spec=spec)


def verify(report: Any, *, model: Any, spec: ReconEvidenceSpec) -> ReconEvidenceReport:
    if type(report) is not ReconEvidenceReport or report._spec != spec:
        raise ReconEvidenceError("Exact matching report wrapper required")
    expected = _derive(model, spec)
    if report.to_json() != _canonical(expected):
        raise ReconEvidenceError("Report differs from supplied model replay")
    return ReconEvidenceReport(expected, spec=spec)
