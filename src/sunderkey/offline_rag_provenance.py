"""Compare supplied retrieval index digests and approval declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "rag_supplied_index_provenance"
PROFILE_ID = "AOE-GD-D20-S11"
CAPABILITY_ID = "army.gd.d20.s11"
VECTOR_ID = "AV-GD-D20-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S11"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:106feeee7f8a3b5bb8b3a4841480be3f5707b2710085e38b53dccf16b626f74c"
DOMAIN = "sunderkey.offline-rag-provenance.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class RagProvenanceError(ValueError):
    """A supplied retrieval-provenance model or replay is invalid."""


def _digest(value: Any, *, allow_unknown: bool = False) -> str:
    if allow_unknown and value == "unknown" and type(value) is str:
        return value
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RagProvenanceError("Document digest must be exact SHA-256 text")
    return value


def _nonempty(value: Any, label: str, maximum: int) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    if not rows:
        raise RagProvenanceError(f"{label} must not be empty")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "documents", "uses"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RagProvenanceError("Unsupported model version")
    core.identifier(model["source_id"], "model source ID")
    documents: set[str] = set()
    for item in _nonempty(model["documents"], "documents", 64):
        row = core.exact(
            item, {"document_id", "expected_sha256", "indexed_sha256", "approval"},
            "document",
        )
        document_id = core.identifier(row["document_id"], "document ID")
        if document_id in documents:
            raise RagProvenanceError("Duplicate document ID")
        documents.add(document_id)
        _digest(row["expected_sha256"], allow_unknown=True)
        _digest(row["indexed_sha256"])
        core.choice(row["approval"], {"approved", "denied", "unknown"}, "approval")
    uses: set[str] = set()
    for item in _nonempty(model["uses"], "uses", 128):
        row = core.exact(
            item,
            {"use_id", "document_id", "retrieved", "incorporated", "context_complete"},
            "use",
        )
        use_id = core.identifier(row["use_id"], "use ID")
        if use_id in uses:
            raise RagProvenanceError("Duplicate use ID")
        uses.add(use_id)
        document_id = core.identifier(row["document_id"], "use document ID")
        if document_id not in documents:
            raise RagProvenanceError("Use references an absent document")
        core.choice(row["retrieved"], {"yes", "no", "unknown"}, "retrieved")
        core.choice(row["incorporated"], {"yes", "no", "unknown"}, "incorporated")
        core.boolean(row["context_complete"], "context completeness")
        if row["retrieved"] == "no" and row["incorporated"] == "yes":
            raise RagProvenanceError("A nonretrieved document cannot be incorporated")
    return model, core.canonical(model)


def _disposition(document: dict, use: dict) -> str:
    if not use["context_complete"] or "unknown" in (
        document["expected_sha256"], document["approval"],
        use["retrieved"], use["incorporated"],
    ):
        return "unknown"
    if use["retrieved"] == "no" or use["incorporated"] == "no":
        return "declared_not_incorporated"
    if document["approval"] == "denied":
        return "candidate_declared_unapproved_retrieval"
    if document["expected_sha256"] != document["indexed_sha256"]:
        return "candidate_declared_index_digest_mismatch"
    return "declared_matching_index_unverified"


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    documents = {item["document_id"]: item for item in model["documents"]}
    projections = []
    for item in model["uses"]:
        document = documents[item["document_id"]]
        projections.append({
            "use_id": item["use_id"],
            "document_id": item["document_id"],
            "disposition": _disposition(document, item),
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "use_projections": projections,
        "candidate_count": sum(
            item["disposition"].startswith("candidate_") for item in projections
        ),
        "unknown_count": sum(item["disposition"] == "unknown" for item in projections),
        "source_authenticated": False,
        "document_content_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Digests, approval and retrieval use are caller-supplied declarations.",
            "No retrieved document, prompt, model output or index is read or queried.",
            "A candidate is an index-provenance discrepancy, not observed RAG poisoning.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RGP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RagProvenanceReport:
    """Unsigned projection requiring separately retained original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RagProvenanceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RagProvenanceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rag_provenance(model: Any) -> RagProvenanceReport:
    return RagProvenanceReport._owned(_derive(model))


def verify_supplied_rag_provenance(
    report: Any, *, model: Any
) -> RagProvenanceReport:
    if type(report) is not RagProvenanceReport:
        raise RagProvenanceError("Exact retrieval-provenance wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RagProvenanceError("Report differs from separate original model")
    return RagProvenanceReport._owned(expected)


def verify_supplied_rag_provenance_bytes(
    report_bytes: bytes, *, model: Any
) -> RagProvenanceReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise RagProvenanceError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise RagProvenanceError("Exported report differs from original replay")
    return RagProvenanceReport._owned(expected)


def component_fixture() -> dict:
    matching = "sha256:" + "a" * 64
    altered = "sha256:" + "b" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-rag-provenance",
        "documents": [
            {
                "document_id": "doc-mismatch", "expected_sha256": matching,
                "indexed_sha256": altered, "approval": "approved",
            },
            {
                "document_id": "doc-denied", "expected_sha256": matching,
                "indexed_sha256": matching, "approval": "denied",
            },
            {
                "document_id": "doc-unknown", "expected_sha256": "unknown",
                "indexed_sha256": matching, "approval": "unknown",
            },
        ],
        "uses": [
            {
                "use_id": "used-mismatch", "document_id": "doc-mismatch",
                "retrieved": "yes", "incorporated": "yes", "context_complete": True,
            },
            {
                "use_id": "used-denied", "document_id": "doc-denied",
                "retrieved": "yes", "incorporated": "yes", "context_complete": True,
            },
            {
                "use_id": "not-used", "document_id": "doc-mismatch",
                "retrieved": "yes", "incorporated": "no", "context_complete": True,
            },
            {
                "use_id": "unknown-use", "document_id": "doc-unknown",
                "retrieved": "yes", "incorporated": "yes", "context_complete": True,
            },
        ],
    }
