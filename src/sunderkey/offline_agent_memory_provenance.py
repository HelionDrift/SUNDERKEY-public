"""Compare supplied agent-memory writer, digest, and read-context declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "agent_supplied_memory_provenance"
PROFILE_ID = "AOE-GD-D20-S16"
CAPABILITY_ID = "army.gd.d20.s16"
VECTOR_ID = "AV-GD-D20-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S16"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:f181853a5f2a979b790f61c2b8082ecaced33ce26924a3bdd2afd535c8aa506c"
DOMAIN = "sunderkey.offline-agent-memory-provenance.v1"
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


class AgentMemoryProvenanceError(ValueError):
    """A supplied memory-provenance declaration or replay is invalid."""


def _digest(value: Any, *, allow_unknown: bool = False) -> str:
    if allow_unknown and type(value) is str and value == "unknown":
        return value
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AgentMemoryProvenanceError("Memory digest must be exact SHA-256 text")
    return value


def _rows(value: Any, label: str, maximum: int) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    if not rows:
        raise AgentMemoryProvenanceError(f"{label} must not be empty")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "entries", "reads"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AgentMemoryProvenanceError("Unsupported model version")
    core.identifier(model["source_id"], "model source ID")
    entries: set[str] = set()
    for item in _rows(model["entries"], "entries", 64):
        row = core.exact(
            item,
            {
                "entry_id", "writer_kind", "writer_approval", "expected_sha256",
                "stored_sha256",
            },
            "memory entry",
        )
        entry_id = core.identifier(row["entry_id"], "entry ID")
        if entry_id in entries:
            raise AgentMemoryProvenanceError("Duplicate entry ID")
        entries.add(entry_id)
        core.choice(
            row["writer_kind"], {"owner", "agent", "external", "unknown"},
            "writer kind",
        )
        core.choice(
            row["writer_approval"], {"approved", "denied", "unknown"},
            "writer approval",
        )
        _digest(row["expected_sha256"], allow_unknown=True)
        _digest(row["stored_sha256"])
    reads: set[str] = set()
    for item in _rows(model["reads"], "reads", 128):
        row = core.exact(
            item,
            {"read_id", "entry_id", "context_role", "admission", "context_complete"},
            "memory read",
        )
        read_id = core.identifier(row["read_id"], "read ID")
        if read_id in reads:
            raise AgentMemoryProvenanceError("Duplicate read ID")
        reads.add(read_id)
        entry_id = core.identifier(row["entry_id"], "read entry ID")
        if entry_id not in entries:
            raise AgentMemoryProvenanceError("Read references an absent entry")
        core.choice(
            row["context_role"],
            {"data", "instruction", "tool_policy", "unknown"},
            "context role",
        )
        core.choice(row["admission"], {"accepted", "rejected", "unknown"}, "admission")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _disposition(entry: dict, read: dict) -> str:
    if not read["context_complete"] or "unknown" in (
        entry["writer_kind"], entry["writer_approval"], entry["expected_sha256"],
        read["context_role"], read["admission"],
    ):
        return "unknown"
    if read["admission"] == "rejected":
        return "declared_rejected"
    if read["context_role"] == "data":
        return "declared_data_only"
    if entry["writer_approval"] == "denied":
        return "candidate_declared_denied_memory_use"
    if entry["expected_sha256"] != entry["stored_sha256"]:
        return "candidate_declared_memory_digest_mismatch"
    return "declared_approved_memory_unverified"


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    entries = {item["entry_id"]: item for item in model["entries"]}
    projections = []
    for item in model["reads"]:
        entry = entries[item["entry_id"]]
        projections.append({
            "read_id": item["read_id"],
            "entry_id": item["entry_id"],
            "context_role": item["context_role"],
            "disposition": _disposition(entry, item),
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "read_projections": projections,
        "candidate_count": sum(
            item["disposition"].startswith("candidate_") for item in projections
        ),
        "unknown_count": sum(item["disposition"] == "unknown" for item in projections),
        "source_authenticated": False,
        "memory_content_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Writer, approval, digest, read and context labels are caller declarations.",
            "No memory entry, prompt, protocol message or model output is read.",
            "A candidate is a declared provenance conflict, not observed memory poisoning.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="AMP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AgentMemoryProvenanceReport:
    """Unsigned projection requiring separately retained original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AgentMemoryProvenanceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AgentMemoryProvenanceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_agent_memory_provenance(model: Any) -> AgentMemoryProvenanceReport:
    return AgentMemoryProvenanceReport._owned(_derive(model))


def verify_supplied_agent_memory_provenance(
    report: Any, *, model: Any
) -> AgentMemoryProvenanceReport:
    if type(report) is not AgentMemoryProvenanceReport:
        raise AgentMemoryProvenanceError("Exact memory-provenance wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AgentMemoryProvenanceError("Report differs from separate original model")
    return AgentMemoryProvenanceReport._owned(expected)


def verify_supplied_agent_memory_provenance_bytes(
    report_bytes: bytes, *, model: Any
) -> AgentMemoryProvenanceReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AgentMemoryProvenanceError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AgentMemoryProvenanceError("Exported report differs from original replay")
    return AgentMemoryProvenanceReport._owned(expected)


def component_fixture() -> dict:
    matching = "sha256:" + "a" * 64
    altered = "sha256:" + "b" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-agent-memory",
        "entries": [
            {
                "entry_id": "denied-entry", "writer_kind": "external",
                "writer_approval": "denied", "expected_sha256": matching,
                "stored_sha256": matching,
            },
            {
                "entry_id": "changed-entry", "writer_kind": "agent",
                "writer_approval": "approved", "expected_sha256": matching,
                "stored_sha256": altered,
            },
            {
                "entry_id": "unknown-entry", "writer_kind": "unknown",
                "writer_approval": "unknown", "expected_sha256": "unknown",
                "stored_sha256": matching,
            },
        ],
        "reads": [
            {
                "read_id": "denied-read", "entry_id": "denied-entry",
                "context_role": "instruction", "admission": "accepted",
                "context_complete": True,
            },
            {
                "read_id": "changed-read", "entry_id": "changed-entry",
                "context_role": "tool_policy", "admission": "accepted",
                "context_complete": True,
            },
            {
                "read_id": "data-read", "entry_id": "changed-entry",
                "context_role": "data", "admission": "accepted",
                "context_complete": True,
            },
            {
                "read_id": "unknown-read", "entry_id": "unknown-entry",
                "context_role": "instruction", "admission": "accepted",
                "context_complete": True,
            },
        ],
    }
