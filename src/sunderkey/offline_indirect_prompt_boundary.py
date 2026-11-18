"""Project declared lower-trust content promotions without reading prompt text."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "agent_supplied_indirect_prompt_boundary"
PROFILE_ID = "AOE-GD-D20-S10"
CAPABILITY_ID = "ai.indirect-prompt-injection"
VECTOR_ID = "AV-GD-D20-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S10"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:dca52dd0109288b8f8ce77600de983c2bda51e08a432777b217d2372d100bc9e"
DOMAIN = "sunderkey.offline-indirect-prompt-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_ITEMS = 64
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class IndirectPromptBoundaryError(ValueError):
    """A supplied prompt-boundary declaration or replay is invalid."""


def _rows(value: Any, label: str, maximum: int = MAX_ITEMS) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    if not rows:
        raise IndirectPromptBoundaryError(f"{label} must not be empty")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    owned = json.loads(core.canonical(value))
    model = core.exact(
        owned,
        {"schema_version", "source_id", "content_sources", "contexts", "promotions"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise IndirectPromptBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "model source ID")
    sources: set[str] = set()
    for item in _rows(model["content_sources"], "content sources"):
        row = core.exact(item, {"content_id", "channel", "trust"}, "content source")
        content_id = core.identifier(row["content_id"], "content ID")
        if content_id in sources:
            raise IndirectPromptBoundaryError("Duplicate content ID")
        sources.add(content_id)
        core.choice(
            row["channel"],
            {"retrieval", "tool_result", "web_content", "operator", "unknown"},
            "content channel",
        )
        core.choice(row["trust"], {"trusted", "untrusted", "unknown"}, "content trust")
    contexts: set[str] = set()
    for item in _rows(model["contexts"], "contexts"):
        row = core.exact(item, {"context_id", "role"}, "context")
        context_id = core.identifier(row["context_id"], "context ID")
        if context_id in contexts:
            raise IndirectPromptBoundaryError("Duplicate context ID")
        contexts.add(context_id)
        core.choice(row["role"], {"data", "instruction", "system", "unknown"}, "role")
    promotions: set[str] = set()
    for item in _rows(model["promotions"], "promotions", maximum=128):
        row = core.exact(
            item,
            {
                "promotion_id", "content_id", "context_id", "boundary",
                "admission", "context_complete",
            },
            "promotion",
        )
        promotion_id = core.identifier(row["promotion_id"], "promotion ID")
        if promotion_id in promotions:
            raise IndirectPromptBoundaryError("Duplicate promotion ID")
        promotions.add(promotion_id)
        content_id = core.identifier(row["content_id"], "promotion content ID")
        context_id = core.identifier(row["context_id"], "promotion context ID")
        if content_id not in sources or context_id not in contexts:
            raise IndirectPromptBoundaryError("Promotion references absent content or context")
        core.choice(row["boundary"], {"preserved", "promoted", "unknown"}, "boundary")
        core.choice(row["admission"], {"accepted", "rejected", "unknown"}, "admission")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _disposition(source: dict, context: dict, promotion: dict) -> str:
    if not promotion["context_complete"] or "unknown" in (
        source["channel"], source["trust"], context["role"],
        promotion["boundary"], promotion["admission"],
    ):
        return "unknown"
    if promotion["admission"] == "rejected":
        return "declared_rejected"
    if context["role"] == "data":
        return "declared_data_context"
    if promotion["boundary"] == "preserved":
        return "declared_boundary_preserved_unverified"
    if source["trust"] == "trusted":
        return "declared_trusted_source_unverified"
    return "candidate_declared_lower_trust_promotion"


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    sources = {row["content_id"]: row for row in model["content_sources"]}
    contexts = {row["context_id"]: row for row in model["contexts"]}
    projections = []
    for item in model["promotions"]:
        source = sources[item["content_id"]]
        context = contexts[item["context_id"]]
        projections.append({
            "promotion_id": item["promotion_id"],
            "content_id": item["content_id"],
            "context_id": item["context_id"],
            "context_role": context["role"],
            "disposition": _disposition(source, context, item),
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "promotion_projections": projections,
        "candidate_count": sum(
            row["disposition"] == "candidate_declared_lower_trust_promotion"
            for row in projections
        ),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "prompt_content_interpreted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Content trust, context role, boundary and admission are caller declarations.",
            "No prompt text, instruction, model output, target response or payload is processed.",
            "A candidate is a declared trust-boundary conflict, not observed prompt injection.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IPB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class IndirectPromptBoundaryReport:
    """Unsigned projection requiring separately retained original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise IndirectPromptBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> IndirectPromptBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_indirect_prompt_boundary(model: Any) -> IndirectPromptBoundaryReport:
    """Analyze bounded caller metadata without evaluating or sending prompts."""
    return IndirectPromptBoundaryReport._owned(_derive(model))


def verify_supplied_indirect_prompt_boundary(
    report: Any, *, model: Any
) -> IndirectPromptBoundaryReport:
    if type(report) is not IndirectPromptBoundaryReport:
        raise IndirectPromptBoundaryError("Exact prompt-boundary wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise IndirectPromptBoundaryError("Report differs from separate original model")
    return IndirectPromptBoundaryReport._owned(expected)


def verify_supplied_indirect_prompt_boundary_bytes(
    report_bytes: bytes, *, model: Any
) -> IndirectPromptBoundaryReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise IndirectPromptBoundaryError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise IndirectPromptBoundaryError("Exported report differs from original replay")
    return IndirectPromptBoundaryReport._owned(expected)


def component_fixture() -> dict:
    """Return a synthetic label-only declaration for the closed dispatcher."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-prompt-boundary",
        "content_sources": [
            {"content_id": "retrieval-one", "channel": "retrieval", "trust": "untrusted"},
            {"content_id": "tool-two", "channel": "tool_result", "trust": "unknown"},
        ],
        "contexts": [
            {"context_id": "instruction-one", "role": "instruction"},
            {"context_id": "data-one", "role": "data"},
        ],
        "promotions": [
            {
                "promotion_id": "promoted-one", "content_id": "retrieval-one",
                "context_id": "instruction-one", "boundary": "promoted",
                "admission": "accepted", "context_complete": True,
            },
            {
                "promotion_id": "data-only", "content_id": "retrieval-one",
                "context_id": "data-one", "boundary": "preserved",
                "admission": "accepted", "context_complete": True,
            },
            {
                "promotion_id": "uncertain-one", "content_id": "tool-two",
                "context_id": "instruction-one", "boundary": "promoted",
                "admission": "accepted", "context_complete": True,
            },
        ],
    }
