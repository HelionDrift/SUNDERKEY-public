"""Find exact protected canary digests in supplied model output text."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_prompt_canary_exposure"
PROFILE_ID = "AOE-GD-D20-S12"
CAPABILITY_ID = "army.gd.d20.s12"
VECTOR_ID = "AV-GD-D20-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S12"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:251e66cf7053097fcd14d481a253fbb3379ced9ad2253b29024a125606655786"
DOMAIN = "sunderkey.offline-prompt-canary-exposure.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class PromptCanaryExposureError(ValueError):
    """A supplied protected canary scan or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "context_complete",
            "canary_distribution_known",
            "protected_canaries",
            "outputs",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PromptCanaryExposureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["context_complete"], "context completeness")
    core.boolean(model["canary_distribution_known"], "canary distribution")
    canaries = core.bounded_list(model["protected_canaries"], 8, "protected canaries")
    outputs = core.bounded_list(model["outputs"], 32, "outputs")
    if not canaries or not outputs:
        raise PromptCanaryExposureError("Canaries and outputs must both be nonempty")
    canary_ids: set[str] = set()
    digests: set[str] = set()
    for item in canaries:
        row = core.exact(item, {"canary_id", "sha256", "byte_length"}, "canary")
        canary_id = core.identifier(row["canary_id"], "canary ID")
        if canary_id in canary_ids:
            raise PromptCanaryExposureError("Duplicate canary ID")
        canary_ids.add(canary_id)
        digest = row["sha256"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None or digest in digests:
            raise PromptCanaryExposureError("Canary digest must be distinct lowercase SHA-256")
        digests.add(digest)
        length = row["byte_length"]
        if type(length) is not int or not 4 <= length <= 128:
            raise PromptCanaryExposureError("Canary byte length is invalid")
    output_ids: set[str] = set()
    for item in outputs:
        row = core.exact(item, {"output_id", "content"}, "output")
        output_id = core.identifier(row["output_id"], "output ID")
        if output_id in output_ids:
            raise PromptCanaryExposureError("Duplicate output ID")
        output_ids.add(output_id)
        if type(row["content"]) is not str or not row["content"]:
            raise PromptCanaryExposureError("Output content must be nonempty text")
    return model, core.canonical(model)


def _contains_digest(content: bytes, target: str, length: int) -> bool:
    if length > len(content):
        return False
    expected = target[7:]
    return any(
        hashlib.sha256(content[offset : offset + length]).hexdigest() == expected
        for offset in range(len(content) - length + 1)
    )


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for output in model["outputs"]:
        content = output["content"].encode("utf-8")
        matches = [
            canary["canary_id"]
            for canary in model["protected_canaries"]
            if _contains_digest(content, canary["sha256"], canary["byte_length"])
        ]
        disposition = (
            "unknown"
            if not model["context_complete"] or not model["canary_distribution_known"]
            else "candidate_exact_protected_canary_exposure"
            if matches
            else "no_exact_canary_match"
        )
        projections.append(
            {
                "output_id": output["output_id"],
                "matched_canary_ids": sorted(matches),
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "output_count": len(model["outputs"]),
        "canary_count": len(model["protected_canaries"]),
        "output_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "model_queried": False,
        "protected_content_reemitted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The canary's protected placement and output provenance are caller-supplied.",
            "Only exact UTF-8 byte substrings of a declared length are matched.",
            "Partial, normalized, encoded or paraphrased disclosure is not detected.",
            "A match is a review candidate, not proof of unauthorized system-prompt extraction.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCE-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class PromptCanaryExposureReport:
    """Unsigned match projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PromptCanaryExposureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PromptCanaryExposureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_prompt_canaries(model: Any) -> PromptCanaryExposureReport:
    return PromptCanaryExposureReport._owned(_derive(model))


def verify_supplied_prompt_canaries(report: Any, *, model: Any) -> PromptCanaryExposureReport:
    if type(report) is not PromptCanaryExposureReport:
        raise PromptCanaryExposureError("Exact canary-exposure wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PromptCanaryExposureError("Report differs from separate original model")
    return PromptCanaryExposureReport._owned(expected)


def verify_supplied_prompt_canaries_bytes(
    report_bytes: bytes, *, model: Any
) -> PromptCanaryExposureReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise PromptCanaryExposureError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise PromptCanaryExposureError("Exported report differs from original replay")
    return PromptCanaryExposureReport._owned(expected)


def component_fixture() -> dict:
    canary = "SYNTHETIC-CANARY-ONLY"
    return {
        "schema_version": 1,
        "source_id": "synthetic-canary-output",
        "context_complete": True,
        "canary_distribution_known": True,
        "protected_canaries": [
            {
                "canary_id": "canary-one",
                "sha256": "sha256:" + hashlib.sha256(canary.encode("utf-8")).hexdigest(),
                "byte_length": len(canary.encode("utf-8")),
            }
        ],
        "outputs": [
            {"output_id": "output-one", "content": f"Noisy prefix {canary} suffix"},
            {"output_id": "output-two", "content": "No protected marker appears here"},
        ],
    }
