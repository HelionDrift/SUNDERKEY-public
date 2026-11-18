"""Compare supplied model output digests without querying either model."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_output_similarity"
PROFILE_ID = "AOE-GD-D20-S05"
CAPABILITY_ID = "army.gd.d20.s05"
VECTOR_ID = "AV-GD-D20-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S05"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:3fdab526ced27982e2eefc4bae39e5bc75b0ee58f819e0dfaf48cec003d73520"
DOMAIN = "sunderkey.offline-model-output-similarity.v1"
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


class ModelOutputSimilarityError(ValueError):
    """A supplied output digest comparison or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "reference_model_id",
            "candidate_model_id",
            "control_model_id",
            "minimum_challenges",
            "minimum_excess_match_basis_points",
            "comparable_conditions",
            "challenge_matches",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ModelOutputSimilarityError("Unsupported model version")
    for key in ("source_id", "reference_model_id", "candidate_model_id", "control_model_id"):
        core.identifier(model[key], key)
    if (
        len(
            {model[key] for key in ("reference_model_id", "candidate_model_id", "control_model_id")}
        )
        != 3
    ):
        raise ModelOutputSimilarityError("Model identifiers must differ")
    if type(model["minimum_challenges"]) is not int or not 1 <= model["minimum_challenges"] <= 128:
        raise ModelOutputSimilarityError("Minimum challenge count is invalid")
    limit = model["minimum_excess_match_basis_points"]
    if type(limit) is not int or not 0 <= limit <= 10_000:
        raise ModelOutputSimilarityError("Excess match limit must be basis points")
    core.boolean(model["comparable_conditions"], "comparable conditions")
    rows = core.bounded_list(model["challenge_matches"], 128, "challenge matches")
    if not rows:
        raise ModelOutputSimilarityError("At least one challenge is required")
    seen: set[str] = set()
    for item in rows:
        row = core.exact(
            item,
            {
                "challenge_id",
                "reference_output_sha256",
                "candidate_output_sha256",
                "control_output_sha256",
            },
            "challenge",
        )
        challenge_id = core.identifier(row["challenge_id"], "challenge ID")
        if challenge_id in seen:
            raise ModelOutputSimilarityError("Duplicate challenge ID")
        seen.add(challenge_id)
        for key in ("reference_output_sha256", "candidate_output_sha256", "control_output_sha256"):
            if type(row[key]) is not str or _DIGEST.fullmatch(row[key]) is None:
                raise ModelOutputSimilarityError("Output digest must be lowercase SHA-256")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = model["challenge_matches"]
    projections = [
        {
            "challenge_id": row["challenge_id"],
            "candidate_matches_reference": row["candidate_output_sha256"]
            == row["reference_output_sha256"],
            "control_matches_reference": row["control_output_sha256"]
            == row["reference_output_sha256"],
        }
        for row in rows
    ]
    candidate_matches = sum(row["candidate_matches_reference"] for row in projections)
    control_matches = sum(row["control_matches_reference"] for row in projections)
    excess = candidate_matches - control_matches
    enough = len(rows) >= model["minimum_challenges"]
    comparable = model["comparable_conditions"]
    exceeds = excess > 0 and excess * 10_000 > model["minimum_excess_match_basis_points"] * len(
        rows
    )
    disposition = (
        "unknown"
        if not enough or not comparable
        else "candidate_declared_output_similarity_excess"
        if exceeds
        else "no_declared_excess_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "challenge_count": len(rows),
        "candidate_match_count": candidate_matches,
        "control_match_count": control_matches,
        "excess_match_numerator": excess,
        "excess_match_denominator": len(rows),
        "challenge_projections": projections,
        "disposition": disposition,
        "candidate_count": int(disposition.startswith("candidate_")),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "model_queried": False,
        "output_content_retained": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Output digests, model identities, pairing and comparability are caller-supplied.",
            "Exact matches depend on identical output normalization and challenge conditions.",
            "Common answers, shared data and control selection can explain excess matches.",
            "A candidate is an offline similarity signal, not proof of model extraction.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MOS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ModelOutputSimilarityReport:
    """Unsigned similarity projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ModelOutputSimilarityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ModelOutputSimilarityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_model_output_similarity(model: Any) -> ModelOutputSimilarityReport:
    return ModelOutputSimilarityReport._owned(_derive(model))


def verify_supplied_model_output_similarity(
    report: Any, *, model: Any
) -> ModelOutputSimilarityReport:
    if type(report) is not ModelOutputSimilarityReport:
        raise ModelOutputSimilarityError("Exact output-similarity wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ModelOutputSimilarityError("Report differs from separate original model")
    return ModelOutputSimilarityReport._owned(expected)


def verify_supplied_model_output_similarity_bytes(
    report_bytes: bytes, *, model: Any
) -> ModelOutputSimilarityReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ModelOutputSimilarityError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ModelOutputSimilarityError("Exported report differs from original replay")
    return ModelOutputSimilarityReport._owned(expected)


def component_fixture() -> dict:
    from hashlib import sha256

    def digest(value: str) -> str:
        return "sha256:" + sha256(value.encode("ascii")).hexdigest()

    return {
        "schema_version": 1,
        "source_id": "synthetic-model-output-comparison",
        "reference_model_id": "reference",
        "candidate_model_id": "candidate",
        "control_model_id": "control",
        "minimum_challenges": 3,
        "minimum_excess_match_basis_points": 2_000,
        "comparable_conditions": True,
        "challenge_matches": [
            {
                "challenge_id": f"challenge-{index}",
                "reference_output_sha256": digest(f"reference-{index}"),
                "candidate_output_sha256": digest(f"reference-{index}"),
                "control_output_sha256": digest(f"control-{index}"),
            }
            for index in range(3)
        ],
    }
