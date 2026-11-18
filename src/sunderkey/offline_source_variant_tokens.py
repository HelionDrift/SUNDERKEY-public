"""Compare bounded supplied function-token inventories without parsing source."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_source_variant_tokens"
PROFILE_ID = "AOE-GE-D21-S17"
CAPABILITY_ID = "army.ge.d21.s17"
VECTOR_ID = "AV-GE-D21-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S17"
WAVE_ID = "IW2-029"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:13973bec9f561118178c8e6e46b1543b1615f86b3b7eb534f99d9423e5c88a6b"
DOMAIN = "sunderkey.offline-source-variant-tokens.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_FUNCTIONS = 32
MAX_TOKENS = 64
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class SourceVariantTokensError(ValueError):
    """The supplied token inventory or original-model replay is invalid."""


def _inventory(value: Any, label: str) -> dict[str, tuple[str, ...]]:
    result = {}
    for item in core.bounded_list(value, MAX_FUNCTIONS, label):
        row = core.exact(item, {"function_id", "tokens"}, "function")
        function_id = core.identifier(row["function_id"], "function ID")
        if function_id in result:
            raise SourceVariantTokensError("Duplicate function ID")
        tokens = tuple(
            core.identifier(token, "token")
            for token in core.bounded_list(row["tokens"], MAX_TOKENS, "tokens")
        )
        if not tokens:
            raise SourceVariantTokensError("Function token list must be nonempty")
        result[function_id] = tokens
    if not result:
        raise SourceVariantTokensError("Function inventory must be nonempty")
    return result


def _model(value: Any) -> tuple[dict, dict, dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "left_source_id", "right_source_id",
            "left_inventory_complete", "right_inventory_complete",
            "left_functions", "right_functions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SourceVariantTokensError("Unsupported model version")
    left_id = core.identifier(model["left_source_id"], "left source ID")
    right_id = core.identifier(model["right_source_id"], "right source ID")
    if left_id == right_id:
        raise SourceVariantTokensError("Source IDs must differ")
    core.boolean(model["left_inventory_complete"], "left inventory completeness")
    core.boolean(model["right_inventory_complete"], "right inventory completeness")
    left = _inventory(model["left_functions"], "left functions")
    right = _inventory(model["right_functions"], "right functions")
    return model, left, right, core.canonical(model)


def _lcs_count(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    previous = [0] * (len(right) + 1)
    for left_token in left:
        current = [0]
        for column, right_token in enumerate(right, start=1):
            current.append(
                previous[column - 1] + 1
                if left_token == right_token
                else max(current[-1], previous[column])
            )
        previous = current
    return previous[-1]


def _derive(value: Any) -> dict:
    model, left, right, source_text = _model(value)
    common = set(left) & set(right)
    modified = []
    unchanged = []
    for function_id in sorted(common):
        before, after = left[function_id], right[function_id]
        if before == after:
            unchanged.append(function_id)
            continue
        lcs = _lcs_count(before, after)
        modified.append({
            "function_id": function_id,
            "left_token_count": len(before),
            "right_token_count": len(after),
            "common_subsequence_token_count": lcs,
            "token_similarity_milli": 2 * lcs * 1000 // (len(before) + len(after)),
        })
    uncertainty = []
    if not model["left_inventory_complete"]:
        uncertainty.append("supplied_left_inventory_incomplete")
    if not model["right_inventory_complete"]:
        uncertainty.append("supplied_right_inventory_incomplete")
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
        "left_source_id": model["left_source_id"],
        "right_source_id": model["right_source_id"],
        "left_inventory_complete_asserted": model["left_inventory_complete"],
        "right_inventory_complete_asserted": model["right_inventory_complete"],
        "left_function_count": len(left),
        "right_function_count": len(right),
        "added_function_ids": sorted(set(right) - set(left)),
        "removed_function_ids": sorted(set(left) - set(right)),
        "unchanged_function_ids": unchanged,
        "modified_functions": modified,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_token_variant_projection",
        "source_authenticated": False,
        "source_files_read": False,
        "parser_semantics_verified": False,
        "behavioral_equivalence_verified": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Function identities and token streams are supplied assertions.",
            "Token subsequence similarity does not establish semantic equivalence.",
            "No source parser, compiler, program, or target is invoked.",
            "Added or changed functions are not vulnerabilities or findings.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SVT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SourceVariantTokensReport:
    """Unsigned source-token comparison requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SourceVariantTokensError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SourceVariantTokensReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_source_variant_tokens(model: Any) -> SourceVariantTokensReport:
    return SourceVariantTokensReport._owned(_derive(model))


def verify_supplied_source_variant_tokens(
    report: Any, *, model: Any
) -> SourceVariantTokensReport:
    if type(report) is not SourceVariantTokensReport:
        raise SourceVariantTokensError("Exact token-variant wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SourceVariantTokensError("Report differs from separate original model")
    return SourceVariantTokensReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "left_source_id": "synthetic-base",
        "right_source_id": "synthetic-variant",
        "left_inventory_complete": True,
        "right_inventory_complete": True,
        "left_functions": [
            {"function_id": "parse", "tokens": ["load", "check", "return"]},
            {"function_id": "old", "tokens": ["return"]},
            {"function_id": "same", "tokens": ["read", "return"]},
        ],
        "right_functions": [
            {"function_id": "parse", "tokens": ["load", "guard", "check", "return"]},
            {"function_id": "new", "tokens": ["check", "return"]},
            {"function_id": "same", "tokens": ["read", "return"]},
        ],
    }
