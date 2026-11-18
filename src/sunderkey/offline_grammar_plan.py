"""Count bounded finite supplied grammar derivations without generating traffic."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_finite_grammar_plan"
PROFILE_ID = "AOE-GE-D21-S14"
CAPABILITY_ID = "army.ge.d21.s14"
VECTOR_ID = "AV-GE-D21-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S14"
WAVE_ID = "IW2-026"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:57206f5cc1c033837b695441af176b8fa62a8a0551761aa747b83ddc9b06c663"
DOMAIN = "sunderkey.offline-finite-grammar-plan.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_RULES = 32
MAX_ALTERNATIVES = 16
MAX_TOKENS = 8
MAX_DERIVATIONS = 1_000_000
MAX_EXPANSION_BYTES = 4096
LITERAL = re.compile(r"[A-Za-z0-9_-]{0,32}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class FiniteGrammarPlanError(ValueError):
    """The finite grammar model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, list[list[dict]]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "start_symbol", "grammar_complete", "rules"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FiniteGrammarPlanError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    start = core.identifier(model["start_symbol"], "start symbol")
    core.boolean(model["grammar_complete"], "grammar completeness")
    rules: dict[str, list[list[dict]]] = {}
    for item in core.bounded_list(model["rules"], MAX_RULES, "rules"):
        row = core.exact(item, {"symbol_id", "alternatives"}, "rule")
        symbol = core.identifier(row["symbol_id"], "symbol ID")
        if symbol in rules:
            raise FiniteGrammarPlanError("Duplicate grammar symbol")
        alternatives = core.bounded_list(
            row["alternatives"], MAX_ALTERNATIVES, "alternatives"
        )
        if not alternatives:
            raise FiniteGrammarPlanError("Rule needs at least one alternative")
        for alternative in alternatives:
            for token in core.bounded_list(alternative, MAX_TOKENS, "tokens"):
                if type(token) is not dict or len(token) != 1:
                    raise FiniteGrammarPlanError("Token must be one literal or reference")
                if "literal" in token:
                    if type(token["literal"]) is not str or (
                        LITERAL.fullmatch(token["literal"]) is None
                    ):
                        raise FiniteGrammarPlanError("Literal must be bounded inert ASCII")
                elif "ref" in token:
                    core.identifier(token["ref"], "symbol reference")
                else:
                    raise FiniteGrammarPlanError("Unsupported grammar token")
        rules[symbol] = alternatives
    if start not in rules:
        raise FiniteGrammarPlanError("Start symbol has no rule")
    for alternatives in rules.values():
        for alternative in alternatives:
            for token in alternative:
                if "ref" in token and token["ref"] not in rules:
                    raise FiniteGrammarPlanError("Unresolved grammar reference")
    return model, rules, core.canonical(model)


def _derive(value: Any) -> dict:
    model, rules, source_text = _model(value)
    visiting: set[str] = set()
    computed: dict[str, tuple[int, int, int]] = {}

    def evaluate(symbol: str) -> tuple[int, int, int]:
        if symbol in computed:
            return computed[symbol]
        if symbol in visiting:
            raise FiniteGrammarPlanError("Recursive grammar is unsupported")
        visiting.add(symbol)
        count = 0
        minimum: int | None = None
        maximum = 0
        for alternative in rules[symbol]:
            alt_count = 1
            alt_min = 0
            alt_max = 0
            for token in alternative:
                if "literal" in token:
                    size = len(token["literal"].encode("ascii"))
                    part_count, part_min, part_max = 1, size, size
                else:
                    part_count, part_min, part_max = evaluate(token["ref"])
                alt_count *= part_count
                alt_min += part_min
                alt_max += part_max
                if alt_count > MAX_DERIVATIONS or alt_max > MAX_EXPANSION_BYTES:
                    raise FiniteGrammarPlanError("Grammar expansion bound exceeded")
            count += alt_count
            minimum = alt_min if minimum is None else min(minimum, alt_min)
            maximum = max(maximum, alt_max)
            if count > MAX_DERIVATIONS or maximum > MAX_EXPANSION_BYTES:
                raise FiniteGrammarPlanError("Grammar expansion bound exceeded")
        visiting.remove(symbol)
        result = count, minimum if minimum is not None else 0, maximum
        computed[symbol] = result
        return result

    start_count, start_min, start_max = evaluate(model["start_symbol"])
    reachable_count = len(computed)
    unreachable = sorted(set(rules) - set(computed))
    for symbol in unreachable:
        evaluate(symbol)
    uncertainty = []
    if not model["grammar_complete"]:
        uncertainty.append("supplied_grammar_incomplete")
    if unreachable:
        uncertainty.append("unreachable_supplied_rules")
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
        "start_symbol": model["start_symbol"],
        "grammar_complete_asserted": model["grammar_complete"],
        "supplied_rule_count": len(rules),
        "reachable_rule_count": reachable_count,
        "unreachable_rule_ids": unreachable,
        "derivation_count": start_count,
        "minimum_expansion_bytes": start_min,
        "maximum_expansion_bytes": start_max,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "supplied_finite_grammar_plan" if not uncertainty else "unknown",
        "source_authenticated": False,
        "grammar_semantics_verified": False,
        "payload_generated": False,
        "target_executed": False,
        "protocol_behavior_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The grammar and its completeness are supplied assertions.",
            "Only finite acyclic alternatives with inert ASCII literals are counted.",
            "No payload is emitted and no protocol implementation is contacted.",
            "A derivation count is not fuzzing coverage or a finding.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="FGP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class FiniteGrammarPlanReport:
    """Unsigned grammar count requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FiniteGrammarPlanError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FiniteGrammarPlanReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_finite_grammar(model: Any) -> FiniteGrammarPlanReport:
    return FiniteGrammarPlanReport._owned(_derive(model))


def verify_supplied_finite_grammar(
    report: Any, *, model: Any
) -> FiniteGrammarPlanReport:
    if type(report) is not FiniteGrammarPlanReport:
        raise FiniteGrammarPlanError("Exact grammar wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise FiniteGrammarPlanError("Report differs from separate original model")
    return FiniteGrammarPlanReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-finite-grammar",
        "start_symbol": "packet",
        "grammar_complete": True,
        "rules": [
            {
                "symbol_id": "packet",
                "alternatives": [[{"literal": "HEAD"}, {"ref": "body"}]],
            },
            {
                "symbol_id": "body",
                "alternatives": [[{"literal": "A"}], [{"literal": "BC"}]],
            },
        ],
    }
