"""Compare caller-supplied NTLM source and target control declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_ntlm_control_pairs"
PROFILE_ID = "AOE-GC-D11-S03"
CAPABILITY_ID = "army.gc.d11.s03"
VECTOR_ID = "AV-GC-D11-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4a1c38993bbac42d87d928abd424f2f17f8dfba878534d3a7d162bac09eae8ea"
DOMAIN = "sunderkey.offline-ntlm-control-pairs.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
REF = re.compile(r"(?:source|target):sha256:[0-9a-f]{64}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class NtlmControlPairsError(ValueError):
    """A control declaration or replay comparison was refused."""


def _ref(value: Any, kind: str) -> str:
    if type(value) is not str or REF.fullmatch(value) is None or not value.startswith(kind + ":"):
        raise NtlmControlPairsError(f"{kind} reference must be an opaque digest")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "pairs"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise NtlmControlPairsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"require_target_signing", "require_target_epa", "require_channel_binding"},
        "policy",
    )
    for key in policy:
        core.boolean(policy[key], key)
    pairs = core.bounded_list(model["pairs"], 64, "pairs")
    if not pairs:
        raise NtlmControlPairsError("At least one supplied pair is required")
    pair_ids: set[str] = set()
    for item in pairs:
        pair = core.exact(
            item,
            {"pair_id", "source_ref", "target_ref", "source_ntlm_offered",
             "target_ntlm_accepted", "target_signing_required", "target_epa_required",
             "channel_binding_declared"},
            "pair",
        )
        pair_id = core.identifier(pair["pair_id"], "pair ID")
        if pair_id in pair_ids:
            raise NtlmControlPairsError("Duplicate pair ID")
        pair_ids.add(pair_id)
        _ref(pair["source_ref"], "source")
        _ref(pair["target_ref"], "target")
        for key in (
            "source_ntlm_offered", "target_ntlm_accepted", "target_signing_required",
            "target_epa_required", "channel_binding_declared",
        ):
            core.boolean(pair[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    policy = model["policy"]
    rows: list[dict] = []
    candidates: list[dict] = []
    for pair in model["pairs"]:
        declared_exchange = pair["source_ntlm_offered"] and pair["target_ntlm_accepted"]
        issues: list[str] = []
        if declared_exchange:
            if policy["require_target_signing"] and not pair["target_signing_required"]:
                issues.append("required_target_signing_not_declared")
            if policy["require_target_epa"] and not pair["target_epa_required"]:
                issues.append("required_target_epa_not_declared")
            if policy["require_channel_binding"] and not pair["channel_binding_declared"]:
                issues.append("required_channel_binding_not_declared")
        row = {
            "pair_id": pair["pair_id"],
            "declared_ntlm_exchange": declared_exchange,
            "policy_issues": issues if complete and declared_exchange else None,
            "row_disposition": (
                "unknown_incomplete_inventory" if not complete else
                "evaluated" if declared_exchange else "not_applicable"
            ),
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"pair_id": pair["pair_id"], "policy_issues": issues})
    applicable_count = sum(row["declared_ntlm_exchange"] for row in rows)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "pair_count": len(rows),
        "applicable_pair_count": applicable_count,
        "rows": rows,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "unknown_count": len(rows) if not complete else 0,
        "disposition": "unknown" if not complete else (
            "no_applicable_supplied_pairs" if not applicable_count else
            "candidate_supplied_control_gap" if candidates else "supplied_controls_match"
        ),
        "source_or_target_authenticated": False,
        "ntlm_exchange_observed": False,
        "coercion_or_relay_attempted": False,
        "relay_feasibility_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Pair endpoints, NTLM use, controls, policy and completeness are caller-supplied.",
            "Control-label mismatches do not establish NTLM relay or coercion feasibility.",
            "No authentication, service, credential, network or target interaction occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="NCP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class NtlmControlPairsReport:
    """Unsigned control projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise NtlmControlPairsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> NtlmControlPairsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ntlm_control_pairs(model: Any) -> NtlmControlPairsReport:
    return NtlmControlPairsReport._owned(_derive(model))


def verify_supplied_ntlm_control_pairs(
    report: Any, *, model: Any
) -> NtlmControlPairsReport:
    if type(report) is not NtlmControlPairsReport:
        raise NtlmControlPairsError("Exact NTLM control-pairs wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise NtlmControlPairsError("Report differs from original-model replay")
    return NtlmControlPairsReport._owned(expected)


def verify_supplied_ntlm_control_pairs_bytes(
    report_bytes: bytes, *, model: Any
) -> NtlmControlPairsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise NtlmControlPairsError("Exported report differs from original-model replay")
    return NtlmControlPairsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ntlm-control-pairs",
        "inventory_complete": True,
        "policy": {
            "require_target_signing": True,
            "require_target_epa": True,
            "require_channel_binding": True,
        },
        "pairs": [
            {"pair_id": "pair-a", "source_ref": "source:sha256:" + "a" * 64,
             "target_ref": "target:sha256:" + "b" * 64,
             "source_ntlm_offered": True, "target_ntlm_accepted": True,
             "target_signing_required": False, "target_epa_required": False,
             "channel_binding_declared": False},
        ],
    }
