"""Compare synthetic receive-only RF metadata with supplied band labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "telecom_supplied_rf_receive_policy_projection"
PROFILE_ID = "AOE-GC-D13-S10"
CAPABILITY_ID = "army.gc.d13.s10"
VECTOR_ID = "AV-GC-D13-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S10"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:49f3912d98ac77f1c647f003852e52a060c8a2176c148ed676bb5e50b837ea66"
DOMAIN = "sunderkey.offline-rf-receive-policy.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class RfReceivePolicyError(ValueError):
    """A supplied receive-policy model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_band_labels", "capture_declarations",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RfReceivePolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise RfReceivePolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved band label")
        for item in core.bounded_list(model["approved_band_labels"], 32, "approved bands")
    ]
    if len(approved) != len(set(approved)):
        raise RfReceivePolicyError("Duplicate approved band label")
    captures = core.bounded_list(model["capture_declarations"], 64, "captures")
    if not captures:
        raise RfReceivePolicyError("At least one capture declaration is required")
    rows = []
    seen = set()
    for item in captures:
        row = core.exact(item, {
            "capture_ref", "band_label", "receive_only_declared", "authorization_ref",
        }, "capture declaration")
        capture_ref = core.identifier(row["capture_ref"], "opaque capture reference")
        if capture_ref in seen:
            raise RfReceivePolicyError("Duplicate capture reference")
        seen.add(capture_ref)
        band_label = core.identifier(row["band_label"], "band label")
        authorization_ref = core.identifier(row["authorization_ref"], "authorization reference")
        receive_only = core.boolean(row["receive_only_declared"], "receive-only declaration")
        rows.append({
            "capture_ref": capture_ref,
            "band_label": band_label,
            "authorization_ref": authorization_ref,
            "receive_only_declared": receive_only,
            "outside_supplied_approved_band_labels": band_label not in approved,
        })
    rows.sort(key=lambda row: row["capture_ref"])
    deviations = [
        row["capture_ref"] for row in rows if row["outside_supplied_approved_band_labels"]
    ]
    unknown = [] if complete else ["supplied_capture_inventory_incomplete"]
    if any(not row["receive_only_declared"] for row in rows):
        unknown.append("non_receive_only_declaration_requires_separate_authority")
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "capture_projections": rows,
        "outside_supplied_band_capture_refs": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_rf_receive_policy_projection",
        "source_authenticated": False,
        "receiver_connected": False,
        "transmitter_connected": False,
        "rf_signal_observed": False,
        "subscriber_data_accessed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Band and capture labels, authorization references, and completeness are assertions.",
            "No frequencies, signal bytes, subscriber data, or transmit parameters are accepted.",
            "No radio device, signal, network, credential, or target is accessed.",
            "A mismatch does not prove unlawful activity, exploitation, or impact.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RFP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class RfReceivePolicyReport:
    """Unsigned receive-policy projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RfReceivePolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RfReceivePolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rf_receive_policy(model: Any) -> RfReceivePolicyReport:
    return RfReceivePolicyReport._owned(_derive(model))


def verify_supplied_rf_receive_policy(report: Any, *, model: Any) -> RfReceivePolicyReport:
    if type(report) is not RfReceivePolicyReport:
        raise RfReceivePolicyError("Exact RF receive-policy wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RfReceivePolicyError("Report differs from separate original model")
    return RfReceivePolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-rf-capture-declarations",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_band_labels": ["band-a"],
        "capture_declarations": [{
            "capture_ref": "capture-opaque-a", "band_label": "band-b",
            "receive_only_declared": True, "authorization_ref": "authorization-opaque-a",
        }],
    }
