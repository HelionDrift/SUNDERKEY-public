"""Measure supplied synthetic PE32+ section bytes without unpacking code."""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_pe32_layout_analysis import analyze_supplied_pe32plus_layout

COMPONENT_ID = "exploit_supplied_pe_packing_triage"
PROFILE_ID = "AOE-GE-D21-S20"
CAPABILITY_ID = "army.ge.d21.s20"
VECTOR_ID = "AV-GE-D21-S20-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S20"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7d179001e55e86f3afd53f9c4e963e25bc240f2f9b65d402143ffd69b4df7578"
DOMAIN = "sunderkey.offline-pe-packing-triage.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 131_072
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PePackingTriageError(ValueError):
    """A supplied PE triage model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PePackingTriageError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise PePackingTriageError("Model exceeds byte bound")
    return result


def _entropy_millibits(data: bytes) -> int:
    if not data:
        return 0
    counts = Counter(data)
    total = len(data)
    bits = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(bits * 1_000)


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "pe_layout_model"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PePackingTriageError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PePackingTriageError("Only synthetic fixtures are accepted")
    layout_model = model["pe_layout_model"]
    if type(layout_model) is not dict:
        raise PePackingTriageError("PE layout model is required")
    layout = analyze_supplied_pe32plus_layout(layout_model).to_dict()
    data = base64.b64decode(layout_model["pe_file_base64"], validate=True)
    if len(data) != layout["source_file_bytes"]:
        raise PePackingTriageError("PE source length differs from layout")
    sections = []
    for section in layout["section_observations"]:
        offset = section["raw_file_offset"]
        size = section["raw_file_bytes"]
        end = section["raw_file_end"]
        if size <= 0 or end is None or end != offset + size or end > len(data):
            raise PePackingTriageError("Only bounded materialized raw sections are accepted")
        section_bytes = data[offset:end]
        sections.append({
            "section_index": section["section_index"],
            "raw_file_bytes": size,
            "byte_entropy_millibits": _entropy_millibits(section_bytes),
            "raw_bytes_sha256": "sha256:" + hashlib.sha256(section_bytes).hexdigest(),
        })
    if not sections:
        raise PePackingTriageError("At least one materialized section is required")
    trailing = layout["trailing_file_extent"]
    trailing_bytes = b"" if trailing is None else data[
        trailing["file_offset"]:trailing["file_offset"] + trailing["bytes"]
    ]
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "base_pe_analysis_id": layout["analysis_id"],
        "base_pe_analysis_sha256": layout["analysis_sha256"],
        "source_file_sha256": layout["source_file_sha256"],
        "synthetic_fixture_asserted": True,
        "section_count": len(sections),
        "section_byte_distribution": sections,
        "trailing_file_bytes": len(trailing_bytes),
        "trailing_file_sha256": (
            "sha256:" + hashlib.sha256(trailing_bytes).hexdigest()
            if trailing_bytes else None
        ),
        "layout_status": layout["analysis_status"],
        "packed_code_verified": False,
        "malware_identity_verified": False,
        "configuration_extracted": False,
        "anti_analysis_behavior_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "section_distribution_not_packer_proof",
            "trailing_bytes_semantics_unverified",
            "malware_identity_and_behavior_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only synthetic supplied PE32+ bytes are measured through the existing layout parser.",
            "Entropy and trailing bytes are descriptive and do not prove packing or malware.",
            "No code is unpacked, deobfuscated, loaded, or executed.",
            "No configuration or anti-analysis behavior is inferred.",
            "No endpoint, process, or target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PPT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PePackingTriageReport:
    """Unsigned byte-distribution projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PePackingTriageError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PePackingTriageReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pe_packing_triage(model: Any) -> PePackingTriageReport:
    return PePackingTriageReport._owned(_derive(model))


def verify_supplied_pe_packing_triage(report: Any, *, model: Any) -> PePackingTriageReport:
    if type(report) is not PePackingTriageReport:
        raise PePackingTriageError("Exact PE triage wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PePackingTriageError("Report differs from separate original model")
    return PePackingTriageReport._owned(expected)


def component_fixture() -> dict:
    from .offline_pe32_layout_analysis import component_fixture as pe_fixture

    pe_model = pe_fixture()
    data = bytearray(base64.b64decode(pe_model["pe_file_base64"]))
    data.extend(b"synthetic-trailing-data")
    pe_model["pe_file_base64"] = base64.b64encode(data).decode("ascii")
    return {
        "schema_version": 1,
        "source_id": "synthetic-pe-packing-triage",
        "synthetic_fixture": True,
        "pe_layout_model": pe_model,
    }
