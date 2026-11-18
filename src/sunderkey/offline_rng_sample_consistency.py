"""Project exact repetitions and bit counts in supplied RNG samples offline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_rng_sample_consistency"
PROFILE_ID = "AOE-GE-D22-S08"
CAPABILITY_ID = "army.ge.d22.s08"
VECTOR_ID = "AV-GE-D22-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S08"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d219a4900f0cd4020d915b6f460f2e52b6f1676663c8f758d9eb6fe7b9ff6fe4"
DOMAIN = "sunderkey.offline-rng-sample-consistency.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_SAMPLES = 256
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class RngSampleConsistencyError(ValueError):
    """The supplied samples or their original-model replay are invalid."""


def _model(value: Any) -> tuple[dict, tuple[tuple[str, int], ...], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "sample_sequence_complete", "bit_width", "samples"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RngSampleConsistencyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["sample_sequence_complete"], "sequence completeness")
    width = model["bit_width"]
    if type(width) is not int or width not in {8, 16, 32, 64}:
        raise RngSampleConsistencyError("Bit width must be 8, 16, 32 or 64")
    samples = []
    seen_ids = set()
    for item in core.bounded_list(model["samples"], MAX_SAMPLES, "samples"):
        row = core.exact(item, {"sample_id", "value_hex"}, "sample")
        sample_id = core.identifier(row["sample_id"], "sample ID")
        if sample_id in seen_ids:
            raise RngSampleConsistencyError("Duplicate sample ID")
        seen_ids.add(sample_id)
        encoded = row["value_hex"]
        pattern = r"[0-9a-f]{" + str(width // 4) + r"}"
        if type(encoded) is not str or re.fullmatch(pattern, encoded) is None:
            raise RngSampleConsistencyError("Sample must be lowercase fixed-width hex")
        samples.append((sample_id, int(encoded, 16)))
    if not samples:
        raise RngSampleConsistencyError("At least one sample is required")
    return model, tuple(samples), core.canonical(model)


def _derive(value: Any) -> dict:
    model, samples, source_text = _model(value)
    width = model["bit_width"]
    by_value: dict[int, list[str]] = {}
    for sample_id, sample in samples:
        by_value.setdefault(sample, []).append(sample_id)
    repeated = sorted(
        (sorted(ids) for ids in by_value.values() if len(ids) > 1),
        key=lambda ids: ids[0],
    )
    adjacent_repetitions = sum(
        samples[index][1] == samples[index - 1][1]
        for index in range(1, len(samples))
    )
    one_counts = [sum((sample >> bit) & 1 for _, sample in samples) for bit in range(width)]
    unknown = [] if model["sample_sequence_complete"] else ["supplied_sample_sequence_incomplete"]
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
        "sample_sequence_complete_asserted": model["sample_sequence_complete"],
        "bit_width": width,
        "supplied_sample_count": len(samples),
        "distinct_value_count": len(by_value),
        "repeated_value_sample_id_groups": repeated,
        "adjacent_equal_pair_count": adjacent_repetitions,
        "bit_one_counts_lsb_first": one_counts,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_sample_consistency_projection",
        "source_authenticated": False,
        "generator_observed": False,
        "entropy_estimated": False,
        "randomness_certified": False,
        "cryptographic_weakness_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Samples and sequence completeness are caller-supplied assertions.",
            "Exact repetitions and bit counts do not estimate entropy or certify randomness.",
            "No generator, target, credential or live action is involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RSC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class RngSampleConsistencyReport:
    """Unsigned sample projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RngSampleConsistencyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RngSampleConsistencyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rng_samples(model: Any) -> RngSampleConsistencyReport:
    return RngSampleConsistencyReport._owned(_derive(model))


def verify_supplied_rng_samples(
    report: Any, *, model: Any
) -> RngSampleConsistencyReport:
    if type(report) is not RngSampleConsistencyReport:
        raise RngSampleConsistencyError("Exact sample wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RngSampleConsistencyError("Report differs from separate original model")
    return RngSampleConsistencyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-sample-sequence",
        "sample_sequence_complete": True,
        "bit_width": 8,
        "samples": [
            {"sample_id": "s1", "value_hex": "01"},
            {"sample_id": "s2", "value_hex": "02"},
            {"sample_id": "s3", "value_hex": "01"},
        ],
    }
