"""Compare bounded synthetic hardware traces without claiming physical leakage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_trace_difference_projection"
PROFILE_ID = "AOE-GD-D18-S08"
CAPABILITY_ID = "army.gd.d18.s08"
VECTOR_ID = "AV-GD-D18-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S08"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:1e6f9c6168f49e519ac3b5966ae0398dc871a8bcb44ded86c49d92ed9ede06f2"
DOMAIN = "sunderkey.offline-hardware-trace-difference.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_TRACES_PER_GROUP = 32
MAX_SAMPLES_PER_TRACE = 64
MAX_ABSOLUTE_SAMPLE_VALUE = 1_000_000
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class HardwareTraceDifferenceError(ValueError):
    """A supplied trace model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture", "modality",
            "sample_inventory_complete", "aligned_trace_asserted", "groups",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HardwareTraceDifferenceError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise HardwareTraceDifferenceError("Only synthetic fixtures are accepted")
    modality = core.choice(model["modality"], {"power", "em", "timing"}, "modality")
    inventory_complete = core.boolean(
        model["sample_inventory_complete"], "sample inventory completeness"
    )
    aligned = core.boolean(model["aligned_trace_asserted"], "trace alignment")
    groups: dict[str, tuple[tuple[int, ...], ...]] = {}
    trace_ids: set[str] = set()
    trace_length = None
    for item in core.bounded_list(model["groups"], 2, "groups"):
        row = core.exact(item, {"group_id", "traces"}, "group")
        group_id = core.choice(row["group_id"], {"control", "variant"}, "group ID")
        if group_id in groups:
            raise HardwareTraceDifferenceError("Duplicate group ID")
        traces = []
        for trace in core.bounded_list(
            row["traces"], MAX_TRACES_PER_GROUP, "traces"
        ):
            record = core.exact(trace, {"trace_id", "sample_values"}, "trace")
            trace_id = core.identifier(record["trace_id"], "trace ID")
            if trace_id in trace_ids:
                raise HardwareTraceDifferenceError("Duplicate trace ID")
            trace_ids.add(trace_id)
            values = core.bounded_list(
                record["sample_values"], MAX_SAMPLES_PER_TRACE, "sample values"
            )
            if len(values) < 4:
                raise HardwareTraceDifferenceError("At least four samples per trace")
            if trace_length is None:
                trace_length = len(values)
            elif len(values) != trace_length:
                raise HardwareTraceDifferenceError("All trace lengths must match")
            if any(
                type(sample) is not int
                or abs(sample) > MAX_ABSOLUTE_SAMPLE_VALUE
                for sample in values
            ):
                raise HardwareTraceDifferenceError("Sample value is outside bound")
            traces.append(tuple(values))
        if len(traces) < 2:
            raise HardwareTraceDifferenceError("At least two traces per group")
        groups[group_id] = tuple(traces)
    if set(groups) != {"control", "variant"}:
        raise HardwareTraceDifferenceError("Control and variant groups are required")
    control = groups["control"]
    variant = groups["variant"]
    count_control = len(control)
    count_variant = len(variant)
    difference_numerators = []
    for index in range(trace_length):
        control_sum = sum(trace[index] for trace in control)
        variant_sum = sum(trace[index] for trace in variant)
        difference_numerators.append(
            variant_sum * count_control - control_sum * count_variant
        )
    peak_index = max(
        range(trace_length), key=lambda index: (abs(difference_numerators[index]), -index)
    )
    uncertainty = []
    if not inventory_complete:
        uncertainty.append("supplied_sample_inventory_incomplete")
    if not aligned:
        uncertainty.append("trace_alignment_not_asserted")
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
        "modality_asserted": modality,
        "sample_inventory_complete_asserted": inventory_complete,
        "aligned_trace_asserted": aligned,
        "sample_count_per_trace": trace_length,
        "trace_counts": {group_id: len(traces) for group_id, traces in sorted(groups.items())},
        "mean_difference_numerator_by_index": difference_numerators,
        "mean_difference_denominator": count_control * count_variant,
        "peak_absolute_difference_index": peak_index,
        "peak_absolute_difference_numerator": abs(difference_numerators[peak_index]),
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_trace_difference_projection",
        "source_authenticated": False,
        "instrument_calibration_verified": False,
        "trace_alignment_verified": False,
        "statistical_significance_claimed": False,
        "physical_leakage_claimed": False,
        "secret_dependent_behavior_claimed": False,
        "device_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Traces, modality, inventory and alignment are caller-supplied assertions.",
            "Exact mean differences are descriptive, not a leakage or significance test.",
            "No instrument, device, physical signal or secret is observed.",
            "No acquisition, execution, target interaction or qualification occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HTD-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class HardwareTraceDifferenceReport:
    """Unsigned trace projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HardwareTraceDifferenceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HardwareTraceDifferenceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hardware_traces(model: Any) -> HardwareTraceDifferenceReport:
    return HardwareTraceDifferenceReport._owned(_derive(model))


def verify_supplied_hardware_traces(
    report: Any, *, model: Any
) -> HardwareTraceDifferenceReport:
    if type(report) is not HardwareTraceDifferenceReport:
        raise HardwareTraceDifferenceError("Exact trace wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HardwareTraceDifferenceError("Report differs from separate original model")
    return HardwareTraceDifferenceReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-hardware-traces",
        "synthetic_fixture": True,
        "modality": "power",
        "sample_inventory_complete": True,
        "aligned_trace_asserted": True,
        "groups": [
            {
                "group_id": "control",
                "traces": [
                    {"trace_id": "c1", "sample_values": [1, 2, 3, 4]},
                    {"trace_id": "c2", "sample_values": [2, 3, 4, 5]},
                ],
            },
            {
                "group_id": "variant",
                "traces": [
                    {"trace_id": "v1", "sample_values": [1, 4, 3, 4]},
                    {"trace_id": "v2", "sample_values": [2, 5, 4, 5]},
                ],
            },
        ],
    }
