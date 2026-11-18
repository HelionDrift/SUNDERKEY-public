"""Project exact timing summaries from two caller-supplied sample groups."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_side_channel_timing_projection"
PROFILE_ID = "AOE-GE-D22-S09"
CAPABILITY_ID = "army.ge.d22.s09"
VECTOR_ID = "AV-GE-D22-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S09"
WAVE_ID = "IW2-022"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:701f5375f828ff4fdc185f61dd476fc08ec8543b86efb3aec340500cccf86af5"
DOMAIN = "sunderkey.offline-side-channel-timing.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_SAMPLES = 256
MAX_DURATION_NS = 1_000_000_000
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class SideChannelTimingProjectionError(ValueError):
    """The supplied timing groups or their original-model replay are invalid."""


def _model(value: Any) -> tuple[dict, dict[str, tuple[int, ...]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "sample_inventory_complete", "groups"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SideChannelTimingProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["sample_inventory_complete"], "inventory completeness")
    groups = {}
    for item in core.bounded_list(model["groups"], 2, "groups"):
        row = core.exact(item, {"group_id", "samples"}, "group")
        group_id = core.choice(row["group_id"], {"control", "variant"}, "group ID")
        if group_id in groups:
            raise SideChannelTimingProjectionError("Duplicate group ID")
        durations = []
        seen_ids = set()
        for sample in core.bounded_list(row["samples"], MAX_SAMPLES, "samples"):
            record = core.exact(sample, {"sample_id", "duration_ns"}, "sample")
            sample_id = core.identifier(record["sample_id"], "sample ID")
            if sample_id in seen_ids:
                raise SideChannelTimingProjectionError("Duplicate sample ID within group")
            seen_ids.add(sample_id)
            duration = record["duration_ns"]
            if type(duration) is not int or not 0 <= duration <= MAX_DURATION_NS:
                raise SideChannelTimingProjectionError("Duration is outside bounded range")
            durations.append(duration)
        if len(durations) < 2:
            raise SideChannelTimingProjectionError("Each group requires at least two samples")
        groups[group_id] = tuple(sorted(durations))
    if set(groups) != {"control", "variant"}:
        raise SideChannelTimingProjectionError("Control and variant groups are required")
    return model, groups, core.canonical(model)


def _median_twice(values: tuple[int, ...]) -> int:
    middle = len(values) // 2
    if len(values) % 2:
        return 2 * values[middle]
    return values[middle - 1] + values[middle]


def _derive(value: Any) -> dict:
    model, groups, source_text = _model(value)
    rows = [
        {
            "group_id": group_id,
            "sample_count": len(values),
            "distinct_duration_count": len(set(values)),
            "minimum_duration_ns": values[0],
            "maximum_duration_ns": values[-1],
            "median_duration_ns_times_two": _median_twice(values),
        }
        for group_id, values in sorted(groups.items())
    ]
    control = groups["control"]
    variant = groups["variant"]
    unknown = [] if model["sample_inventory_complete"] else [
        "supplied_sample_inventory_incomplete"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "sample_inventory_complete_asserted": model["sample_inventory_complete"],
        "groups": rows,
        "median_variant_minus_control_ns_times_two": (
            _median_twice(variant) - _median_twice(control)
        ),
        "duration_ranges_overlap_inclusive": (
            max(control[0], variant[0]) <= min(control[-1], variant[-1])
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_timing_summary_projection",
        "source_authenticated": False,
        "measurement_conditions_verified": False,
        "statistical_significance_claimed": False,
        "secret_dependent_leakage_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Durations, group labels and inventory completeness are supplied assertions.",
            "Median and range summaries do not establish statistical significance or leakage.",
            "No secret, implementation, device, process or target is observed.",
            "The projection grants no finding, qualification or action authority.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SCT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SideChannelTimingProjectionReport:
    """Unsigned timing projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SideChannelTimingProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SideChannelTimingProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_side_channel_timings(model: Any) -> SideChannelTimingProjectionReport:
    return SideChannelTimingProjectionReport._owned(_derive(model))


def verify_supplied_side_channel_timings(
    report: Any, *, model: Any
) -> SideChannelTimingProjectionReport:
    if type(report) is not SideChannelTimingProjectionReport:
        raise SideChannelTimingProjectionError("Exact timing wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SideChannelTimingProjectionError("Report differs from separate original model")
    return SideChannelTimingProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-timing-groups",
        "sample_inventory_complete": True,
        "groups": [
            {
                "group_id": "control",
                "samples": [
                    {"sample_id": "c1", "duration_ns": 10},
                    {"sample_id": "c2", "duration_ns": 12},
                    {"sample_id": "c3", "duration_ns": 14},
                ],
            },
            {
                "group_id": "variant",
                "samples": [
                    {"sample_id": "v1", "duration_ns": 12},
                    {"sample_id": "v2", "duration_ns": 14},
                    {"sample_id": "v3", "duration_ns": 16},
                ],
            },
        ],
    }
