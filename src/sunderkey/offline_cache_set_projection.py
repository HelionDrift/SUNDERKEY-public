"""Project synthetic cache-set pressure without timing or leakage claims."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hardware_supplied_cache_set_mapping_projection"
PROFILE_ID = "AOE-GD-D18-S11"
CAPABILITY_ID = "army.gd.d18.s11"
VECTOR_ID = "AV-GD-D18-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S11"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GD-D18-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:56971f4127bbacf570245c1e5db4ad3edafe0316cb115846da12e5f9491dea98"
DOMAIN = "sunderkey.offline-cache-set-projection.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_ACCESSES = 128
ADDRESS = re.compile(r"0x[0-9a-f]{1,12}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class CacheSetProjectionError(ValueError):
    """A supplied cache model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CacheSetProjectionError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise CacheSetProjectionError("Model exceeds byte bound")
    return result


def _power_of_two(value: Any, minimum: int, maximum: int, name: str) -> int:
    if (
        type(value) is not int or not minimum <= value <= maximum
        or value & (value - 1)
    ):
        raise CacheSetProjectionError(f"{name} must be a bounded power of two")
    return value


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "line_size_bytes",
         "set_count", "way_count", "accesses"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CacheSetProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise CacheSetProjectionError("Only synthetic fixtures are accepted")
    line_size = _power_of_two(model["line_size_bytes"], 16, 256, "line size")
    set_count = _power_of_two(model["set_count"], 1, 1024, "set count")
    way_count = model["way_count"]
    if type(way_count) is not int or not 1 <= way_count <= 32:
        raise CacheSetProjectionError("Way count is outside bound")
    accesses = model["accesses"]
    if type(accesses) is not list or not 1 <= len(accesses) <= MAX_ACCESSES:
        raise CacheSetProjectionError("Accesses must be a bounded nonempty array")
    by_set: dict[int, dict] = {}
    for item in accesses:
        row = core.exact(item, {"address_hex"}, "access")
        address = row["address_hex"]
        if type(address) is not str or ADDRESS.fullmatch(address) is None:
            raise CacheSetProjectionError("Address must be bounded lowercase hex")
        line_number = int(address, 16) // line_size
        set_index = line_number % set_count
        tag = line_number // set_count
        slot = by_set.setdefault(set_index, {"access_count": 0, "tags": set()})
        slot["access_count"] += 1
        slot["tags"].add(tag)
    observations = [
        {
            "set_index": index,
            "access_count": by_set[index]["access_count"],
            "distinct_line_count": len(by_set[index]["tags"]),
            "declared_pressure_above_way_count": len(by_set[index]["tags"]) > way_count,
        }
        for index in sorted(by_set)
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
        "synthetic_fixture_asserted": True,
        "line_size_bytes": line_size,
        "set_count": set_count,
        "way_count": way_count,
        "access_count": len(accesses),
        "observed_set_count": len(observations),
        "declared_pressure_set_count": sum(
            row["declared_pressure_above_way_count"] for row in observations
        ),
        "set_observations": observations,
        "candidate_count": 0,
        "uncertainty": [
            "parameterized_mapping_not_measured_hardware",
            "replacement_timing_and_leakage_unassessed",
        ],
        "unknown_count": 2,
        "disposition": "unknown",
        "source_authenticated": False,
        "cache_topology_verified": False,
        "physical_address_mapping_verified": False,
        "cache_replacement_verified": False,
        "timing_or_leakage_observed": False,
        "side_channel_claimed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Addresses and cache parameters are synthetic caller-supplied assertions.",
            "Only line and set arithmetic is performed; addresses and tags are not retained.",
            "Declared pressure is not a measured miss, eviction, timing or leakage result.",
            "Physical address translation, replacement and actual cache topology are unknown.",
            "No process, device, target or provider interaction occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CacheSetProjectionReport:
    """Unsigned mapping projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CacheSetProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CacheSetProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cache_set_projection(model: Any) -> CacheSetProjectionReport:
    return CacheSetProjectionReport._owned(_derive(model))


def verify_supplied_cache_set_projection(
    report: Any, *, model: Any
) -> CacheSetProjectionReport:
    if type(report) is not CacheSetProjectionReport:
        raise CacheSetProjectionError("Exact cache-set wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CacheSetProjectionError("Report differs from separate original model")
    return CacheSetProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-cache-set-projection",
        "synthetic_fixture": True,
        "line_size_bytes": 64,
        "set_count": 64,
        "way_count": 2,
        "accesses": [
            {"address_hex": "0x0"},
            {"address_hex": "0x1000"},
            {"address_hex": "0x2000"},
            {"address_hex": "0x40"},
        ],
    }
