"""Compare reduced, supplied build-run metadata without invoking a build."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "build_supplied_reproducibility_projection"
PROFILE_ID = "AOE-GC-D17-S09"
CAPABILITY_ID = "army.gc.d17.s09"
VECTOR_ID = "AV-GC-D17-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S09"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b29876c18509fc921bfb9365bae2a293a0bdf5adc8fd5045089c6b50a18f8d9e"
DOMAIN = "sunderkey.offline-build-reproducibility.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_RUNS = 32
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class BuildReproducibilityError(ValueError):
    """The reduced declaration or original-source replay is invalid."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise BuildReproducibilityError(f"{label} must be a canonical SHA-256 digest")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "runs"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BuildReproducibilityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["runs"], MAX_RUNS, "runs"):
        run = core.exact(row, {
            "run_id", "source_sha256", "definition_sha256", "toolchain_sha256",
            "inputs_sha256", "artifact_sha256", "declared_inputs_complete",
            "sandboxed", "network_allowed",
        }, "run")
        run_id = core.identifier(run["run_id"], "run ID")
        if run_id in seen:
            raise BuildReproducibilityError("Duplicate run ID")
        seen.add(run_id)
        for field in (
            "source_sha256", "definition_sha256", "toolchain_sha256",
            "inputs_sha256", "artifact_sha256",
        ):
            _digest(run[field], field)
        for field in ("declared_inputs_complete", "sandboxed", "network_allowed"):
            core.boolean(run[field], field)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    runs = sorted(model["runs"], key=lambda row: row["run_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    groups: dict[tuple[str, ...], list[dict]] = {}
    for run in runs:
        run_id = run["run_id"]
        if not run["declared_inputs_complete"]:
            uncertainty.append({"issue": "declared_inputs_incomplete", "run_id": run_id})
        if not run["sandboxed"]:
            signals.append({"issue": "declared_unsandboxed_build", "run_id": run_id})
        if run["network_allowed"]:
            signals.append({"issue": "declared_build_network_access", "run_id": run_id})
        key = tuple(run[field] for field in (
            "source_sha256", "definition_sha256", "toolchain_sha256", "inputs_sha256",
        ))
        groups.setdefault(key, []).append(run)
    for members in groups.values():
        if len(members) < 2 or not all(
            row["declared_inputs_complete"] for row in members
        ):
            continue
        if len({row["artifact_sha256"] for row in members}) > 1:
            for row in members:
                signals.append({
                    "issue": "same_declared_inputs_divergent_artifact",
                    "run_id": row["run_id"],
                })
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "run_id": "none"})
    signals.sort(key=lambda row: (row["run_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["run_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_build_review"
    elif uncertainty or not runs:
        disposition = "unknown"
    else:
        disposition = "no_declared_build_review_signal"
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
        "inventory_complete_asserted": model["inventory_complete"],
        "run_count": len(runs),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not runs),
        "disposition": disposition,
        "source_authenticated": False,
        "build_executed": False,
        "toolchain_verified": False,
        "artifact_bytes_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All run, digest, sandbox, network and input-completeness metadata is supplied.",
            "Equal declared inputs do not prove a reproducible build environment.",
            "Divergent artifacts can be benign nondeterminism, not compromise proof.",
            "No build, compiler, container, registry, repository or target is accessed.",
            "An absent signal does not establish build integrity or safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BRP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class BuildReproducibilityReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BuildReproducibilityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BuildReproducibilityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_build_reproducibility(model: Any) -> BuildReproducibilityReport:
    return BuildReproducibilityReport._owned(_derive(model))


def verify_supplied_build_reproducibility(
    report: Any, *, model: Any
) -> BuildReproducibilityReport:
    if type(report) is not BuildReproducibilityReport:
        raise BuildReproducibilityError("Exact build report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BuildReproducibilityError("Report differs from separate original model")
    return BuildReproducibilityReport._owned(expected)


def component_fixture() -> dict:
    common = {
        "source_sha256": "sha256:" + "a" * 64,
        "definition_sha256": "sha256:" + "b" * 64,
        "toolchain_sha256": "sha256:" + "c" * 64,
        "inputs_sha256": "sha256:" + "d" * 64,
        "declared_inputs_complete": True,
        "sandboxed": True,
        "network_allowed": False,
    }
    return {
        "schema_version": 1,
        "source_id": "synthetic-build-runs",
        "inventory_complete": True,
        "runs": [
            {**common, "run_id": "run_a", "artifact_sha256": "sha256:" + "e" * 64},
            {**common, "run_id": "run_b", "artifact_sha256": "sha256:" + "f" * 64},
        ],
    }
