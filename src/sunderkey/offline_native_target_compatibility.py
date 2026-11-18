"""Review supplied native, Cargo and Go artifact target metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "native_supplied_target_compatibility_projection"
PROFILE_ID = "AOE-GC-D17-S07"
CAPABILITY_ID = "army.gc.d17.s07"
VECTOR_ID = "AV-GC-D17-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S07"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6aa11710efe02ec25aa530be5b73769bd93a28bc03dd4ca1822206225a14ca27"
DOMAIN = "sunderkey.offline-native-target-compatibility.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_ARTIFACTS = 32
MAX_TARGETS = 16
ECOSYSTEMS = frozenset({"native", "cargo", "go"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class NativeTargetCompatibilityError(ValueError):
    """The reduced artifact declaration or replay is invalid."""


def _digest(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise NativeTargetCompatibilityError(f"{label} must be a canonical SHA-256 digest")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "artifacts"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise NativeTargetCompatibilityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["artifacts"], MAX_ARTIFACTS, "artifacts"):
        artifact = core.exact(
            row,
            {
                "artifact_id",
                "ecosystem",
                "package_id",
                "release_id",
                "requested_target_id",
                "supported_target_ids",
                "target_list_complete",
                "pinned_digest",
                "artifact_digest",
            },
            "artifact",
        )
        artifact_id = core.identifier(artifact["artifact_id"], "artifact ID")
        if artifact_id in seen:
            raise NativeTargetCompatibilityError("Duplicate artifact ID")
        seen.add(artifact_id)
        core.choice(artifact["ecosystem"], ECOSYSTEMS, "ecosystem")
        for field in ("package_id", "release_id", "requested_target_id"):
            core.identifier(artifact[field], field)
        targets = core.bounded_list(artifact["supported_target_ids"], MAX_TARGETS, "targets")
        if len(targets) != len(set(core.identifier(item, "target ID") for item in targets)):
            raise NativeTargetCompatibilityError("Duplicate target ID")
        core.boolean(artifact["target_list_complete"], "target list completeness")
        _digest(artifact["pinned_digest"], "pinned digest", optional=True)
        _digest(artifact["artifact_digest"], "artifact digest")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    artifacts = sorted(model["artifacts"], key=lambda row: row["artifact_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for artifact in artifacts:
        artifact_id = artifact["artifact_id"]
        if artifact["requested_target_id"] not in artifact["supported_target_ids"]:
            if artifact["target_list_complete"]:
                signals.append(
                    {"issue": "requested_target_not_declared_supported", "artifact_id": artifact_id}
                )
            else:
                uncertainty.append(
                    {"issue": "incomplete_declared_target_list", "artifact_id": artifact_id}
                )
        if artifact["pinned_digest"] is None:
            uncertainty.append(
                {"issue": "missing_declared_artifact_pin", "artifact_id": artifact_id}
            )
        elif artifact["pinned_digest"] != artifact["artifact_digest"]:
            signals.append(
                {"issue": "declared_artifact_digest_difference", "artifact_id": artifact_id}
            )
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "artifact_id": "none"})
    signals.sort(key=lambda row: (row["artifact_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["artifact_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_target_review"
    elif uncertainty or not artifacts:
        disposition = "unknown"
    else:
        disposition = "no_declared_target_review_signal"
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
        "artifact_count": len(artifacts),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not artifacts),
        "disposition": disposition,
        "source_authenticated": False,
        "target_compatibility_verified": False,
        "artifact_bytes_read": False,
        "package_installed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Package, release, target and digest labels are supplied and unauthenticated.",
            "No package manager, ABI, architecture or toolchain compatibility check runs.",
            "A declared target or digest difference is a review hypothesis, not compromise proof.",
            "No registry, repository, artifact or target is contacted or executed.",
            "An absent signal does not establish runtime compatibility or artifact integrity.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="NTC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class NativeTargetCompatibilityReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise NativeTargetCompatibilityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> NativeTargetCompatibilityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_native_target_compatibility(model: Any) -> NativeTargetCompatibilityReport:
    return NativeTargetCompatibilityReport._owned(_derive(model))


def verify_supplied_native_target_compatibility(
    report: Any, *, model: Any
) -> NativeTargetCompatibilityReport:
    if type(report) is not NativeTargetCompatibilityReport:
        raise NativeTargetCompatibilityError("Exact native target wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise NativeTargetCompatibilityError("Report differs from separate original model")
    return NativeTargetCompatibilityReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-native-targets",
        "inventory_complete": True,
        "artifacts": [
            {
                "artifact_id": "artifact_a",
                "ecosystem": "cargo",
                "package_id": "sample",
                "release_id": "release_1",
                "requested_target_id": "linux_x86_64",
                "supported_target_ids": ["windows_x86_64"],
                "target_list_complete": True,
                "pinned_digest": "sha256:" + "a" * 64,
                "artifact_digest": "sha256:" + "b" * 64,
            }
        ],
    }
