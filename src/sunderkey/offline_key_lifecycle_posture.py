"""Compare bounded, supplied key lifecycle assertions without contacting a KMS."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_key_lifecycle_posture"
PROFILE_ID = "AOE-GE-D22-S10"
CAPABILITY_ID = "army.ge.d22.s10"
VECTOR_ID = "AV-GE-D22-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S10"
WAVE_ID = "IW2-023"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cbc84a947d6597f84aa44eae2053802fe213a487d7be662f1695689f59e44979"
DOMAIN = "sunderkey.offline-key-lifecycle-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_KEYS = 32
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
STATES = {"active", "disabled", "destroyed"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class KeyLifecyclePostureError(ValueError):
    """The supplied key lifecycle model or replay is invalid."""


def _time(value: Any, label: str) -> datetime:
    if type(value) is not str or TIMESTAMP.fullmatch(value) is None:
        raise KeyLifecyclePostureError(f"{label} must be exact UTC seconds")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KeyLifecyclePostureError(f"{label} is not a valid UTC time") from exc


def _optional_time(value: Any, label: str) -> datetime | None:
    return None if value is None else _time(value, label)


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "snapshot_at", "inventory_complete", "keys"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KeyLifecyclePostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    snapshot = _time(model["snapshot_at"], "snapshot time")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for item in core.bounded_list(model["keys"], MAX_KEYS, "keys"):
        row = core.exact(
            item,
            {
                "key_id", "state", "created_at", "last_rotation_at", "last_use_at",
                "destroyed_at", "rotation_interval_days", "policy_assertions_complete",
            },
            "key",
        )
        key_id = core.identifier(row["key_id"], "key ID")
        if key_id in seen:
            raise KeyLifecyclePostureError("Duplicate key ID")
        seen.add(key_id)
        core.choice(row["state"], STATES, "key state")
        created = _time(row["created_at"], "creation time")
        rotated = _optional_time(row["last_rotation_at"], "rotation time")
        used = _optional_time(row["last_use_at"], "last-use time")
        destroyed = _optional_time(row["destroyed_at"], "destruction time")
        for label, moment in (("creation", created), ("rotation", rotated),
                              ("last use", used), ("destruction", destroyed)):
            if moment is not None and not created <= moment <= snapshot:
                raise KeyLifecyclePostureError(f"{label} time escapes supplied lifecycle")
        if row["state"] == "destroyed" and destroyed is None:
            raise KeyLifecyclePostureError("Destroyed key needs destruction time")
        if row["state"] != "destroyed" and destroyed is not None:
            raise KeyLifecyclePostureError("Nondestroyed key cannot have destruction time")
        interval = row["rotation_interval_days"]
        if interval is not None and (
            type(interval) is not int or not 1 <= interval <= 3650
        ):
            raise KeyLifecyclePostureError("Rotation interval is invalid")
        core.boolean(row["policy_assertions_complete"], "policy completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    snapshot = _time(model["snapshot_at"], "snapshot time")
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for row in sorted(model["keys"], key=lambda item: item["key_id"]):
        key_id = row["key_id"]
        if not row["policy_assertions_complete"]:
            uncertainty.append({"key_id": key_id, "issue": "incomplete_declared_policy"})
            continue
        destroyed = _optional_time(row["destroyed_at"], "destruction time")
        used = _optional_time(row["last_use_at"], "last-use time")
        if destroyed is not None and used is not None and used > destroyed:
            signals.append({"key_id": key_id, "issue": "declared_use_after_destruction"})
        if row["state"] == "active":
            interval = row["rotation_interval_days"]
            if interval is None:
                uncertainty.append({"key_id": key_id, "issue": "rotation_policy_not_asserted"})
            else:
                rotated = _optional_time(row["last_rotation_at"], "rotation time")
                base = rotated or _time(row["created_at"], "creation time")
                if snapshot - base > timedelta(days=interval):
                    signals.append(
                        {"key_id": key_id, "issue": "declared_rotation_interval_elapsed"}
                    )
    if not model["inventory_complete"]:
        uncertainty.append({"key_id": "none", "issue": "incomplete_supplied_inventory"})
    signals.sort(key=lambda item: (item["key_id"], item["issue"]))
    uncertainty.sort(key=lambda item: (item["key_id"], item["issue"]))
    disposition = (
        "candidate_declared_key_lifecycle_review" if signals else
        "unknown" if uncertainty or not model["keys"] else
        "no_declared_key_lifecycle_signal"
    )
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
        "snapshot_at_asserted": model["snapshot_at"],
        "inventory_complete_asserted": model["inventory_complete"],
        "key_count": len(model["keys"]),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not model["keys"]),
        "disposition": disposition,
        "source_authenticated": False,
        "kms_queried": False,
        "key_material_access_proven": False,
        "policy_effectiveness_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All timestamps, states and policy labels are supplied assertions.",
            "No KMS, HSM, key material, grants or provider policy are inspected.",
            "A chronological mismatch is a review signal, not proof of key use.",
            "An absent signal does not establish key lifecycle safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KLP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class KeyLifecyclePostureReport:
    """Unsigned declaration projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KeyLifecyclePostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KeyLifecyclePostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_key_lifecycle(model: Any) -> KeyLifecyclePostureReport:
    return KeyLifecyclePostureReport._owned(_derive(model))


def verify_supplied_key_lifecycle(
    report: Any, *, model: Any
) -> KeyLifecyclePostureReport:
    if type(report) is not KeyLifecyclePostureReport:
        raise KeyLifecyclePostureError("Exact key lifecycle wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KeyLifecyclePostureError("Report differs from separate original model")
    return KeyLifecyclePostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-key-lifecycle",
        "snapshot_at": "2026-01-10T00:00:00Z",
        "inventory_complete": True,
        "keys": [{
            "key_id": "key_a",
            "state": "active",
            "created_at": "2025-01-01T00:00:00Z",
            "last_rotation_at": "2025-01-01T00:00:00Z",
            "last_use_at": "2025-12-01T00:00:00Z",
            "destroyed_at": None,
            "rotation_interval_days": 90,
            "policy_assertions_complete": True,
        }],
    }
