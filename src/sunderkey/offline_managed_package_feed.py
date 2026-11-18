"""Review supplied JVM and .NET package feed and digest metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "managed_supplied_package_feed_projection"
PROFILE_ID = "AOE-GC-D17-S06"
CAPABILITY_ID = "army.gc.d17.s06"
VECTOR_ID = "AV-GC-D17-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S06"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:df1a28a8bc0ce1c4c0ff19ecb49d244a4b60c588f9a08f4be7e491dcdefbcb7f"
DOMAIN = "sunderkey.offline-managed-package-feed.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_PACKAGES = 32
ECOSYSTEMS = frozenset({"maven", "nuget"})
VERIFICATION_STATES = frozenset({"verified", "failed", "unknown"})
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


class ManagedPackageFeedError(ValueError):
    """The reduced package declaration or replay is invalid."""


def _digest(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ManagedPackageFeedError(f"{label} must be a canonical SHA-256 digest")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "packages"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ManagedPackageFeedError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["packages"], MAX_PACKAGES, "packages"):
        package = core.exact(
            row,
            {
                "record_id",
                "ecosystem",
                "coordinate_id",
                "release_id",
                "intended_feed_id",
                "selected_feed_id",
                "pinned_artifact_sha256",
                "selected_artifact_sha256",
                "verification_state",
            },
            "package",
        )
        record_id = core.identifier(package["record_id"], "record ID")
        if record_id in seen:
            raise ManagedPackageFeedError("Duplicate record ID")
        seen.add(record_id)
        for field in ("coordinate_id", "release_id", "intended_feed_id", "selected_feed_id"):
            core.identifier(package[field], field)
        if type(package["ecosystem"]) is not str or package["ecosystem"] not in ECOSYSTEMS:
            raise ManagedPackageFeedError("Unsupported managed package ecosystem")
        if (
            type(package["verification_state"]) is not str
            or package["verification_state"] not in VERIFICATION_STATES
        ):
            raise ManagedPackageFeedError("Verification state is invalid")
        _digest(package["pinned_artifact_sha256"], "pinned artifact", optional=True)
        _digest(package["selected_artifact_sha256"], "selected artifact")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    packages = sorted(model["packages"], key=lambda row: row["record_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for package in packages:
        record_id = package["record_id"]
        if package["selected_feed_id"] != package["intended_feed_id"]:
            signals.append({"issue": "declared_feed_selection_difference", "record_id": record_id})
        pinned = package["pinned_artifact_sha256"]
        if pinned is None:
            uncertainty.append({"issue": "missing_declared_artifact_pin", "record_id": record_id})
        elif pinned != package["selected_artifact_sha256"]:
            signals.append({"issue": "declared_artifact_digest_difference", "record_id": record_id})
        if package["verification_state"] == "failed":
            signals.append({"issue": "declared_verification_failure", "record_id": record_id})
        elif package["verification_state"] == "unknown":
            uncertainty.append({"issue": "verification_not_asserted", "record_id": record_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "record_id": "none"})
    signals.sort(key=lambda row: (row["record_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["record_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_managed_package_review"
    elif uncertainty or not packages:
        disposition = "unknown"
    else:
        disposition = "no_declared_managed_package_review_signal"
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
        "package_count": len(packages),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not packages),
        "disposition": disposition,
        "source_authenticated": False,
        "feed_contacted": False,
        "signature_verified": False,
        "artifact_bytes_read": False,
        "package_installed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Ecosystem, coordinates, feed choices, digests and verification state are supplied.",
            "No Maven or NuGet parser, version normalization or resolver runs.",
            "A selected feed or digest difference is a review hypothesis, not compromise proof.",
            "No package feed, repository, artifact, signature service or target is contacted.",
            "An absent signal does not establish package origin or integrity.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPF-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ManagedPackageFeedReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ManagedPackageFeedError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ManagedPackageFeedReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_managed_package_feed(model: Any) -> ManagedPackageFeedReport:
    return ManagedPackageFeedReport._owned(_derive(model))


def verify_supplied_managed_package_feed(report: Any, *, model: Any) -> ManagedPackageFeedReport:
    if type(report) is not ManagedPackageFeedReport:
        raise ManagedPackageFeedError("Exact managed package wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ManagedPackageFeedError("Report differs from separate original model")
    return ManagedPackageFeedReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-managed-packages",
        "inventory_complete": True,
        "packages": [
            {
                "record_id": "package_a",
                "ecosystem": "maven",
                "coordinate_id": "example.group:sample",
                "release_id": "release_1",
                "intended_feed_id": "internal",
                "selected_feed_id": "public",
                "pinned_artifact_sha256": "sha256:" + "a" * 64,
                "selected_artifact_sha256": "sha256:" + "b" * 64,
                "verification_state": "unknown",
            }
        ],
    }
