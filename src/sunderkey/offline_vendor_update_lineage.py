"""Inert comparison of supplied vendor update versions and artifact digests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "vendor_supplied_update_lineage_projection"
PROFILE_ID = "AOE-GC-D17-S14"
CAPABILITY_ID = "army.gc.d17.s14"
VECTOR_ID = "AV-GC-D17-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S14"
WAVE_ID = "IW2-026"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:781f269fd8298715d51f963ee0466b15ebd3dc25adf7dbabcdde9c6d05b1a98e"
DOMAIN = "sunderkey.offline-vendor-update-lineage.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_OFFERS = 32
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
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


class VendorUpdateLineageError(ValueError):
    """A reduced declaration or original-source replay is invalid."""


def _version(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise VendorUpdateLineageError(f"{label} must be a nonnegative signed64 integer")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise VendorUpdateLineageError(f"{label} must be a canonical SHA-256 digest")
    return value


def _time(value: Any, label: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise VendorUpdateLineageError(f"{label} must be a second-resolution UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise VendorUpdateLineageError(f"{label} is invalid") from exc


def _release(value: Any, label: str, *, offer: bool) -> dict:
    fields = {"channel_id", "release_version", "artifact_sha256", "metadata_version"}
    if offer:
        fields = fields | {"offer_id", "expires_at"}
    row = core.exact(value, fields, label)
    core.identifier(row["channel_id"], f"{label} channel ID")
    _version(row["release_version"], f"{label} release version")
    _version(row["metadata_version"], f"{label} metadata version")
    _digest(row["artifact_sha256"], f"{label} artifact digest")
    if offer:
        core.identifier(row["offer_id"], f"{label} offer ID")
        _time(row["expires_at"], f"{label} expiration")
    return row


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "observed_at", "trusted", "offers"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VendorUpdateLineageError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    _time(model["observed_at"], "observation time")
    _release(model["trusted"], "trusted release", offer=False)
    seen: set[str] = set()
    for row in core.bounded_list(model["offers"], MAX_OFFERS, "offers"):
        offer = _release(row, "offer", offer=True)
        if offer["offer_id"] in seen:
            raise VendorUpdateLineageError("Duplicate offer ID")
        seen.add(offer["offer_id"])
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    trusted = model["trusted"]
    observed = _time(model["observed_at"], "observation time")
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "offer_id": "none"})
    for offer in sorted(model["offers"], key=lambda row: row["offer_id"]):
        identifier = offer["offer_id"]
        if offer["channel_id"] != trusted["channel_id"]:
            uncertainty.append({"issue": "different_declared_channel", "offer_id": identifier})
            continue
        if offer["metadata_version"] < trusted["metadata_version"]:
            signals.append({"issue": "declared_metadata_version_rollback", "offer_id": identifier})
        if offer["release_version"] < trusted["release_version"]:
            signals.append({"issue": "declared_release_version_rollback", "offer_id": identifier})
        if (
            offer["release_version"] == trusted["release_version"]
            and offer["artifact_sha256"] != trusted["artifact_sha256"]
        ):
            signals.append({"issue": "same_version_digest_divergence", "offer_id": identifier})
        if _time(offer["expires_at"], "offer expiration") <= observed:
            signals.append(
                {"issue": "expired_at_supplied_observation_time", "offer_id": identifier}
            )
    if signals:
        disposition = "candidate_declared_update_lineage_conflict"
    elif uncertainty or not model["offers"]:
        disposition = "unknown"
    else:
        disposition = "no_declared_update_lineage_conflict"
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
        "trusted_channel_id": trusted["channel_id"],
        "offer_count": len(model["offers"]),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not model["offers"]),
        "disposition": disposition,
        "source_authenticated": False,
        "metadata_signatures_verified": False,
        "artifact_bytes_read": False,
        "clock_authenticated": False,
        "update_installed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Trusted release, offers, digests, versions and observation time are "
            "supplied assertions.",
            "No signature, key, trusted root, artifact bytes or provider currentness is verified.",
            "A version or digest mismatch is not proof of compromise or downgrade acceptance.",
            "No update source, registry, repository, vendor endpoint or device is contacted.",
            "An absent declared conflict does not establish update-channel safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VUL-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class VendorUpdateLineageReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VendorUpdateLineageError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VendorUpdateLineageReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_vendor_update_lineage(model: Any) -> VendorUpdateLineageReport:
    return VendorUpdateLineageReport._owned(_derive(model))


def verify_supplied_vendor_update_lineage(report: Any, *, model: Any) -> VendorUpdateLineageReport:
    if type(report) is not VendorUpdateLineageReport:
        raise VendorUpdateLineageError("Exact update-lineage wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VendorUpdateLineageError("Report differs from separate original model")
    return VendorUpdateLineageReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-vendor-update-lineage",
        "inventory_complete": True,
        "observed_at": "2026-01-05T00:00:00Z",
        "trusted": {
            "channel_id": "stable",
            "release_version": 12,
            "artifact_sha256": "sha256:" + "a" * 64,
            "metadata_version": 8,
        },
        "offers": [
            {
                "offer_id": "offer_a",
                "channel_id": "stable",
                "release_version": 11,
                "artifact_sha256": "sha256:" + "b" * 64,
                "metadata_version": 7,
                "expires_at": "2026-01-04T00:00:00Z",
            }
        ],
    }
