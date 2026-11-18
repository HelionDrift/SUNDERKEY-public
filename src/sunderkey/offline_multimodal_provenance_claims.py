"""Compare synthetic media authenticity claims with supplied provenance metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_multimodal_provenance_claim_projection"
PROFILE_ID = "AOE-GD-D20-S17"
CAPABILITY_ID = "army.gd.d20.s17"
VECTOR_ID = "AV-GD-D20-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S17"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GD-D20-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:76b9229c363218870ea3bb0f155997d0f26fb9de9c9a33151b48c5aab3c2c821"
DOMAIN = "sunderkey.offline-multimodal-provenance-claims.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MultimodalProvenanceError(ValueError):
    """A supplied media claim or original-model replay is invalid."""


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:"):
        raise MultimodalProvenanceError(f"{label} must be a SHA-256 label")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise MultimodalProvenanceError(f"{label} must be a SHA-256 label")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_source_labels", "media_claims",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MultimodalProvenanceError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MultimodalProvenanceError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = {}
    for item in core.bounded_list(model["approved_source_labels"], 32, "source labels"):
        row = core.exact(item, {"source_ref", "digest_label"}, "source label")
        source_ref = core.identifier(row["source_ref"], "opaque source reference")
        if source_ref in approved:
            raise MultimodalProvenanceError("Duplicate source reference")
        approved[source_ref] = _sha(row["digest_label"], "source digest label")
    if not approved:
        raise MultimodalProvenanceError("At least one source label is required")
    claims = core.bounded_list(model["media_claims"], 64, "media claims")
    if not claims:
        raise MultimodalProvenanceError("At least one media claim is required")
    rows = []
    seen = set()
    unknown_sources = []
    for item in claims:
        row = core.exact(item, {
            "asset_ref", "media_kind", "source_ref", "claimed_source_digest_label",
            "transformation_disclosed", "authenticity_claimed",
        }, "media claim")
        asset_ref = core.identifier(row["asset_ref"], "opaque asset reference")
        if asset_ref in seen:
            raise MultimodalProvenanceError("Duplicate asset reference")
        seen.add(asset_ref)
        source_ref = core.identifier(row["source_ref"], "opaque source reference")
        digest_label = _sha(row["claimed_source_digest_label"], "claimed digest label")
        kind = core.choice(row["media_kind"], {"audio", "image", "video"}, "media kind")
        disclosed = core.boolean(row["transformation_disclosed"], "transformation declaration")
        authentic = core.boolean(row["authenticity_claimed"], "authenticity declaration")
        known = source_ref in approved
        if not known:
            unknown_sources.append(asset_ref)
        flags = []
        if known and digest_label != approved[source_ref]:
            flags.append("claimed_source_digest_differs_from_supplied_label")
        if authentic and not disclosed:
            flags.append("authenticity_claim_without_transform_disclosure")
        rows.append({
            "asset_ref": asset_ref,
            "media_kind": kind,
            "source_ref": source_ref,
            "claimed_source_digest_label": digest_label,
            "source_in_supplied_inventory": known,
            "transformation_disclosed": disclosed,
            "authenticity_claimed": authentic,
            "declared_provenance_flags": flags,
        })
    rows.sort(key=lambda row: row["asset_ref"])
    flagged = [row["asset_ref"] for row in rows if row["declared_provenance_flags"]]
    unknown = [] if complete else ["supplied_source_inventory_incomplete"]
    if unknown_sources:
        unknown.append("media_claim_source_absent_from_supplied_inventory")
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
        "inventory_complete_asserted": complete,
        "media_claim_projections": rows,
        "flagged_asset_refs": flagged,
        "unknown_source_asset_refs": sorted(unknown_sources),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_media_provenance_projection",
        "source_authenticated": False,
        "media_bytes_processed": False,
        "signature_verified": False,
        "deepfake_detected": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Digest labels, source claims, disclosures, and completeness are assertions.",
            "No media bytes or signature material are accepted or verified.",
            "A metadata flag is not deepfake detection or proof of manipulation.",
            "No model, provider, network, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MultimodalProvenanceReport:
    """Unsigned media-claim projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MultimodalProvenanceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MultimodalProvenanceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_multimodal_provenance(model: Any) -> MultimodalProvenanceReport:
    return MultimodalProvenanceReport._owned(_derive(model))


def verify_supplied_multimodal_provenance(
    report: Any, *, model: Any
) -> MultimodalProvenanceReport:
    if type(report) is not MultimodalProvenanceReport:
        raise MultimodalProvenanceError("Exact media-claim wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MultimodalProvenanceError("Report differs from separate original model")
    return MultimodalProvenanceReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-media-provenance-claims",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_source_labels": [{
            "source_ref": "source-opaque-a", "digest_label": "sha256:" + "a" * 64,
        }],
        "media_claims": [{
            "asset_ref": "asset-opaque-a", "media_kind": "image",
            "source_ref": "source-opaque-a", "claimed_source_digest_label": "sha256:" + "b" * 64,
            "transformation_disclosed": False, "authenticity_claimed": True,
        }],
    }
