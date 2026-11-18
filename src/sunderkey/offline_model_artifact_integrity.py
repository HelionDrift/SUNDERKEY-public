"""Compare supplied model-artifact bytes with declared release digests."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_artifact_integrity"
PROFILE_ID = "AOE-GD-D20-S08"
CAPABILITY_ID = "army.gd.d20.s08"
VECTOR_ID = "AV-GD-D20-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S08"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:e3084cce5f066641c4883deef97aecd9c740a46a1f836928f4f3435466dbbee8"
DOMAIN = "sunderkey.offline-model-artifact-integrity.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_ARTIFACT_BYTES = 16_384
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class ModelArtifactIntegrityError(ValueError):
    """A supplied model artifact declaration or replay is invalid."""


def _decode_blob(value: Any) -> bytes:
    if type(value) is not str or not value or len(value) > 4 * MAX_ARTIFACT_BYTES // 3 + 8:
        raise ModelArtifactIntegrityError("Artifact must contain bounded canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModelArtifactIntegrityError("Artifact base64 is invalid") from exc
    if not raw or len(raw) > MAX_ARTIFACT_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise ModelArtifactIntegrityError("Artifact base64 is noncanonical or oversized")
    return raw


def _model(value: Any) -> tuple[dict, str, dict[str, bytes]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "release_id", "artifacts"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ModelArtifactIntegrityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.identifier(model["release_id"], "release ID")
    rows = core.bounded_list(model["artifacts"], 8, "artifacts")
    if not rows:
        raise ModelArtifactIntegrityError("Artifacts must not be empty")
    blobs: dict[str, bytes] = {}
    for item in rows:
        row = core.exact(
            item,
            {"artifact_id", "blob_base64", "expected_sha256", "declared_origin"},
            "artifact",
        )
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        if artifact_id in blobs:
            raise ModelArtifactIntegrityError("Duplicate artifact ID")
        expected = row["expected_sha256"]
        if type(expected) is not str or (
            expected != "unknown" and _DIGEST.fullmatch(expected) is None
        ):
            raise ModelArtifactIntegrityError("Expected digest must be SHA-256 or unknown")
        core.choice(row["declared_origin"], {"approved", "unapproved", "unknown"}, "origin")
        blobs[artifact_id] = _decode_blob(row["blob_base64"])
    return model, core.canonical(model), blobs


def _derive(value: Any) -> dict:
    model, model_text, blobs = _model(value)
    projections = []
    for item in model["artifacts"]:
        raw = blobs[item["artifact_id"]]
        observed = core.digest(raw)
        if item["expected_sha256"] == "unknown":
            disposition = "unknown_expected_digest"
        elif observed != item["expected_sha256"]:
            disposition = "candidate_declared_digest_mismatch"
        elif item["declared_origin"] == "unapproved":
            disposition = "candidate_declared_unapproved_origin"
        elif item["declared_origin"] == "unknown":
            disposition = "unknown_origin"
        else:
            disposition = "declared_matching_digest_unverified"
        projections.append({
            "artifact_id": item["artifact_id"],
            "artifact_sha256": observed,
            "artifact_bytes": len(raw),
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "artifact_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"].startswith("unknown_") for row in projections),
        "source_authenticated": False,
        "release_manifest_authenticated": False,
        "signature_verified": False,
        "provider_fetch_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only supplied bytes are hashed; no model hub or provider is contacted.",
            "Expected digests and origin labels are unauthenticated caller declarations.",
            "A digest match proves only equality to the supplied expectation, not safety.",
            "A mismatch is a local integrity candidate, not an observed supply-chain attack.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MAI-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ModelArtifactIntegrityReport:
    """Unsigned digest projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ModelArtifactIntegrityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ModelArtifactIntegrityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_model_artifact_integrity(model: Any) -> ModelArtifactIntegrityReport:
    return ModelArtifactIntegrityReport._owned(_derive(model))


def verify_supplied_model_artifact_integrity(
    report: Any, *, model: Any
) -> ModelArtifactIntegrityReport:
    if type(report) is not ModelArtifactIntegrityReport:
        raise ModelArtifactIntegrityError("Exact model-artifact wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ModelArtifactIntegrityError("Report differs from separate original model")
    return ModelArtifactIntegrityReport._owned(expected)


def verify_supplied_model_artifact_integrity_bytes(
    report_bytes: bytes, *, model: Any
) -> ModelArtifactIntegrityReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ModelArtifactIntegrityError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ModelArtifactIntegrityError("Exported report differs from original replay")
    return ModelArtifactIntegrityReport._owned(expected)


def component_fixture() -> dict:
    safe = b"I1\n."
    pickle_with_global = b"cbuiltins\nlist\n."
    return {
        "schema_version": 1,
        "source_id": "synthetic-model-release",
        "release_id": "synthetic-release-one",
        "artifacts": [
            {
                "artifact_id": "pickle-risky",
                "blob_base64": base64.b64encode(pickle_with_global).decode("ascii"),
                "expected_sha256": core.digest(pickle_with_global),
                "declared_origin": "approved",
            },
            {
                "artifact_id": "digest-mismatch",
                "blob_base64": base64.b64encode(safe).decode("ascii"),
                "expected_sha256": core.digest(pickle_with_global),
                "declared_origin": "approved",
            },
            {
                "artifact_id": "unapproved-origin",
                "blob_base64": base64.b64encode(safe).decode("ascii"),
                "expected_sha256": core.digest(safe),
                "declared_origin": "unapproved",
            },
            {
                "artifact_id": "unknown-expected",
                "blob_base64": base64.b64encode(safe).decode("ascii"),
                "expected_sha256": "unknown",
                "declared_origin": "unknown",
            },
        ],
    }
