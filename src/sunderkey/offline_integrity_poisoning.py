"""Compare supplied artifact digests, origin trust, and consumption claims."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_integrity_poisoning"
PROFILE_ID = "AOE-GE-D23-S15"
CAPABILITY_ID = "army.ge.d23.s15"
VECTOR_ID = "AV-GE-D23-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S15"
WAVE_ID = "IW2-029"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c64f492f13c64b8bb17871e675358be762ec9db2817c13fedac701e3892dafbc"
SEMANTICS_PROFILE = "supplied-artifact-integrity-consumption-v1"
DOMAIN = "sunderkey.offline-integrity-poisoning.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_ARTIFACTS = 128
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ORIGINS = {"trusted", "untrusted", "unknown"}
_OUTCOMES = {"allow", "deny", "unknown"}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

IntegrityPoisoningError = core.FrameworkDeclarationError


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "artifacts"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise IntegrityPoisoningError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise IntegrityPoisoningError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"], {"declaration_complete", "require_digest_match"}, "policy"
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    core.boolean(policy["require_digest_match"], "digest match requirement")
    artifacts = core.bounded_list(item["artifacts"], MAX_ARTIFACTS, "artifacts")
    if not artifacts:
        raise IntegrityPoisoningError("At least one artifact is required")
    identifiers: set[str] = set()
    for raw in artifacts:
        artifact = core.exact(
            raw,
            {"artifact_id", "artifact_ref", "expected_digest", "presented_digest",
             "origin_trust", "declared_consumption", "capture_complete"},
            "artifact",
        )
        identity = core.identifier(artifact["artifact_id"], "artifact ID")
        if identity in identifiers:
            raise IntegrityPoisoningError("Artifact identifier is repeated")
        identifiers.add(identity)
        if type(artifact["artifact_ref"]) is not str or _REF.fullmatch(
            artifact["artifact_ref"]
        ) is None:
            raise IntegrityPoisoningError("Artifact label must be an opaque reference")
        for field in ("expected_digest", "presented_digest"):
            if type(artifact[field]) is not str or _DIGEST.fullmatch(artifact[field]) is None:
                raise IntegrityPoisoningError("Artifact digest must be SHA-256 syntax")
        core.choice(artifact["origin_trust"], _ORIGINS, "origin trust")
        core.choice(artifact["declared_consumption"], _OUTCOMES, "consumption")
        core.boolean(artifact["capture_complete"], "capture completeness")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    projections = []
    for item in sorted(model["artifacts"], key=lambda row: row["artifact_id"]):
        mismatch = item["expected_digest"] != item["presented_digest"]
        negative = model["policy"]["require_digest_match"] and mismatch
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif item["origin_trust"] == "unknown" or item["declared_consumption"] == "unknown":
            disposition = "unresolved_origin_or_consumption"
        elif not negative:
            disposition = "no_declared_integrity_conflict"
        elif item["declared_consumption"] == "deny":
            disposition = "declared_integrity_rejection_consistent"
        elif item["origin_trust"] == "untrusted":
            disposition = "candidate_declared_untrusted_content_consumption"
        else:
            disposition = "candidate_declared_integrity_policy_conflict"
        projections.append(
            {"artifact_id": item["artifact_id"],
             "digest_relation": "mismatch" if mismatch else "match",
             "negative_predicate": "digest_mismatch_requires_deny" if negative else None,
             "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "artifact_count": len(projections),
        "projections": projections,
        "flags": {
            "artifact_bytes_verified": False,
            "origin_trust_verified": False,
            "consumption_verified": False,
            "poisoning_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Digests, origin trust, policy and consumption are caller assertions.",
            "Digest strings are compared but no artifact bytes are read or hashed.",
            "A declared conflict does not verify poisoning or target consumption.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IPO-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class IntegrityPoisoning:
    """Immutable replay of one supplied artifact-integrity model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise IntegrityPoisoningError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise IntegrityPoisoningError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_integrity_poisoning(model: Any) -> IntegrityPoisoning:
    """Project supplied integrity claims without reading artifact bytes."""
    return IntegrityPoisoning(_derive(model))


def verify_supplied_integrity_poisoning(
    report: Any, *, model: Any
) -> IntegrityPoisoning:
    if type(report) is not IntegrityPoisoning:
        raise IntegrityPoisoningError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise IntegrityPoisoningError("Report differs from supplied source replay")
    return IntegrityPoisoning(expected)
