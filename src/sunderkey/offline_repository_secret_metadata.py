"""Review supplied repository and build-log secret occurrence metadata only."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "repository_supplied_secret_occurrence_projection"
PROFILE_ID = "AOE-GC-D17-S11"
CAPABILITY_ID = "army.gc.d17.s11"
VECTOR_ID = "AV-GC-D17-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S11"
WAVE_ID = "IW2-023"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a97504a73d843ab9f91c4780cb2f7a580230cb9278e2df1d99612191e13eb1e1"
DOMAIN = "sunderkey.offline-repository-secret-metadata.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_OCCURRENCES = 64
SURFACES = frozenset({"repository", "build_log"})
AUDIENCES = frozenset({"restricted", "organization", "public"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class RepositorySecretMetadataError(ValueError):
    """The reduced occurrence declaration or replay is invalid."""


def _choice(value: Any, choices: frozenset[str], label: str) -> str:
    if type(value) is not str or value not in choices:
        raise RepositorySecretMetadataError(f"{label} is invalid")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "occurrences"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RepositorySecretMetadataError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["occurrences"], MAX_OCCURRENCES, "occurrences"):
        occurrence = core.exact(row, {
            "occurrence_id", "opaque_incident_id", "surface", "audience",
            "content_redacted", "rotation_confirmed", "removal_confirmed",
        }, "occurrence")
        occurrence_id = core.identifier(occurrence["occurrence_id"], "occurrence ID")
        if occurrence_id in seen:
            raise RepositorySecretMetadataError("Duplicate occurrence ID")
        seen.add(occurrence_id)
        core.identifier(occurrence["opaque_incident_id"], "opaque incident ID")
        _choice(occurrence["surface"], SURFACES, "surface")
        _choice(occurrence["audience"], AUDIENCES, "audience")
        for field in ("content_redacted", "rotation_confirmed", "removal_confirmed"):
            core.boolean(occurrence[field], field)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    occurrences = sorted(model["occurrences"], key=lambda row: row["occurrence_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    by_incident: dict[str, list[dict]] = {}
    for row in occurrences:
        occurrence_id = row["occurrence_id"]
        by_incident.setdefault(row["opaque_incident_id"], []).append(row)
        if row["audience"] == "public" and not row["content_redacted"]:
            signals.append({
                "issue": "declared_public_unredacted_occurrence",
                "occurrence_id": occurrence_id,
            })
        if not row["rotation_confirmed"]:
            uncertainty.append({
                "issue": "rotation_not_confirmed",
                "occurrence_id": occurrence_id,
            })
        if not row["removal_confirmed"]:
            uncertainty.append({
                "issue": "removal_not_confirmed",
                "occurrence_id": occurrence_id,
            })
    for members in by_incident.values():
        if {row["surface"] for row in members} == SURFACES:
            signals.append({
                "issue": "same_opaque_incident_across_declared_surfaces",
                "occurrence_id": min(row["occurrence_id"] for row in members),
            })
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "occurrence_id": "none"})
    signals.sort(key=lambda row: (row["occurrence_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["occurrence_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_secret_occurrence_review"
    elif uncertainty or not occurrences:
        disposition = "unknown"
    else:
        disposition = "no_declared_occurrence_review_signal"
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
        "occurrence_count": len(occurrences),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not occurrences),
        "disposition": disposition,
        "source_authenticated": False,
        "secret_bytes_read": False,
        "secret_validity_verified": False,
        "rotation_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Occurrence, audience, redaction, rotation, removal and identity labels are supplied.",
            "Opaque incident IDs must be assigned independently, never derived from secret bytes.",
            "The model has no secret value, reusable hash, file path or log content fields.",
            "No repository, log, scanner, credential provider or target is accessed.",
            "Co-occurrence does not prove the same secret or any actual exposure.",
            "An absent signal does not establish that secrets are absent or remediated.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RSM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RepositorySecretMetadataReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RepositorySecretMetadataError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RepositorySecretMetadataReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_repository_secret_metadata(
    model: Any,
) -> RepositorySecretMetadataReport:
    return RepositorySecretMetadataReport._owned(_derive(model))


def verify_supplied_repository_secret_metadata(
    report: Any, *, model: Any
) -> RepositorySecretMetadataReport:
    if type(report) is not RepositorySecretMetadataReport:
        raise RepositorySecretMetadataError("Exact occurrence report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RepositorySecretMetadataError("Report differs from separate original model")
    return RepositorySecretMetadataReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-secret-occurrences",
        "inventory_complete": True,
        "occurrences": [
            {
                "occurrence_id": "repo_a", "opaque_incident_id": "incident_demo_1",
                "surface": "repository", "audience": "public", "content_redacted": False,
                "rotation_confirmed": False, "removal_confirmed": False,
            },
            {
                "occurrence_id": "log_b", "opaque_incident_id": "incident_demo_1",
                "surface": "build_log", "audience": "restricted", "content_redacted": True,
                "rotation_confirmed": False, "removal_confirmed": True,
            },
        ],
    }
