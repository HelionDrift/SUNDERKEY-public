"""Compare bounded, caller-supplied registry signature binding declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "oci_supplied_registry_signature_bindings"
PROFILE_ID = "AOE-GC-D15-S11"
CAPABILITY_ID = "army.gc.d15.s11"
VECTOR_ID = "AV-GC-D15-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S11"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b9ac882cf604d5e988cf907d6ed19a1e10f43362d1f599efa92dfaf31bdaea9b"
DOMAIN = "sunderkey.offline-oci-registry-signature-bindings.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_SIGNATURES = 64
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REGISTRY = re.compile(r"[a-z0-9][a-z0-9.:-]{0,127}\Z")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._/-]{0,254}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class OciRegistrySignatureBindingsError(ValueError):
    """A supplied binding declaration or original replay is invalid."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise OciRegistrySignatureBindingsError(f"{label} must be lowercase SHA-256")
    return value


def _repository(value: Any, label: str) -> str:
    if type(value) is not str or _REPOSITORY.fullmatch(value) is None:
        raise OciRegistrySignatureBindingsError(f"{label} is outside the finite subset")
    if any(segment in ("", ".", "..") for segment in value.split("/")):
        raise OciRegistrySignatureBindingsError(f"{label} has an ambiguous segment")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "registry", "signatures"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OciRegistrySignatureBindingsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    registry = core.exact(model["registry"], {"host", "repository", "manifest_digest"}, "registry")
    if type(registry["host"]) is not str or _REGISTRY.fullmatch(registry["host"]) is None:
        raise OciRegistrySignatureBindingsError("Registry host is outside the finite subset")
    _repository(registry["repository"], "registry repository")
    _digest(registry["manifest_digest"], "manifest digest")
    signatures = core.bounded_list(model["signatures"], MAX_SIGNATURES, "signatures")
    seen: set[str] = set()
    for index, value in enumerate(signatures):
        item = core.exact(
            value,
            {"signature_id", "artifact_digest", "subject_digest", "repository"},
            f"signature {index}",
        )
        signature_id = core.identifier(item["signature_id"], "signature ID")
        if signature_id in seen:
            raise OciRegistrySignatureBindingsError("Duplicate signature ID")
        seen.add(signature_id)
        _digest(item["artifact_digest"], "signature artifact digest")
        _digest(item["subject_digest"], "signature subject digest")
        _repository(item["repository"], "signature repository")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    registry = model["registry"]
    complete = model["inventory_complete"]
    rows = []
    mismatches: list[dict[str, str]] = []
    for index, signature in enumerate(model["signatures"]):
        subject_match = (
            signature["subject_digest"] == registry["manifest_digest"] if complete else None
        )
        repository_match = (
            signature["repository"] == registry["repository"] if complete else None
        )
        if complete and not subject_match:
            mismatches.append({"issue": "subject_digest_mismatch", "path": f"signatures/{index}"})
        if complete and not repository_match:
            mismatches.append({"issue": "repository_mismatch", "path": f"signatures/{index}"})
        if not complete:
            status = "unknown"
        elif not subject_match or not repository_match:
            status = "candidate_supplied_binding_mismatch"
        else:
            status = "supplied_binding_consistent"
        rows.append({
            "signature_id": signature["signature_id"],
            "artifact_digest": signature["artifact_digest"],
            "subject_digest": signature["subject_digest"],
            "repository": signature["repository"],
            "subject_match": subject_match,
            "repository_match": repository_match,
            "status": status,
        })
    if not complete or not rows:
        disposition = "unknown"
    elif mismatches:
        disposition = "candidate_supplied_binding_mismatch"
    else:
        disposition = "supplied_binding_consistent"
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
        "signature_record_count": len(rows),
        "signature_rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "registry_contacted": False,
        "signature_bytes_verified": False,
        "cryptographic_signature_verified": False,
        "signer_identity_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Registry and signature records, including completeness, are caller-supplied.",
            "The artifact digest identifies a claimed signature artifact; its bytes are not read.",
            "Only supplied subject digest and repository equality are compared.",
            "No registry call, cryptographic verification, signer trust or policy check occurs.",
            "A matching declaration does not establish image provenance, integrity or safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ORS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OciRegistrySignatureBindingsReport:
    """Unsigned binding projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OciRegistrySignatureBindingsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OciRegistrySignatureBindingsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_oci_registry_signature_bindings(
    model: Any,
) -> OciRegistrySignatureBindingsReport:
    return OciRegistrySignatureBindingsReport._owned(_derive(model))


def verify_supplied_oci_registry_signature_bindings(
    report: Any, *, model: Any,
) -> OciRegistrySignatureBindingsReport:
    if type(report) is not OciRegistrySignatureBindingsReport:
        raise OciRegistrySignatureBindingsError("Exact registry binding wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OciRegistrySignatureBindingsError("Report differs from separate original model")
    return OciRegistrySignatureBindingsReport._owned(expected)


def verify_supplied_oci_registry_signature_bindings_bytes(
    report_bytes: bytes, *, model: Any,
) -> OciRegistrySignatureBindingsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise OciRegistrySignatureBindingsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise OciRegistrySignatureBindingsError("Exported report differs from original replay")
    return OciRegistrySignatureBindingsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-registry-bindings",
        "inventory_complete": True,
        "registry": {
            "host": "registry.example.test",
            "repository": "demo/service",
            "manifest_digest": "sha256:" + "a" * 64,
        },
        "signatures": [{
            "signature_id": "synthetic-signature-1",
            "artifact_digest": "sha256:" + "b" * 64,
            "subject_digest": "sha256:" + "a" * 64,
            "repository": "demo/service",
        }],
    }
