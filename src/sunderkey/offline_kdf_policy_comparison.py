"""Compare supplied KDF configuration numbers with a supplied local policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_kdf_policy_comparison"
PROFILE_ID = "AOE-GE-D22-S04"
CAPABILITY_ID = "army.ge.d22.s04"
VECTOR_ID = "AV-GE-D22-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S04"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GE-D22-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f8509d0353fdab542e9077fca15ebbdd2959afd06a03415e237b4ca1c4510002"
DOMAIN = "sunderkey.offline-kdf-policy-comparison.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_RECORDS = 256
MAX_NUMBER = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PARAMETERS = {
    "argon2id": {"memory_kib", "iterations", "parallelism"},
    "scrypt": {"cost_n", "block_size", "parallelism"},
    "pbkdf2_sha256": {"iterations"},
}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class KdfPolicyComparisonError(ValueError):
    """A supplied KDF model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise KdfPolicyComparisonError(f"{label} must be synthetic")
    return identifier


def _positive(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_NUMBER:
        raise KdfPolicyComparisonError(f"{label} must be a bounded positive integer")
    return value


def _parameters(value: Any, algorithm: str, label: str) -> dict:
    params = core.exact(value, PARAMETERS[algorithm], label)
    for name, number in params.items():
        _positive(number, name)
    if algorithm == "scrypt" and (
        params["cost_n"] < 2 or params["cost_n"] & (params["cost_n"] - 1)
    ):
        raise KdfPolicyComparisonError("scrypt cost_n must be a power of two")
    return params


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "records_complete",
            "policy_profiles", "records",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KdfPolicyComparisonError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    core.boolean(model["policy_complete"], "policy completeness")
    core.boolean(model["records_complete"], "record completeness")
    profiles = core.bounded_list(model["policy_profiles"], len(PARAMETERS), "profiles")
    seen_profiles: set[str] = set()
    for item in profiles:
        profile = core.exact(
            item,
            {"algorithm", "minimum_parameters", "minimum_salt_bytes", "minimum_output_bytes"},
            "policy profile",
        )
        algorithm = core.choice(profile["algorithm"], set(PARAMETERS), "algorithm")
        if algorithm in seen_profiles:
            raise KdfPolicyComparisonError("Duplicate policy algorithm")
        seen_profiles.add(algorithm)
        _parameters(profile["minimum_parameters"], algorithm, "minimum parameters")
        _positive(profile["minimum_salt_bytes"], "minimum salt bytes")
        _positive(profile["minimum_output_bytes"], "minimum output bytes")
    records = core.bounded_list(model["records"], MAX_RECORDS, "records")
    if not records:
        raise KdfPolicyComparisonError("At least one record is required")
    seen_records: set[str] = set()
    for item in records:
        row = core.exact(
            item,
            {"record_id", "algorithm", "parameters", "salt_bytes", "output_bytes", "active"},
            "record",
        )
        record_id = _synthetic(row["record_id"], "record ID")
        if record_id in seen_records:
            raise KdfPolicyComparisonError("Duplicate record ID")
        seen_records.add(record_id)
        algorithm = core.choice(row["algorithm"], set(PARAMETERS), "algorithm")
        _parameters(row["parameters"], algorithm, "record parameters")
        _positive(row["salt_bytes"], "salt bytes")
        _positive(row["output_bytes"], "output bytes")
        core.boolean(row["active"], "active")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    profiles = {item["algorithm"]: item for item in model["policy_profiles"]}
    complete = model["policy_complete"] and model["records_complete"]
    projections: list[dict] = []
    for row in model["records"]:
        profile = profiles.get(row["algorithm"])
        flags: list[str] = []
        if complete and row["active"]:
            if profile is None:
                flags.append("candidate_algorithm_absent_from_supplied_policy")
            else:
                for name in sorted(PARAMETERS[row["algorithm"]]):
                    if row["parameters"][name] < profile["minimum_parameters"][name]:
                        flags.append(f"candidate_{name}_below_supplied_minimum")
                if row["salt_bytes"] < profile["minimum_salt_bytes"]:
                    flags.append("candidate_salt_bytes_below_supplied_minimum")
                if row["output_bytes"] < profile["minimum_output_bytes"]:
                    flags.append("candidate_output_bytes_below_supplied_minimum")
        disposition = (
            "unknown_incomplete_declarations" if not complete
            else "not_assessed_retired" if not row["active"]
            else "candidate_declared_policy_mismatch" if flags
            else "no_declared_policy_mismatch"
        )
        projections.append({
            "record_id": row["record_id"],
            "algorithm": row["algorithm"],
            "active": row["active"],
            "disposition": disposition,
            "candidate_flags": flags,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "record_count": len(projections),
            "candidate_count": sum(
                item["disposition"] == "candidate_declared_policy_mismatch"
                for item in projections
            ),
            "unknown_count": sum(
                item["disposition"] == "unknown_incomplete_declarations"
                for item in projections
            ),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "deployed_configuration_observed": False,
        "password_or_hash_processed": False,
        "kdf_invoked": False,
        "cryptographic_strength_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All policy minima, configurations, activity labels and completeness are supplied.",
            "No default threshold or external cryptographic recommendation is asserted.",
            "A numeric policy mismatch does not prove deployed weakness or exploitability.",
            "No password, hash, salt value, credential or target response is processed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KPC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KdfPolicyComparisonReport:
    """Unsigned KDF policy projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KdfPolicyComparisonError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KdfPolicyComparisonReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kdf_policy(model: Any) -> KdfPolicyComparisonReport:
    try:
        return KdfPolicyComparisonReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise KdfPolicyComparisonError(str(exc)) from exc


def verify_supplied_kdf_policy(
    report: Any, *, model: Any,
) -> KdfPolicyComparisonReport:
    if type(report) is not KdfPolicyComparisonReport:
        raise KdfPolicyComparisonError("Exact report wrapper required")
    expected = analyze_supplied_kdf_policy(model)
    if report.to_json() != expected.to_json():
        raise KdfPolicyComparisonError("Report differs from separate original model")
    return expected


def verify_supplied_kdf_policy_bytes(
    report_bytes: bytes, *, model: Any,
) -> KdfPolicyComparisonReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise KdfPolicyComparisonError(str(exc)) from exc
    expected = analyze_supplied_kdf_policy(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise KdfPolicyComparisonError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:kdf-policy",
        "policy_complete": True,
        "records_complete": True,
        "policy_profiles": [
            {"algorithm": "argon2id",
             "minimum_parameters": {"memory_kib": 65536, "iterations": 3, "parallelism": 1},
             "minimum_salt_bytes": 16, "minimum_output_bytes": 32},
        ],
        "records": [
            {"record_id": "synthetic:configuration-one", "algorithm": "argon2id",
             "parameters": {"memory_kib": 32768, "iterations": 3, "parallelism": 1},
             "salt_bytes": 16, "output_bytes": 32, "active": True},
        ],
    }


__all__ = [
    "KdfPolicyComparisonError", "KdfPolicyComparisonReport",
    "analyze_supplied_kdf_policy", "verify_supplied_kdf_policy",
    "verify_supplied_kdf_policy_bytes", "component_fixture",
]
