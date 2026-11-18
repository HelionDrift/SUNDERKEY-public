"""Deterministic, non-operational qualification scenarios for Army v2 specialists."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError

CORPUS_DOMAIN = "sunderkey.specialist-scenario-corpus.v1"
SCENARIO_DOMAIN = "sunderkey.specialist-qualification-scenario.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")

SOURCE_SPECS = (
    ("expert_registry", "army-v2.json", "catalog_id", "catalog_version"),
    ("attack_vectors", "attack-vectors-v2.json", "catalog_id", "catalog_version"),
    ("capability_graph", "capabilities-army-v2.json", "catalog_id", "catalog_version"),
    (
        "qualification_plans",
        "qualification-plans-army-v2.json",
        "plan_catalog_id",
        "plan_catalog_version",
    ),
    (
        "candidate_blueprints",
        "candidate-blueprints-army-v2.json",
        "blueprint_catalog_id",
        "blueprint_catalog_version",
    ),
    (
        "commander_work_packages",
        "implementation-work-packages-v2.json",
        "package_catalog_id",
        "package_catalog_version",
    ),
)

VARIANT_DEFINITIONS = (
    {
        "variant_id": "positive_reproducible",
        "source_requirement": "Positive case with reproducible evidence.",
        "expected_disposition": "verified_or_negative_observation_with_reproducible_evidence",
        "proof_focus_id": "qualification.proof.positive-reproducibility",
    },
    {
        "variant_id": "negative_control",
        "source_requirement": "Negative case that must not be reported as a finding.",
        "expected_disposition": "negative_result_not_finding",
        "proof_focus_id": "qualification.proof.negative-control",
    },
    {
        "variant_id": "ambiguous_authority",
        "source_requirement": "Ambiguous authority or target case requiring abstention.",
        "expected_disposition": "abstention",
        "proof_focus_id": "qualification.proof.authority-abstention",
    },
    {
        "variant_id": "adversarial_evidence",
        "source_requirement": "Adversarial or misleading evidence case.",
        "expected_disposition": "evidence_rejected_or_qualified",
        "proof_focus_id": "qualification.proof.adversarial-evidence",
    },
    {
        "variant_id": "collaboration_conflict",
        "source_requirement": "Cross-specialist handoff and conflict-resolution case.",
        "expected_disposition": "typed_handoff_and_conflict_disposition",
        "proof_focus_id": "qualification.proof.collaboration-conflict",
    },
    {
        "variant_id": "restoration_verification",
        "source_requirement": "Cleanup, restoration, and residual-effect verification case.",
        "expected_disposition": "restoration_verified_or_escalated",
        "proof_focus_id": "qualification.proof.restoration-verification",
    },
)

_CATALOG_HASH_DOMAINS = {
    "attack_vectors": "sunderkey.attack-vector-catalog.v2",
    "qualification_plans": "sunderkey.qualification-plans-v2.v1",
    "candidate_blueprints": "sunderkey.candidate-blueprint-catalog.v2",
    "commander_work_packages": "sunderkey.implementation-work-packages.v2",
}


class SpecialistScenarioCorpusError(QualificationError):
    """Raised when source integrity or corpus invariants fail."""


@dataclass(frozen=True)
class ScenarioCorpusLimits:
    """Resource ceilings applied before and after corpus construction."""

    maximum_source_bytes: int = 8 * 1024 * 1024
    maximum_total_source_bytes: int = 16 * 1024 * 1024
    maximum_json_nodes_per_source: int = 500_000
    maximum_json_depth: int = 32
    maximum_specialists: int = 512
    maximum_scenarios: int = 3_072
    maximum_corpus_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise SpecialistScenarioCorpusError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class SpecialistScenarioCorpus:
    """Validated canonical scenario corpus."""

    corpus_id: str
    corpus_sha256: str
    scenarios: tuple[dict[str, Any], ...]
    gaps: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, Any]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise SpecialistScenarioCorpusError("Could not serialize canonical corpus data") from exc


def _canonical_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value).encode('ascii')).hexdigest()}"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpecialistScenarioCorpusError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _measure_json(value: Any) -> tuple[int, int]:
    count = 0
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        count += 1
        deepest = max(deepest, depth)
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise SpecialistScenarioCorpusError("JSON object keys must be text")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise SpecialistScenarioCorpusError("Source JSON contains an unsupported value")
    return count, deepest


def _file_state(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_source(path: Path, limits: ScenarioCorpusLimits) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SpecialistScenarioCorpusError(f"Could not inspect source artifact: {path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise SpecialistScenarioCorpusError(f"Source artifact must be a regular file: {path.name}")
    if before.st_size > limits.maximum_source_bytes:
        raise SpecialistScenarioCorpusError(f"Source artifact exceeds byte limit: {path.name}")
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _file_state(opened) != _file_state(before):
                raise SpecialistScenarioCorpusError(
                    f"Source artifact changed while opening: {path.name}"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read(limits.maximum_source_bytes + 1)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
    except OSError as exc:
        raise SpecialistScenarioCorpusError(f"Could not load source artifact: {path}") from exc
    if len(payload) > limits.maximum_source_bytes:
        raise SpecialistScenarioCorpusError(f"Source artifact exceeds byte limit: {path.name}")
    if (
        len(payload) != opened.st_size
        or not stat.S_ISREG(after_path.st_mode)
        or _file_state(after_open) != _file_state(opened)
        or _file_state(after_path) != _file_state(opened)
    ):
        raise SpecialistScenarioCorpusError(f"Source artifact changed while reading: {path.name}")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SpecialistScenarioCorpusError(f"Could not load source artifact: {path}") from exc
    if not isinstance(value, dict):
        raise SpecialistScenarioCorpusError(f"Source artifact must be an object: {path.name}")
    node_count, depth = _measure_json(value)
    if node_count > limits.maximum_json_nodes_per_source:
        raise SpecialistScenarioCorpusError(f"Source artifact exceeds node limit: {path.name}")
    if depth > limits.maximum_json_depth:
        raise SpecialistScenarioCorpusError(f"Source artifact exceeds depth limit: {path.name}")
    return value, payload


def _content_sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _declared_hash(document: dict[str, Any]) -> str | None:
    value = document.get("catalog_sha256")
    return value if isinstance(value, str) else None


def _verify_catalog_hash(role: str, document: dict[str, Any]) -> None:
    domain = _CATALOG_HASH_DOMAINS.get(role)
    if domain is None:
        return
    digest = document.get("catalog_sha256")
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise SpecialistScenarioCorpusError(f"{role} declared catalog hash is invalid")
    canonical = dict(document)
    canonical.pop("catalog_sha256")
    expected = _canonical_sha256({"domain": domain, "catalog": canonical})
    if digest != expected:
        raise SpecialistScenarioCorpusError(f"{role} declared catalog hash does not match content")


def _source_binding(
    role: str,
    artifact_name: str,
    id_field: str,
    version_field: str,
    document: dict[str, Any],
    payload: bytes,
) -> dict[str, Any]:
    artifact_id = document.get(id_field)
    artifact_version = document.get(version_field)
    if not isinstance(artifact_id, str) or not artifact_id:
        raise SpecialistScenarioCorpusError(f"{role} artifact ID is missing")
    if not isinstance(artifact_version, str) or not artifact_version:
        raise SpecialistScenarioCorpusError(f"{role} artifact version is missing")
    return {
        "source_role": role,
        "artifact_name": artifact_name,
        "artifact_id": artifact_id,
        "artifact_version": artifact_version,
        "content_sha256": _content_sha256(payload),
        "canonical_sha256": _canonical_sha256(document),
        "declared_catalog_sha256": _declared_hash(document),
    }


def _verify_source_set(documents: dict[str, dict[str, Any]]) -> None:
    for role, document in documents.items():
        _verify_catalog_hash(role, document)

    registry = documents["expert_registry"]
    vectors = documents["attack_vectors"]
    capabilities = documents["capability_graph"]
    plans = documents["qualification_plans"]
    blueprints = documents["candidate_blueprints"]
    packages = documents["commander_work_packages"]

    expert_hash = _canonical_sha256(registry)
    capability_hash = _canonical_sha256(capabilities)
    checks = (
        (vectors.get("expert_catalog_id"), registry.get("catalog_id"), "vector expert ID"),
        (
            vectors.get("expert_catalog_version"),
            registry.get("catalog_version"),
            "vector expert version",
        ),
        (plans.get("expert_catalog_id"), registry.get("catalog_id"), "plan expert ID"),
        (
            plans.get("expert_catalog_version"),
            registry.get("catalog_version"),
            "plan expert version",
        ),
        (
            plans.get("capability_catalog_id"),
            capabilities.get("catalog_id"),
            "plan capability ID",
        ),
        (
            plans.get("capability_catalog_version"),
            capabilities.get("catalog_version"),
            "plan capability version",
        ),
        (plans.get("capability_catalog_sha256"), capability_hash, "plan capability hash"),
        (
            plans.get("vector_catalog_sha256"),
            vectors.get("catalog_sha256"),
            "plan vector hash",
        ),
        (
            blueprints.get("expert_catalog_sha256"),
            expert_hash,
            "blueprint expert hash",
        ),
        (
            blueprints.get("capability_catalog_sha256"),
            capability_hash,
            "blueprint capability hash",
        ),
        (
            blueprints.get("vector_catalog_sha256"),
            vectors.get("catalog_sha256"),
            "blueprint vector hash",
        ),
        (
            blueprints.get("qualification_plan_catalog_sha256"),
            plans.get("catalog_sha256"),
            "blueprint qualification plan hash",
        ),
        (packages.get("expert_catalog_sha256"), expert_hash, "package expert hash"),
        (
            packages.get("capability_catalog_sha256"),
            capability_hash,
            "package capability hash",
        ),
        (
            packages.get("vector_catalog_sha256"),
            vectors.get("catalog_sha256"),
            "package vector hash",
        ),
        (
            packages.get("qualification_plan_catalog_sha256"),
            plans.get("catalog_sha256"),
            "package qualification plan hash",
        ),
        (
            packages.get("blueprint_catalog_sha256"),
            blueprints.get("catalog_sha256"),
            "package blueprint hash",
        ),
    )
    for actual, expected, label in checks:
        if actual != expected:
            raise SpecialistScenarioCorpusError(f"Source binding mismatch: {label}")

    for document, fields, label in (
        (plans, ("qualification_effect",), "qualification plan"),
        (
            blueprints,
            ("qualification_effect", "routing_effect", "execution_effect", "deployment_effect"),
            "candidate blueprint",
        ),
        (
            packages,
            ("qualification_effect", "routing_effect", "execution_effect", "deployment_effect"),
            "commander work package",
        ),
    ):
        if any(document.get(field) != "none" for field in fields):
            raise SpecialistScenarioCorpusError(f"{label} source has a non-none effect")


def _records(document: dict[str, Any], field: str, id_field: str) -> dict[str, dict[str, Any]]:
    values = document.get(field)
    if not isinstance(values, list):
        raise SpecialistScenarioCorpusError(f"Source field must be a list: {field}")
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict):
            raise SpecialistScenarioCorpusError(f"Source field contains a non-object: {field}")
        record_id = value.get(id_field)
        if not isinstance(record_id, str) or not record_id:
            raise SpecialistScenarioCorpusError(f"Source record ID is invalid: {field}")
        if record_id in result:
            raise SpecialistScenarioCorpusError(f"Source record ID is duplicated: {record_id}")
        result[record_id] = value
    return result


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return None
    if len(value) != len(set(value)):
        return None
    return list(value)


def _safe_proof_identifiers(
    vector: dict[str, Any],
    plan: dict[str, Any],
    blueprint: dict[str, Any],
    package: dict[str, Any],
    variant: dict[str, str],
) -> list[str] | None:
    values = [
        vector.get("vector_id"),
        vector.get("qualification_scenario_id"),
        blueprint.get("blueprint_sha256"),
        package.get("package_id"),
        variant["proof_focus_id"],
        *(_string_list(plan.get("primary_capability_ids")) or []),
        *(_string_list(plan.get("supporting_capability_ids")) or []),
        *(_string_list(plan.get("required_gate_ids")) or []),
    ]
    if any(
        not isinstance(value, str) or SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None
        for value in values
    ):
        return None
    return list(dict.fromkeys(values))


def _profile_gap_reasons(
    profile: dict[str, Any],
    command: dict[str, Any] | None,
    vector: dict[str, Any] | None,
    capability: dict[str, Any] | None,
    plan: dict[str, Any] | None,
    blueprint: dict[str, Any] | None,
    package: dict[str, Any] | None,
) -> list[str]:
    reasons: list[str] = []
    records = (
        ("missing_command", command),
        ("missing_vector", vector),
        ("missing_capability_assignment", capability),
        ("missing_qualification_plan", plan),
        ("missing_candidate_blueprint", blueprint),
        ("missing_commander_work_package", package),
    )
    reasons.extend(code for code, record in records if record is None)
    if reasons:
        return reasons
    assert command is not None
    assert vector is not None
    assert capability is not None
    assert plan is not None
    assert blueprint is not None
    assert package is not None

    profile_id = profile["id"]
    binding_checks = (
        (vector.get("primary_specialist_id") == profile_id, "vector_profile_mismatch"),
        (plan.get("vector_id") == vector.get("vector_id"), "plan_vector_mismatch"),
        (blueprint.get("vector_id") == vector.get("vector_id"), "blueprint_vector_mismatch"),
        (package.get("vector_id") == vector.get("vector_id"), "package_vector_mismatch"),
        (
            plan.get("scenario_family_id") == vector.get("qualification_scenario_id"),
            "plan_scenario_family_mismatch",
        ),
        (
            blueprint.get("scenario_family_id") == vector.get("qualification_scenario_id"),
            "blueprint_scenario_family_mismatch",
        ),
        (
            plan.get("primary_capability_ids") == capability.get("primary_capability_ids"),
            "plan_primary_capability_mismatch",
        ),
        (
            plan.get("supporting_capability_ids") == capability.get("supporting_capability_ids"),
            "plan_supporting_capability_mismatch",
        ),
        (
            blueprint.get("primary_capability_ids") == capability.get("primary_capability_ids"),
            "blueprint_primary_capability_mismatch",
        ),
        (
            blueprint.get("supporting_capability_ids")
            == capability.get("supporting_capability_ids"),
            "blueprint_supporting_capability_mismatch",
        ),
        (
            package.get("primary_capability_ids") == capability.get("primary_capability_ids"),
            "package_primary_capability_mismatch",
        ),
        (
            package.get("supporting_capability_ids") == capability.get("supporting_capability_ids"),
            "package_supporting_capability_mismatch",
        ),
        (
            plan.get("independent_validator_id") == vector.get("independent_validator_id"),
            "plan_validator_mismatch",
        ),
        (
            blueprint.get("independent_validator_id") == vector.get("independent_validator_id"),
            "blueprint_validator_mismatch",
        ),
        (
            package.get("independent_validator_id") == vector.get("independent_validator_id"),
            "package_validator_mismatch",
        ),
        (profile.get("command_id") == command.get("id"), "profile_command_mismatch"),
        (blueprint.get("command_id") == command.get("id"), "blueprint_command_mismatch"),
        (package.get("command_id") == command.get("id"), "package_command_mismatch"),
        (
            package.get("commander_profile_id") == command.get("commander_profile_id"),
            "package_commander_mismatch",
        ),
        (
            plan.get("allowed_action_tiers") == vector.get("allowed_action_tiers"),
            "plan_action_tier_mismatch",
        ),
        (
            blueprint.get("allowed_action_tiers") == vector.get("allowed_action_tiers"),
            "blueprint_action_tier_mismatch",
        ),
        (
            package.get("blueprint_sha256") == blueprint.get("blueprint_sha256"),
            "package_blueprint_hash_mismatch",
        ),
    )
    reasons.extend(code for valid, code in binding_checks if not valid)

    list_requirements = (
        (vector.get("prerequisites_and_observations"), "missing_prerequisite_observations"),
        (plan.get("required_evidence"), "missing_expected_evidence"),
        (blueprint.get("prohibited_actions"), "missing_prohibited_action_controls"),
        (blueprint.get("stop_conditions"), "missing_stop_controls"),
        (blueprint.get("critical_failures"), "missing_critical_failure_controls"),
        (blueprint.get("restoration_contract"), "missing_restoration_checks"),
        (blueprint.get("known_blind_spots"), "missing_known_blind_spots"),
        (plan.get("required_gate_ids"), "missing_qualification_gates"),
    )
    reasons.extend(code for value, code in list_requirements if _string_list(value) is None)

    expected_variants = [item["source_requirement"] for item in VARIANT_DEFINITIONS]
    if plan.get("required_scenario_variants") != expected_variants:
        reasons.append("qualification_plan_variant_set_mismatch")
    if blueprint.get("required_scenario_variants") != expected_variants:
        reasons.append("candidate_blueprint_variant_set_mismatch")

    maximum_tier = blueprint.get("maximum_autonomous_action_tier")
    if not isinstance(maximum_tier, str) or maximum_tier not in (
        vector.get("allowed_action_tiers") or []
    ):
        reasons.append("invalid_action_tier_ceiling")
    for variant in VARIANT_DEFINITIONS:
        if _safe_proof_identifiers(vector, plan, blueprint, package, variant) is None:
            reasons.append("invalid_safe_proof_identifier")
            break
    return sorted(set(reasons))


def _build_scenario(
    profile: dict[str, Any],
    vector: dict[str, Any],
    capability: dict[str, Any],
    plan: dict[str, Any],
    blueprint: dict[str, Any],
    package: dict[str, Any],
    variant: dict[str, str],
    source_hashes: dict[str, str],
) -> dict[str, Any]:
    proof_ids = _safe_proof_identifiers(vector, plan, blueprint, package, variant)
    if proof_ids is None:
        raise SpecialistScenarioCorpusError("Safe proof identifiers were not validated")
    scenario = {
        "profile_id": profile["id"],
        "profile_version": profile["version"],
        "variant_id": variant["variant_id"],
        "variant_requirement": variant["source_requirement"],
        "expected_disposition": variant["expected_disposition"],
        "scenario_family_id": vector["qualification_scenario_id"],
        "vector_id": vector["vector_id"],
        "primary_capability_ids": capability["primary_capability_ids"],
        "supporting_capability_ids": capability["supporting_capability_ids"],
        "prerequisite_observations": vector["prerequisites_and_observations"],
        "safe_proof_identifiers": proof_ids,
        "negative_controls": {
            "prohibited_actions": blueprint["prohibited_actions"],
            "stop_conditions": blueprint["stop_conditions"],
            "critical_failures": blueprint["critical_failures"],
        },
        "restoration_checks": blueprint["restoration_contract"],
        "expected_evidence": plan["required_evidence"],
        "independent_validator_ids": [vector["independent_validator_id"]],
        "commander_binding": {
            "command_id": profile["command_id"],
            "commander_profile_id": package["commander_profile_id"],
            "group_commander_profile_id": package["group_commander_profile_id"],
            "work_package_id": package["package_id"],
        },
        "action_tier": {
            "allowed_action_tiers": vector["allowed_action_tiers"],
            "maximum_permitted_action_tier": blueprint["maximum_autonomous_action_tier"],
        },
        "known_blind_spots": blueprint["known_blind_spots"],
        "source_binding_sha256s": source_hashes,
        "qualification_effect": "none",
        "routing_effect": "none",
        "authority_effect": "none",
        "execution_effect": "none",
    }
    scenario_sha256 = _canonical_sha256({"domain": SCENARIO_DOMAIN, "scenario": scenario})
    return {
        "scenario_id": f"QSC-{scenario_sha256[7:39].upper()}",
        "scenario_sha256": scenario_sha256,
        **scenario,
    }


def build_specialist_scenario_corpus(
    registry_directory: str | Path,
    *,
    limits: ScenarioCorpusLimits | None = None,
) -> SpecialistScenarioCorpus:
    """Build the corpus from the six reviewed Army v2 registry artifacts."""

    active_limits = limits or ScenarioCorpusLimits()
    registry_path = Path(registry_directory)
    documents: dict[str, dict[str, Any]] = {}
    source_bindings: list[dict[str, Any]] = []
    total_source_bytes = 0
    for role, artifact_name, id_field, version_field in SOURCE_SPECS:
        document, payload = _read_source(registry_path / artifact_name, active_limits)
        total_source_bytes += len(payload)
        if total_source_bytes > active_limits.maximum_total_source_bytes:
            raise SpecialistScenarioCorpusError("Source artifacts exceed total byte limit")
        documents[role] = document
        source_bindings.append(
            _source_binding(
                role,
                artifact_name,
                id_field,
                version_field,
                document,
                payload,
            )
        )
    _verify_source_set(documents)

    profiles = _records(documents["expert_registry"], "profiles", "id")
    specialists = [profile for profile in profiles.values() if profile.get("kind") == "specialist"]
    specialists.sort(key=lambda item: item["id"])
    if len(specialists) > active_limits.maximum_specialists:
        raise SpecialistScenarioCorpusError("Specialist count exceeds resource limit")
    expected_scenario_count = len(specialists) * len(VARIANT_DEFINITIONS)
    if expected_scenario_count > active_limits.maximum_scenarios:
        raise SpecialistScenarioCorpusError("Expected scenario count exceeds resource limit")

    commands = _records(documents["expert_registry"], "commands", "id")
    vectors = _records(documents["attack_vectors"], "vectors", "primary_specialist_id")
    capabilities = _records(documents["capability_graph"], "profile_assignments", "profile_id")
    plans = _records(documents["qualification_plans"], "profile_plans", "profile_id")
    blueprints = _records(documents["candidate_blueprints"], "blueprints", "profile_id")
    packages = _records(documents["commander_work_packages"], "packages", "profile_id")
    specialist_ids = {item["id"] for item in specialists}
    for label, index in (
        ("vector", vectors),
        ("capability assignment", capabilities),
        ("qualification plan", plans),
        ("candidate blueprint", blueprints),
        ("commander work package", packages),
    ):
        unknown = sorted(set(index) - specialist_ids)
        if unknown:
            raise SpecialistScenarioCorpusError(
                f"{label} source contains unknown specialist: {unknown[0]}"
            )

    source_hashes = {item["source_role"]: item["content_sha256"] for item in source_bindings}
    scenarios: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for profile in specialists:
        profile_id = profile["id"]
        command = commands.get(profile.get("command_id"))
        vector = vectors.get(profile_id)
        capability = capabilities.get(profile_id)
        plan = plans.get(profile_id)
        blueprint = blueprints.get(profile_id)
        package = packages.get(profile_id)
        reasons = _profile_gap_reasons(
            profile, command, vector, capability, plan, blueprint, package
        )
        if reasons:
            gaps.append({"profile_id": profile_id, "reason_codes": reasons})
            continue
        assert vector is not None
        assert capability is not None
        assert plan is not None
        assert blueprint is not None
        assert package is not None
        for variant in VARIANT_DEFINITIONS:
            scenarios.append(
                _build_scenario(
                    profile,
                    vector,
                    capability,
                    plan,
                    blueprint,
                    package,
                    variant,
                    source_hashes,
                )
            )

    scenario_ids = [item["scenario_id"] for item in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise SpecialistScenarioCorpusError("Scenario ID collision detected")
    gap_reason_counts = Counter(reason for gap in gaps for reason in gap["reason_codes"])
    eligible_profiles = len(specialists) - len(gaps)
    coverage_summary = {
        "specialist_profile_count": len(specialists),
        "eligible_profile_count": eligible_profiles,
        "gap_profile_count": len(gaps),
        "required_variants_per_profile": len(VARIANT_DEFINITIONS),
        "expected_scenario_count": expected_scenario_count,
        "scenario_count": len(scenarios),
        "missing_scenario_count": expected_scenario_count - len(scenarios),
        "gap_reason_counts": dict(sorted(gap_reason_counts.items())),
        "complete": not gaps and len(scenarios) == expected_scenario_count,
    }
    corpus = {
        "schema_version": 1,
        "corpus_version": "1.0.0",
        "corpus_status": "complete" if coverage_summary["complete"] else "gaps_preserved",
        "source_bindings": source_bindings,
        "variant_definitions": [dict(item) for item in VARIANT_DEFINITIONS],
        "coverage_summary": coverage_summary,
        "scenarios": scenarios,
        "gaps": gaps,
        "qualification_effect": "none",
        "routing_effect": "none",
        "authority_effect": "none",
        "execution_effect": "none",
        "limitations": [
            "The corpus defines qualification evidence expectations and grants no authority.",
            (
                "Scenarios contain no exploit payloads, target instructions, credentials, "
                "or endpoints."
            ),
            "Source omissions remain explicit gaps and are not replaced with inferred detail.",
            "A scenario does not qualify, route, authorize, dispatch, or execute a specialist.",
        ],
    }
    corpus_sha256 = _canonical_sha256({"domain": CORPUS_DOMAIN, "corpus": corpus})
    document = {
        "corpus_id": f"QCP-{corpus_sha256[7:39].upper()}",
        "corpus_sha256": corpus_sha256,
        **corpus,
    }
    document_json = _canonical_json(document)
    if len(document_json.encode("ascii")) > active_limits.maximum_corpus_bytes:
        raise SpecialistScenarioCorpusError("Generated corpus exceeds byte limit")
    validate_specialist_scenario_corpus(document)
    return SpecialistScenarioCorpus(
        corpus_id=document["corpus_id"],
        corpus_sha256=corpus_sha256,
        scenarios=tuple(scenarios),
        gaps=tuple(gaps),
        coverage_summary=coverage_summary,
        document_json=document_json,
    )


def validate_specialist_scenario_corpus(document: Any) -> None:
    """Validate content addresses, uniqueness, coverage, and zero effects."""

    if not isinstance(document, dict):
        raise SpecialistScenarioCorpusError("Scenario corpus must be an object")
    required_fields = {
        "corpus_id",
        "corpus_sha256",
        "schema_version",
        "corpus_version",
        "corpus_status",
        "source_bindings",
        "variant_definitions",
        "coverage_summary",
        "scenarios",
        "gaps",
        "qualification_effect",
        "routing_effect",
        "authority_effect",
        "execution_effect",
        "limitations",
    }
    if set(document) != required_fields:
        raise SpecialistScenarioCorpusError("Scenario corpus fields are invalid")
    if document.get("schema_version") != 1 or document.get("corpus_version") != "1.0.0":
        raise SpecialistScenarioCorpusError("Scenario corpus version is invalid")
    if any(
        document.get(field) != "none"
        for field in (
            "qualification_effect",
            "routing_effect",
            "authority_effect",
            "execution_effect",
        )
    ):
        raise SpecialistScenarioCorpusError("Scenario corpus effects must be none")
    bindings = document.get("source_bindings")
    if not isinstance(bindings, list) or len(bindings) != len(SOURCE_SPECS):
        raise SpecialistScenarioCorpusError("Scenario corpus source bindings are invalid")
    roles = [item.get("source_role") for item in bindings if isinstance(item, dict)]
    if roles != [item[0] for item in SOURCE_SPECS]:
        raise SpecialistScenarioCorpusError("Scenario corpus source binding order is invalid")
    expected_source_hashes: dict[str, str] = {}
    for binding in bindings:
        for field in ("content_sha256", "canonical_sha256"):
            value = binding.get(field)
            if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
                raise SpecialistScenarioCorpusError("Scenario corpus source hash is invalid")
        expected_source_hashes[binding["source_role"]] = binding["content_sha256"]

    if document.get("variant_definitions") != [dict(item) for item in VARIANT_DEFINITIONS]:
        raise SpecialistScenarioCorpusError("Scenario corpus variant definitions are invalid")

    scenarios = document.get("scenarios")
    gaps = document.get("gaps")
    coverage = document.get("coverage_summary")
    if (
        not isinstance(scenarios, list)
        or not isinstance(gaps, list)
        or not isinstance(coverage, dict)
    ):
        raise SpecialistScenarioCorpusError("Scenario corpus collections are invalid")
    scenario_ids: set[str] = set()
    scenario_profiles: Counter[str] = Counter()
    variants_by_profile: dict[str, set[str]] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise SpecialistScenarioCorpusError("Scenario entry must be an object")
        scenario_id = scenario.get("scenario_id")
        scenario_sha256 = scenario.get("scenario_sha256")
        if not isinstance(scenario_id, str) or scenario_id in scenario_ids:
            raise SpecialistScenarioCorpusError("Scenario ID is invalid or duplicated")
        if (
            not isinstance(scenario_sha256, str)
            or SHA256_PATTERN.fullmatch(scenario_sha256) is None
        ):
            raise SpecialistScenarioCorpusError("Scenario hash is invalid")
        body = dict(scenario)
        body.pop("scenario_id")
        body.pop("scenario_sha256")
        expected = _canonical_sha256({"domain": SCENARIO_DOMAIN, "scenario": body})
        if scenario_sha256 != expected or scenario_id != f"QSC-{expected[7:39].upper()}":
            raise SpecialistScenarioCorpusError("Scenario content address is invalid")
        if any(
            scenario.get(field) != "none"
            for field in (
                "qualification_effect",
                "routing_effect",
                "authority_effect",
                "execution_effect",
            )
        ):
            raise SpecialistScenarioCorpusError("Scenario effects must be none")
        if scenario.get("source_binding_sha256s") != expected_source_hashes:
            raise SpecialistScenarioCorpusError("Scenario source hashes are invalid")
        profile_id = scenario.get("profile_id")
        variant_id = scenario.get("variant_id")
        if not isinstance(profile_id, str) or not isinstance(variant_id, str):
            raise SpecialistScenarioCorpusError("Scenario profile or variant is invalid")
        profile_variants = variants_by_profile.setdefault(profile_id, set())
        if variant_id in profile_variants:
            raise SpecialistScenarioCorpusError("Scenario variant is duplicated for a profile")
        profile_variants.add(variant_id)
        scenario_ids.add(scenario_id)
        scenario_profiles[profile_id] += 1
    expected_variants = {item["variant_id"] for item in VARIANT_DEFINITIONS}
    if any(variants != expected_variants for variants in variants_by_profile.values()):
        raise SpecialistScenarioCorpusError("Eligible profiles must have every scenario variant")
    gap_profiles: set[str] = set()
    observed_gap_reasons: Counter[str] = Counter()
    for gap in gaps:
        if not isinstance(gap, dict):
            raise SpecialistScenarioCorpusError("Gap entry must be an object")
        profile_id = gap.get("profile_id")
        reasons = gap.get("reason_codes")
        if (
            not isinstance(profile_id, str)
            or profile_id in gap_profiles
            or profile_id in scenario_profiles
            or not isinstance(reasons, list)
            or not reasons
            or len(reasons) != len(set(reasons))
            or any(not isinstance(reason, str) or not reason for reason in reasons)
        ):
            raise SpecialistScenarioCorpusError("Gap entry is invalid or duplicated")
        gap_profiles.add(profile_id)
        observed_gap_reasons.update(reasons)
    if coverage.get("scenario_count") != len(scenarios):
        raise SpecialistScenarioCorpusError("Scenario coverage count is invalid")
    if coverage.get("gap_profile_count") != len(gaps):
        raise SpecialistScenarioCorpusError("Gap coverage count is invalid")
    if coverage.get("eligible_profile_count") != len(scenario_profiles):
        raise SpecialistScenarioCorpusError("Eligible profile coverage count is invalid")
    if coverage.get("specialist_profile_count") != len(scenario_profiles) + len(gaps):
        raise SpecialistScenarioCorpusError("Specialist profile coverage count is invalid")
    if coverage.get("required_variants_per_profile") != len(VARIANT_DEFINITIONS):
        raise SpecialistScenarioCorpusError("Required variant coverage count is invalid")
    if coverage.get("expected_scenario_count") != (
        coverage["specialist_profile_count"] * len(VARIANT_DEFINITIONS)
    ):
        raise SpecialistScenarioCorpusError("Expected scenario coverage count is invalid")
    if coverage.get("missing_scenario_count") != len(gaps) * len(VARIANT_DEFINITIONS):
        raise SpecialistScenarioCorpusError("Missing scenario coverage count is invalid")
    if coverage.get("gap_reason_counts") != dict(sorted(observed_gap_reasons.items())):
        raise SpecialistScenarioCorpusError("Gap reason coverage counts are invalid")
    if coverage.get("complete") != (not gaps):
        raise SpecialistScenarioCorpusError("Scenario corpus completion state is invalid")
    if document.get("corpus_status") != ("complete" if not gaps else "gaps_preserved"):
        raise SpecialistScenarioCorpusError("Scenario corpus status is invalid")
    canonical = dict(document)
    corpus_id = canonical.pop("corpus_id", None)
    corpus_sha256 = canonical.pop("corpus_sha256", None)
    expected_corpus_hash = _canonical_sha256({"domain": CORPUS_DOMAIN, "corpus": canonical})
    if (
        corpus_sha256 != expected_corpus_hash
        or corpus_id != f"QCP-{expected_corpus_hash[7:39].upper()}"
    ):
        raise SpecialistScenarioCorpusError("Scenario corpus content address is invalid")


__all__ = [
    "CORPUS_DOMAIN",
    "SCENARIO_DOMAIN",
    "SOURCE_SPECS",
    "VARIANT_DEFINITIONS",
    "ScenarioCorpusLimits",
    "SpecialistScenarioCorpus",
    "SpecialistScenarioCorpusError",
    "build_specialist_scenario_corpus",
    "validate_specialist_scenario_corpus",
]
