"""Compare supplied Docker or Podman runtime declarations without execution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "container_supplied_runtime_declarations"
PROFILE_ID = "AOE-GC-D15-S02"
CAPABILITY_ID = "army.gc.d15.s02"
VECTOR_ID = "AV-GC-D15-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S02"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:573a431ccd945728db70504d442ae7d806103f4c5beac952ef81515108c8c0c6"
DOMAIN = "sunderkey.offline-container-runtime-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class ContainerRuntimeDeclarationsError(ValueError):
    """A supplied runtime declaration or original-source replay is invalid."""


def _model(value: Any) -> tuple[dict, str, dict[str, dict]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "runtime_inventory_complete", "runtimes", "checks"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ContainerRuntimeDeclarationsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["runtime_inventory_complete"], "runtime inventory completeness")
    runtimes: dict[str, dict] = {}
    for row in core.bounded_list(model["runtimes"], 64, "runtimes"):
        runtime = core.exact(
            row,
            {
                "runtime_id",
                "engine",
                "rootless",
                "user_namespace_enabled",
                "remote_api_enabled",
            },
            "runtime",
        )
        runtime_id = core.identifier(runtime["runtime_id"], "runtime ID")
        if runtime_id in runtimes:
            raise ContainerRuntimeDeclarationsError("Duplicate runtime ID")
        core.choice(runtime["engine"], {"docker", "podman"}, "engine")
        for field in ("rootless", "user_namespace_enabled", "remote_api_enabled"):
            core.boolean(runtime[field], field)
        runtimes[runtime_id] = runtime
    check_ids: set[str] = set()
    for row in core.bounded_list(model["checks"], 128, "checks"):
        check = core.exact(
            row,
            {
                "check_id",
                "runtime_id",
                "expected_engine",
                "require_rootless",
                "require_user_namespace",
                "require_remote_api_disabled",
                "claimed_compliant",
                "context_complete",
            },
            "check",
        )
        check_id = core.identifier(check["check_id"], "check ID")
        if check_id in check_ids:
            raise ContainerRuntimeDeclarationsError("Duplicate check ID")
        check_ids.add(check_id)
        core.identifier(check["runtime_id"], "referenced runtime ID")
        core.choice(check["expected_engine"], {"docker", "podman"}, "expected engine")
        for field in (
            "require_rootless",
            "require_user_namespace",
            "require_remote_api_disabled",
            "claimed_compliant",
            "context_complete",
        ):
            core.boolean(check[field], field)
    return model, core.canonical(model), runtimes


def _derive(value: Any) -> dict:
    model, source_text, runtimes = _model(value)
    rows = []
    for check in sorted(model["checks"], key=lambda row: row["check_id"]):
        runtime = runtimes.get(check["runtime_id"])
        reasons = []
        unknown = not check["context_complete"]
        if runtime is None:
            if model["runtime_inventory_complete"]:
                reasons.append("runtime_absent_from_complete_inventory")
            else:
                unknown = True
        else:
            if runtime["engine"] != check["expected_engine"]:
                reasons.append("engine_declaration_mismatch")
            if check["require_rootless"] and not runtime["rootless"]:
                reasons.append("rootless_requirement_not_declared")
            if check["require_user_namespace"] and not runtime["user_namespace_enabled"]:
                reasons.append("user_namespace_requirement_not_declared")
            if check["require_remote_api_disabled"] and runtime["remote_api_enabled"]:
                reasons.append("remote_api_declared_enabled")
        projected = None if unknown else not reasons
        disposition = (
            "unknown_supplied_context"
            if projected is None
            else "candidate_claim_conflict"
            if projected != check["claimed_compliant"]
            else "supplied_claim_consistent"
        )
        rows.append(
            {
                "check_id": check["check_id"],
                "runtime_id": check["runtime_id"],
                "reasons": reasons,
                "projected_compliant": projected,
                "claimed_compliant": check["claimed_compliant"],
                "disposition": disposition,
            }
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
        "runtime_count": len(runtimes),
        "check_count": len(rows),
        "rows": rows,
        "candidate_count": sum(row["disposition"] == "candidate_claim_conflict" for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown_supplied_context" for row in rows),
        "source_authenticated": False,
        "runtime_inspected": False,
        "container_started": False,
        "socket_contacted": False,
        "network_contacted": False,
        "configuration_changed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All runtime declarations, requirements, claims and completeness flags are supplied.",
            "Comparisons express caller-supplied policy, not Docker or Podman conformance.",
            "No runtime, container, socket, daemon, image or endpoint is inspected or contacted.",
            "A claim conflict is an unsigned review candidate, not proof of runtime exposure.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CRD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ContainerRuntimeDeclarationsReport:
    """Unsigned runtime projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ContainerRuntimeDeclarationsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ContainerRuntimeDeclarationsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_container_runtime_declarations(
    model: Any,
) -> ContainerRuntimeDeclarationsReport:
    return ContainerRuntimeDeclarationsReport._owned(_derive(model))


def verify_supplied_container_runtime_declarations(
    report: Any, *, model: Any
) -> ContainerRuntimeDeclarationsReport:
    if type(report) is not ContainerRuntimeDeclarationsReport:
        raise ContainerRuntimeDeclarationsError("Exact runtime report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ContainerRuntimeDeclarationsError("Report differs from separate original model")
    return ContainerRuntimeDeclarationsReport._owned(expected)


def verify_supplied_container_runtime_declarations_bytes(
    report_bytes: bytes, *, model: Any
) -> ContainerRuntimeDeclarationsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ContainerRuntimeDeclarationsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ContainerRuntimeDeclarationsError("Exported report differs from original replay")
    return ContainerRuntimeDeclarationsReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-container-runtime-declarations",
        "runtime_inventory_complete": True,
        "runtimes": [
            {
                "runtime_id": "runtime-a",
                "engine": "podman",
                "rootless": False,
                "user_namespace_enabled": True,
                "remote_api_enabled": False,
            }
        ],
        "checks": [
            {
                "check_id": "check-a",
                "runtime_id": "runtime-a",
                "expected_engine": "podman",
                "require_rootless": True,
                "require_user_namespace": True,
                "require_remote_api_disabled": True,
                "claimed_compliant": True,
                "context_complete": True,
            }
        ],
    }
