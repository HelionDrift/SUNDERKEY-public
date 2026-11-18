"""Compare supplied ROS 2 deployment security labels with protected-topic intent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ros2_supplied_security_declaration_gap"
PROFILE_ID = "AOE-GD-D19-S18"
CAPABILITY_ID = "army.gd.d19.s18"
VECTOR_ID = "AV-GD-D19-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S18"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:5adafbb100ea3b4fa4cdc11dae2a4fe0c13155afb0a824fb8114c0c2bf2e5109"
DOMAIN = "sunderkey.offline-ros2-security-declaration.v1"
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


class Ros2SecurityDeclarationError(ValueError):
    """A supplied ROS 2 declaration or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "deployments"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise Ros2SecurityDeclarationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    deployments = core.bounded_list(model["deployments"], 32, "deployments")
    if not deployments:
        raise Ros2SecurityDeclarationError("At least one deployment is required")
    seen: set[str] = set()
    for item in deployments:
        row = core.exact(
            item,
            {
                "deployment_id",
                "protected_topic_ids",
                "authentication_required",
                "security_enabled",
                "strict_enforcement",
                "allow_unauthenticated_participants",
                "join_access_control",
                "context_complete",
            },
            "deployment",
        )
        deployment_id = core.identifier(row["deployment_id"], "deployment ID")
        if deployment_id in seen:
            raise Ros2SecurityDeclarationError("Duplicate deployment ID")
        seen.add(deployment_id)
        topics = core.bounded_list(row["protected_topic_ids"], 32, "protected topic IDs")
        topic_ids = [core.identifier(item, "topic ID") for item in topics]
        if len(set(topic_ids)) != len(topic_ids):
            raise Ros2SecurityDeclarationError("Duplicate topic ID")
        for key in (
            "authentication_required",
            "security_enabled",
            "strict_enforcement",
            "allow_unauthenticated_participants",
            "join_access_control",
            "context_complete",
        ):
            core.boolean(row[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["deployments"]:
        gaps = []
        if not row["security_enabled"]:
            gaps.append("security_disabled")
        if not row["strict_enforcement"]:
            gaps.append("strict_enforcement_disabled")
        if row["allow_unauthenticated_participants"]:
            gaps.append("unauthenticated_participants_allowed")
        if not row["join_access_control"]:
            gaps.append("join_access_control_disabled")
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_ros2_security_gap"
            if row["authentication_required"] and row["protected_topic_ids"] and gaps
            else "no_declared_ros2_security_gap"
        )
        projections.append(
            {
                "deployment_id": row["deployment_id"],
                "protected_topic_ids": sorted(row["protected_topic_ids"]),
                "unmet_control_labels": gaps,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "deployment_count": len(model["deployments"]),
        "deployment_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "ros_runtime_queried": False,
        "dds_policy_parsed": False,
        "effective_participant_access_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Deployment intent, protected topic IDs and security controls are caller-supplied.",
            "No signed governance, permissions, certificate or running participant is inspected.",
            "A declared control gap does not prove a usable DDS or ROS 2 access path.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RSD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class Ros2SecurityDeclarationReport:
    """Unsigned ROS 2 policy projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise Ros2SecurityDeclarationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> Ros2SecurityDeclarationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ros2_security(model: Any) -> Ros2SecurityDeclarationReport:
    return Ros2SecurityDeclarationReport._owned(_derive(model))


def verify_supplied_ros2_security(
    report: Any, *, model: Any
) -> Ros2SecurityDeclarationReport:
    if type(report) is not Ros2SecurityDeclarationReport:
        raise Ros2SecurityDeclarationError("Exact ROS 2 security wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise Ros2SecurityDeclarationError("Report differs from separate original model")
    return Ros2SecurityDeclarationReport._owned(expected)


def verify_supplied_ros2_security_bytes(
    report_bytes: bytes, *, model: Any
) -> Ros2SecurityDeclarationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise Ros2SecurityDeclarationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise Ros2SecurityDeclarationError("Exported report differs from original replay")
    return Ros2SecurityDeclarationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ros2-policy",
        "deployments": [
            {
                "deployment_id": "robot-cell-one",
                "protected_topic_ids": ["motion-command"],
                "authentication_required": True,
                "security_enabled": True,
                "strict_enforcement": False,
                "allow_unauthenticated_participants": False,
                "join_access_control": True,
                "context_complete": True,
            }
        ],
    }
