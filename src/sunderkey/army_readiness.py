"""Deterministic full-Army capability and qualification readiness."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .errors import RoutingError
from .registry import (
    DomainCommand,
    ExpertProfile,
    ExpertRegistry,
    ManeuverGroup,
)
from .routing import (
    CapabilityCatalog,
    CapabilityProfileScope,
    ProfileCapabilityAssignment,
    RoutingPolicy,
    _canonical_json,
    _canonical_sha256,
)
from .types import MissionEnvironment, ProfileKind

ARMY_READINESS_REPORT_DOMAIN = "sunderkey.army-readiness-report.v1"
ARMY_READINESS_REPORT_SCHEMA_VERSION = 1
ARMY_READINESS_REPORT_ID_PATTERN = re.compile(r"ARR-[0-9A-F]{32}")


@dataclass(frozen=True)
class ArmyReadinessReport:
    """Canonical, self-identifying capability readiness report."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ArmyReadinessReport:
        if not isinstance(raw, dict):
            raise RoutingError("Army readiness report must be an object")
        expected = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "registry",
            "capability_catalog",
            "routing_policy",
            "summary",
            "groups",
            "commands",
            "profiles",
            "limitations",
        }
        if set(raw) != expected:
            raise RoutingError("Army readiness report fields are invalid")
        if raw["schema_version"] != ARMY_READINESS_REPORT_SCHEMA_VERSION:
            raise RoutingError(
                "Army readiness report schema version is invalid"
            )
        report_id = raw["report_id"]
        report_hash = raw["report_sha256"]
        if (
            not isinstance(report_id, str)
            or ARMY_READINESS_REPORT_ID_PATTERN.fullmatch(report_id)
            is None
            or not isinstance(report_hash, str)
        ):
            raise RoutingError("Army readiness report identity is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        expected_id = _report_id(expected_hash)
        if report_hash != expected_hash or report_id != expected_id:
            raise RoutingError("Army readiness report hash is invalid")
        return cls(
            report_id=report_id,
            report_sha256=report_hash,
            document_json=_canonical_json(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise RoutingError("Army readiness report document is invalid")
        return value


def assess_army_readiness(
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    policy: RoutingPolicy,
) -> ArmyReadinessReport:
    """Assess explicit capability coverage without activating profiles."""

    if not isinstance(registry, ExpertRegistry):
        raise RoutingError("registry must be an ExpertRegistry")
    if not isinstance(catalog, CapabilityCatalog):
        raise RoutingError("catalog must be a CapabilityCatalog")
    if not isinstance(policy, RoutingPolicy):
        raise RoutingError("policy must be a RoutingPolicy")
    registry.validate()
    catalog = catalog.revalidated(registry)
    policy = policy.revalidated(catalog)
    if catalog.profile_scope is not CapabilityProfileScope.ALL_SPECIALISTS:
        raise RoutingError(
            "Army readiness requires an all_specialists capability catalog"
        )
    specialists = tuple(
        sorted(
            (
                profile
                for profile in registry.profiles
                if profile.kind is ProfileKind.SPECIALIST
            ),
            key=lambda profile: profile.id,
        )
    )
    assignments = catalog.assignments_by_profile_id
    profile_records = tuple(
        _profile_record(
            profile,
            assignments[profile.id],
            policy,
        )
        for profile in specialists
    )
    records_by_id = {
        str(record["profile_id"]): record
        for record in profile_records
    }
    command_records = tuple(
        _command_record(command, records_by_id)
        for command in sorted(
            registry.commands,
            key=lambda command: command.id,
        )
    )
    commands_by_id = {
        str(record["command_id"]): record
        for record in command_records
    }
    group_records = tuple(
        _group_record(group, commands_by_id)
        for group in sorted(
            registry.groups,
            key=lambda group: group.id,
        )
    )
    status_counts = Counter(profile.status for profile in specialists)
    policy_eligible_count = sum(
        bool(record["policy_eligible"])
        for record in profile_records
    )
    policy_review_reasons = _policy_review_reasons(policy)
    pending_qualification_count = status_counts["defined"]
    if policy_review_reasons:
        status = "policy_review_required"
    elif pending_qualification_count or status_counts["retired"]:
        status = "qualification_incomplete"
    else:
        status = "ready"
    body = {
        "schema_version": ARMY_READINESS_REPORT_SCHEMA_VERSION,
        "status": status,
        "registry": {
            "id": registry.catalog_id,
            "version": registry.catalog_version,
            "sha256": _canonical_sha256(registry.to_dict()),
        },
        "capability_catalog": {
            "schema_version": catalog.schema_version,
            "profile_scope": catalog.profile_scope.value,
            "id": catalog.catalog_id,
            "version": catalog.catalog_version,
            "sha256": catalog.canonical_sha256,
        },
        "routing_policy": {
            "id": policy.policy_id,
            "version": policy.policy_version,
            "sha256": policy.canonical_sha256,
            "allowed_statuses": list(policy.allowed_statuses),
            "require_pilot": policy.require_pilot,
            "allowed_environments": [
                environment.value
                for environment in policy.allowed_environments
            ],
            "allow_tier_escalation": policy.allow_tier_escalation,
            "review_reasons": list(policy_review_reasons),
        },
        "summary": {
            "group_count": len(group_records),
            "command_count": len(command_records),
            "specialist_count": len(specialists),
            "mapped_specialist_count": len(assignments),
            "capability_count": len(catalog.capabilities),
            "primary_assignment_count": sum(
                len(assignment.primary_capability_ids)
                for assignment in catalog.profile_assignments
            ),
            "supporting_assignment_count": sum(
                len(assignment.supporting_capability_ids)
                for assignment in catalog.profile_assignments
            ),
            "qualified_specialist_count": status_counts["qualified"],
            "defined_specialist_count": status_counts["defined"],
            "retired_specialist_count": status_counts["retired"],
            "pilot_specialist_count": sum(
                profile.pilot for profile in specialists
            ),
            "policy_eligible_specialist_count": policy_eligible_count,
            "pending_qualification_count": (
                pending_qualification_count
            ),
            "commands_with_qualified_specialists": sum(
                int(record["qualified_specialist_count"] > 0)
                for record in command_records
            ),
            "commands_fully_qualified": sum(
                int(
                    record["qualified_specialist_count"]
                    == record["specialist_count"]
                )
                for record in command_records
            ),
        },
        "groups": list(group_records),
        "commands": list(command_records),
        "profiles": list(profile_records),
        "limitations": [
            (
                "Registry qualification is a reviewed catalog state, "
                "not proof that a model, person, or process is deployed."
            ),
            (
                "Policy eligibility is profile-level and does not replace "
                "mission environment, action-tier, scope, or cell-size "
                "checks."
            ),
            (
                "This report does not activate a profile, dispatch work, "
                "grant authority, sign data, connect to a tool, or execute "
                "an action."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return ArmyReadinessReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _profile_record(
    profile: ExpertProfile,
    assignment: ProfileCapabilityAssignment,
    policy: RoutingPolicy,
) -> dict[str, Any]:
    eligible = (
        profile.status != "retired"
        and profile.status in policy.allowed_statuses
        and (not policy.require_pilot or profile.pilot)
    )
    if profile.status == "retired":
        readiness_state = "retired"
    elif profile.status != "qualified":
        readiness_state = "pending_qualification"
    elif eligible:
        readiness_state = "qualified_policy_eligible"
    else:
        readiness_state = "qualified_policy_restricted"
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "status": profile.status,
        "pilot": profile.pilot,
        "maximum_autonomous_action_tier": (
            profile.max_autonomous_tier.value
        ),
        "minimum_evidence_level": (
            profile.minimum_evidence_level.value
        ),
        "primary_capability_ids": list(
            assignment.primary_capability_ids
        ),
        "supporting_capability_ids": list(
            assignment.supporting_capability_ids
        ),
        "policy_eligible": eligible,
        "readiness_state": readiness_state,
    }


def _command_record(
    command: DomainCommand,
    profiles_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    records = tuple(
        profiles_by_id[profile_id]
        for profile_id in command.specialist_profile_ids
    )
    qualified = tuple(
        str(record["profile_id"])
        for record in records
        if record["status"] == "qualified"
    )
    eligible = tuple(
        str(record["profile_id"])
        for record in records
        if record["policy_eligible"]
    )
    pending = tuple(
        str(record["profile_id"])
        for record in records
        if record["readiness_state"] == "pending_qualification"
    )
    return {
        "command_id": command.id,
        "name": command.name,
        "group_id": command.group_id,
        "specialist_count": len(records),
        "mapped_specialist_count": len(records),
        "qualified_specialist_count": len(qualified),
        "policy_eligible_specialist_count": len(eligible),
        "pending_qualification_count": len(pending),
        "qualified_specialist_ids": list(qualified),
        "policy_eligible_specialist_ids": list(eligible),
        "pending_qualification_ids": list(pending),
    }


def _group_record(
    group: ManeuverGroup,
    commands_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    records = tuple(
        commands_by_id[command_id]
        for command_id in group.command_ids
    )
    return {
        "group_id": group.id,
        "name": group.name,
        "command_count": len(records),
        "specialist_count": sum(
            int(record["specialist_count"])
            for record in records
        ),
        "mapped_specialist_count": sum(
            int(record["mapped_specialist_count"])
            for record in records
        ),
        "qualified_specialist_count": sum(
            int(record["qualified_specialist_count"])
            for record in records
        ),
        "policy_eligible_specialist_count": sum(
            int(record["policy_eligible_specialist_count"])
            for record in records
        ),
        "pending_qualification_count": sum(
            int(record["pending_qualification_count"])
            for record in records
        ),
    }


def _policy_review_reasons(
    policy: RoutingPolicy,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if "defined" in policy.allowed_statuses:
        reasons.append("defined_profiles_allowed")
    if policy.allow_tier_escalation:
        reasons.append("action_tier_escalation_allowed")
    if MissionEnvironment.PRODUCTION in policy.allowed_environments:
        reasons.append("production_environment_allowed")
    return tuple(reasons)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": ARMY_READINESS_REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "ARR-" + report_hash.removeprefix("sha256:")[:32].upper()
